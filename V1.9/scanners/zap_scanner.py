"""DAST scanner: drives an existing OWASP ZAP instance against a live URL,
black-box only - no credentials, no login, just what's reachable from the
outside, the same vantage point a real attacker has.

This wrapper only calls ZAP's documented REST API. It assumes ZAP is
already running in daemon mode and pointed at infrastructure you own and
are authorized to test - never point this at a target outside your own
environment.
"""
from __future__ import annotations

import time
from typing import List, Optional

import requests

from models import OwaspCategory, RawFinding
from runtime_settings import get_settings
from scanners.base import BaseScanner

_RISK_TO_SEVERITY = {"High": "high", "Medium": "medium", "Low": "low", "Informational": "info"}

_ALERT_KEYWORDS = {
    OwaspCategory.A01_ACCESS_CONTROL: [
        "access control", "path traversal", "directory traversal",
        "authorization", "idor", "privilege escalation", "admin",
    ],
    OwaspCategory.A02_MISCONFIGURATION: [
        "misconfiguration", "default credential", "unnecessary service",
        "debug", "server leaks", "x-content-type", "x-frame-options",
        "content security policy", "hsts", "clickjacking", "information disclosure",
        "server version", "directory listing",
    ],
    OwaspCategory.A03_SUPPLY_CHAIN: [
        "vulnerable js library", "retire.js", "outdated library",
        "third-party", "supply chain", "dependency", "sri", "subresource integrity",
    ],
    OwaspCategory.A04_CRYPTO_FAILURES: [
        "tls", "ssl", "certificate", "weak cipher", "plaintext", "http only",
        "secure flag", "mixed content", "hsts", "rc4", "des", "md5", "sha1",
    ],
    OwaspCategory.A05_INJECTION: [
        "sql injection", "cross site scripting", "xss", "command injection",
        "ldap injection", "nosql injection", "template injection", "ssti",
        "code injection", "expression language injection",
    ],
    OwaspCategory.A06_INSECURE_DESIGN: [
        "business logic", "rate limit", "brute force", "account enumeration",
        "workflow bypass", "insecure design",
    ],
    OwaspCategory.A07_AUTH_FAILURES: [
        "authentication", "session fixation", "session", "jwt",
        "credential", "login", "logout", "password", "token",
    ],
    OwaspCategory.A08_INTEGRITY_FAILURES: [
        "deserialization", "integrity", "unsigned", "update mechanism",
        "object injection",
    ],
    OwaspCategory.A09_LOGGING_FAILURES: [
        "logging", "monitoring", "audit", "alerting",
    ],
    OwaspCategory.A10_EXCEPTIONAL: [
        "denial of service", "dos", "resource exhaustion", "stack trace",
        "exception", "error handling", "unhandled", "crash", "redos",
        "application error",
    ],
}

_SCAN_POLICY_NAME = "Default Policy"
_AJAX_SPIDER_MAX_SECONDS = 300  # hard cap so a stuck ajax spider can't block a scan indefinitely


def _infer_category(alert_name: str) -> OwaspCategory:
    lowered = alert_name.lower()
    # Check SSRF explicitly - maps to A10 exceptional conditions in 2026 framework
    if any(k in lowered for k in ["server side request forgery", "ssrf"]):
        return OwaspCategory.A10_EXCEPTIONAL
    for category, keywords in _ALERT_KEYWORDS.items():
        if any(keyword in lowered for keyword in keywords):
            return category
    return OwaspCategory.A02_MISCONFIGURATION  # best default for unclassified ZAP alerts


class ZapScanner(BaseScanner):
    """Targets a live URL - configured at construction, not per scan() call.

    Built for maximum black-box coverage: both the classic spider and the
    JavaScript-aware Ajax Spider run before the active scan (most modern
    targets are single-page apps the classic spider alone can't fully
    see), and the active scan policy is pushed to its highest attack
    strength and most sensitive alert threshold before scanning starts.
    """

    def __init__(self, target_url: str):
        self.target_url = target_url
        rt = get_settings()
        self.base = rt["zap_api_url"]
        self.params = {"apikey": rt["zap_api_key"]}

    def _get(self, path: str, **extra_params):
        response = requests.get(f"{self.base}{path}", params={**self.params, **extra_params}, timeout=30)
        response.raise_for_status()
        return response.json()

    def _message_context(self, message_id: Optional[str]) -> str:
        """Pull the actual HTTP request/response for an alert, so the agent
        reviews real traffic instead of just a one-line description."""
        if not message_id:
            return ""
        try:
            msg = self._get("/JSON/core/view/message/", id=message_id).get("message", {})
        except requests.RequestException:
            return ""
        request_part = f"{msg.get('requestHeader', '')}\n{msg.get('requestBody', '')}"
        response_part = f"{msg.get('responseHeader', '')}\n{msg.get('responseBody', '')}"
        combined = f"--- request ---\n{request_part}\n--- response ---\n{response_part}"
        return combined[:3000]

    def _maximize_thoroughness(self) -> None:
        """Best-effort: push the active scan policy to maximum attack
        strength and minimum (most sensitive) alert threshold. Never blocks
        the scan if this fails - older ZAP versions or a renamed/custom
        policy might reject these calls, in which case ZAP's own defaults
        still apply."""
        try:
            self._get(
                "/JSON/ascan/action/setPolicyAttackStrength/",
                scanPolicyName=_SCAN_POLICY_NAME,
                attackStrength="HIGH",
            )
            self._get(
                "/JSON/ascan/action/setPolicyAlertThreshold/",
                scanPolicyName=_SCAN_POLICY_NAME,
                alertThreshold="LOW",
            )
        except requests.RequestException:
            pass

    def _run_ajax_spider(self) -> None:
        """Crawls JavaScript-rendered pages and routes the classic spider
        can't see by actually executing the page in a browser - essential
        coverage for single-page apps, which is most black-box targets."""
        try:
            self._get("/JSON/ajaxSpider/action/scan/", url=self.target_url)
        except requests.RequestException:
            return

        deadline = time.time() + _AJAX_SPIDER_MAX_SECONDS
        while True:
            try:
                status = self._get("/JSON/ajaxSpider/view/status/").get("status")
            except requests.RequestException:
                return
            if status != "running":
                return
            if time.time() > deadline:
                try:
                    self._get("/JSON/ajaxSpider/action/stop/")
                except requests.RequestException:
                    pass
                return
            time.sleep(3)

    def scan(self) -> List[RawFinding]:
        self._maximize_thoroughness()

        self._get("/JSON/spider/action/scan/", url=self.target_url)
        while int(self._get("/JSON/spider/view/status/")["status"]) < 100:
            time.sleep(2)

        self._run_ajax_spider()

        scan_id = self._get("/JSON/ascan/action/scan/", url=self.target_url)["scan"]
        while int(self._get("/JSON/ascan/view/status/", scanId=scan_id)["status"]) < 100:
            time.sleep(5)

        alerts = self._get("/JSON/core/view/alerts/", baseurl=self.target_url).get("alerts", [])
        findings: List[RawFinding] = []
        for alert in alerts:
            evidence = self._message_context(alert.get("messageId")) or alert.get("evidence", "")
            findings.append(
                RawFinding(
                    tool="zap",
                    category=_infer_category(alert.get("alert", "")),
                    title=alert.get("alert", "zap finding"),
                    url=alert.get("url"),
                    raw_severity=_RISK_TO_SEVERITY.get(alert.get("risk"), "low"),
                    description=alert.get("description", ""),
                    evidence=evidence,
                )
            )
        return findings
