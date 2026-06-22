"""Runs the full multi-tool black-box scan pipeline.

Scanner stack (each independent, skipped gracefully if not installed):
  1. ZAP          — classic + Ajax spider + active scan at max thoroughness
  2. SQLMap       — deep SQL injection confirmation, all techniques
  3. Nuclei       — 4000+ CVE and vulnerability templates (2003 → 2026)
  4. Nikto        — web server misconfiguration + outdated software
  5. FFuf         — directory/file/admin panel discovery
  6. SSL scanner  — TLS/SSL weakness detection (SSLv2 → TLS 1.3 issues)
  7. Exposed paths — curated check for commonly left-exposed sensitive files

Together these cover every OWASP vulnerability class from 2003 to 2026.
None of this touches the Anthropic API — all findings land in the pending
queue and only reach Claude when you explicitly approve AI triage.
"""
from __future__ import annotations

import concurrent.futures
from typing import List, Optional
from urllib.parse import urlparse

from models import RawFinding
from pending_store import PendingFindingsStore
from runtime_settings import get_settings
from scanners.base import ScannerNotInstalled
from scanners.exposed_paths import check_exposed_paths
from scanners.ffuf_scanner import run_ffuf
from scanners.nikto_scanner import run_nikto
from scanners.nuclei_scanner import run_nuclei
from scanners.sqlmap_scanner import run_sqlmap
from scanners.ssl_scanner import run_ssl_scan
from scanners.zap_scanner import ZapScanner


def _default_app_name(target_url: str) -> str:
    return urlparse(target_url).hostname or target_url


def _safe_run(fn, *args, scanner_name: str) -> tuple[List[RawFinding], str | None]:
    """Run a scanner function, returning (findings, error_message_or_None)."""
    try:
        results = fn(*args)
        return results, None
    except ScannerNotInstalled as exc:
        return [], f"[skip] {scanner_name}: {exc}"
    except Exception as exc:
        return [], f"[error] {scanner_name}: {exc}"


class Orchestrator:
    def __init__(self, target_url: str, app_name: Optional[str] = None):
        self.target_url = target_url
        self.app_name = app_name or _default_app_name(target_url)
        self.pending_store = PendingFindingsStore()
        self.scanner_log: List[str] = []

    def scan(self) -> List[RawFinding]:
        """Runs all scanners in parallel where safe to do so, tags every
        finding with app_name, and queues them for AI triage.

        ZAP runs first and alone (it modifies browser state in its daemon).
        SQLMap, Nuclei, Nikto, and the TLS scanner run in parallel after ZAP.
        FFuf and exposed-paths also run in parallel.

        Each scanner is skipped gracefully if its binary isn't installed,
        with a note logged so the user knows what's missing.
        """
        all_findings: List[RawFinding] = []

        # --- Phase 1: ZAP (must run solo, owns its own session) ---
        zap_findings, zap_err = _safe_run(ZapScanner(self.target_url).scan, scanner_name="zap")
        if zap_err:
            self.scanner_log.append(zap_err)
        all_findings.extend(zap_findings)

        # --- Phase 2: parallel scanners ---
        parallel_tasks = [
            ("sqlmap",        run_sqlmap,           self.target_url),
            ("nuclei",        run_nuclei,           self.target_url),
            ("nikto",         run_nikto,            self.target_url),
            ("ssl-scanner",   run_ssl_scan,         self.target_url),
            ("ffuf",          run_ffuf,             self.target_url),
            ("exposed-paths", check_exposed_paths,  self.target_url),
        ]

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = {
                executor.submit(_safe_run, fn, arg, scanner_name=name): name
                for name, fn, arg in parallel_tasks
            }
            for future in concurrent.futures.as_completed(futures):
                findings, err = future.result()
                if err:
                    self.scanner_log.append(err)
                all_findings.extend(findings)

        # --- Filter and tag ---
        if get_settings()["skip_info_findings"]:
            all_findings = [f for f in all_findings if (f.raw_severity or "").lower() != "info"]

        for finding in all_findings:
            finding.app_name = self.app_name

        self.pending_store.save_many(all_findings)
        return all_findings
