"""The OwaspAgent: takes a batch of raw DAST findings for one category and
triages all of them in a single Claude call, instead of one call per
finding. That's the main cost lever in this tool - the system prompt
(category instructions + any app-specific knowledge base context) gets
paid for once per batch instead of once per finding, which matters a lot
once you've added real context to knowledge_base.yaml.

This is also the only place in the codebase that calls the Anthropic API,
and every call's token usage is returned alongside the results so the
caller can log it against the budget.
"""
from __future__ import annotations

import json

import anthropic

from agents.prompts import PROMPTS
from knowledge import AppKnowledge
from models import OwaspCategory, RawFinding, TriagedFinding
from runtime_settings import get_settings

# Caps how large a single batch request gets. Large enough that most
# scans finish a category in 1-2 calls; small enough that one malformed
# response doesn't cost you re-doing dozens of findings, and that the
# per-call token ceiling below stays sane.
MAX_BATCH_SIZE = 8  # smaller batches = more tokens per finding = better quality rationale


def _build_client(rt: dict):
    """Direct Anthropic API by default. If Azure AI Foundry is configured
    as the provider, use AnthropicFoundry instead - same Messages API
    shape, different transport/auth, so nothing else in this file needs
    to change based on which one is active."""
    if rt["provider"] == "azure_foundry":
        endpoint = (rt.get("azure_foundry_endpoint") or "").strip().rstrip("/") + "/"
        key = rt.get("azure_foundry_api_key") or ""
        if not endpoint or endpoint == "/":
            raise ValueError(
                "Azure Foundry endpoint is not set. Add it on the Settings tab "
                "(e.g. https://<resource>.services.ai.azure.com/anthropic)."
            )
        if not key:
            raise ValueError(
                "Azure Foundry API key is not set. Add it on the Settings tab."
            )
        from anthropic import AnthropicFoundry
        return AnthropicFoundry(api_key=key, base_url=endpoint)
    return anthropic.Anthropic(api_key=rt["anthropic_api_key"])


def _finding_block(index: int, finding: RawFinding) -> str:
    severity_hint = (finding.raw_severity or "unknown").upper()
    return (
        f"### Finding {index}\n"
        f"Tool: {finding.tool}\n"
        f"ZAP reported severity: {severity_hint} — this is from ZAP's active scanner which confirmed the payload triggered a vulnerable response\n"
        f"Title: {finding.title}\n"
        f"URL: {finding.url}\n"
        f"Description: {finding.description}\n"
        f"HTTP request/response evidence (payload sent + response received):\n{finding.evidence}"
    )


class OwaspAgent:
    def __init__(self, category: OwaspCategory, knowledge: AppKnowledge | None = None):
        self.category = category
        self.knowledge = knowledge or AppKnowledge()
        self.system_prompt = PROMPTS[category]
        context_block = self.knowledge.for_category(category)
        if context_block:
            self.system_prompt = f"{self.system_prompt}\n\n{context_block}"
        rt = get_settings()
        self.model = rt["agent_model"]
        self.client = _build_client(rt)

    def triage_batch(self, findings: list[RawFinding]) -> tuple[list[TriagedFinding], dict]:
        """Triages up to MAX_BATCH_SIZE findings in one call. Returns
        (results, usage) where usage is {"input_tokens": int, "output_tokens": int}
        for the whole call, not per finding."""
        if not findings:
            return [], {"input_tokens": 0, "output_tokens": 0}

        findings_block = "\n\n".join(_finding_block(i + 1, f) for i, f in enumerate(findings))
        user_message = (
            f"Review these {len(findings)} finding(s) and respond with a JSON array of "
            f"exactly {len(findings)} objects, in the same order.\n\n{findings_block}"
        )

        response = self.client.messages.create(
            model=self.model,
            max_tokens=min(400 + 350 * len(findings), 8192),
            system=[{"type": "text", "text": self.system_prompt, "cache_control": {"type": "ephemeral"}}],
            messages=[{"role": "user", "content": user_message}],
        )
        text = "".join(block.text for block in response.content if block.type == "text")
        parsed_list = json.loads(text)

        if len(parsed_list) != len(findings):
            raise ValueError(
                f"Expected {len(findings)} results from batch triage, got {len(parsed_list)}."
            )

        results = []
        for finding, parsed in zip(findings, parsed_list):
            results.append(
                TriagedFinding(
                    tool=finding.tool,
                    category=finding.category,
                    title=finding.title,
                    url=finding.url,
                    app_name=finding.app_name or "unspecified",
                    severity=parsed["severity"],
                    exploitable=parsed["exploitable"],
                    rationale=parsed["rationale"],
                    remediation=parsed.get("remediation"),
                )
            )

        usage = {
            "input_tokens": getattr(response.usage, "input_tokens", 0),
            "output_tokens": getattr(response.usage, "output_tokens", 0),
        }
        return results, usage
