"""Runs a scan in a background thread so the API can return immediately
and the UI can poll for status, instead of the browser request hanging
for however long the ZAP active scan takes.

This never touches the Anthropic API - it only calls Orchestrator.scan(),
so no API key is required to use it. Findings land in the pending queue,
not the triaged findings table, until someone approves AI review.
"""
from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Optional

from orchestrator import Orchestrator

_state = {
    "running": False,
    "target_url": None,
    "app_name": None,
    "started_at": None,
    "finished_at": None,
    "last_error": None,
    "last_raw_count": None,
    "scanner_log": [],
}
_lock = threading.Lock()


def status() -> dict:
    with _lock:
        return dict(_state)


def start_scan(target_url: str, app_name: Optional[str] = None) -> bool:
    with _lock:
        if _state["running"]:
            return False
        _state.update(
            running=True,
            target_url=target_url,
            app_name=app_name,
            started_at=datetime.now(timezone.utc).isoformat(),
            finished_at=None,
            last_error=None,
            scanner_log=[],
        )

    def _run() -> None:
        try:
            orchestrator = Orchestrator(target_url=target_url, app_name=app_name)
            findings = orchestrator.scan()
            with _lock:
                _state["last_raw_count"] = len(findings)
                _state["app_name"] = orchestrator.app_name
                _state["scanner_log"] = orchestrator.scanner_log
        except Exception as exc:
            with _lock:
                _state["last_error"] = str(exc)
        finally:
            with _lock:
                _state["running"] = False
                _state["finished_at"] = datetime.now(timezone.utc).isoformat()

    threading.Thread(target=_run, daemon=True).start()
    return True
