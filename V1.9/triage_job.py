"""Background-thread wrapper around triage_runner.triage_app(), same
pattern as scan_runner.py - lets the UI start AI triage and poll for
status instead of holding a request open while ten agents work."""
from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Optional

from triage_runner import AIIntegrationDisabled, TokenBudgetExceeded, triage_app

_state = {
    "running": False,
    "app_name": None,
    "started_at": None,
    "finished_at": None,
    "last_error": None,
    "last_result": None,
}
_lock = threading.Lock()


def status() -> dict:
    with _lock:
        return dict(_state)


def start_triage(app_name: Optional[str], token_limit: Optional[int]) -> bool:
    with _lock:
        if _state["running"]:
            return False
        _state.update(
            running=True,
            app_name=app_name,
            started_at=datetime.now(timezone.utc).isoformat(),
            finished_at=None,
            last_error=None,
        )

    def _run() -> None:
        try:
            result = triage_app(app_name=app_name, token_limit=token_limit)
            with _lock:
                _state["last_result"] = result
        except (TokenBudgetExceeded, AIIntegrationDisabled) as exc:
            with _lock:
                _state["last_error"] = str(exc)
        except Exception as exc:
            with _lock:
                _state["last_error"] = str(exc)
        finally:
            with _lock:
                _state["running"] = False
                _state["finished_at"] = datetime.now(timezone.utc).isoformat()

    threading.Thread(target=_run, daemon=True).start()
    return True
