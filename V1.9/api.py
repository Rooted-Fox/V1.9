"""FastAPI backend: serves the JSON API under /api and the browser UI as
static files at /. Run with `python cli.py serve`, then open
http://localhost:8000 in a browser.

Scanning (POST /api/scan) never requires an Anthropic API key - it only
runs ZAP and queues raw findings. AI triage (POST /api/triage) is a
separate, explicitly approved step that does require the key, and is
governed by an optional token budget set in Settings.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from fastapi import APIRouter, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import runtime_settings
import scan_runner
import triage_job
from models import FindingStatus
from pending_store import PendingFindingsStore
from store import FindingsStore
from token_store import TokenStore

app = FastAPI(title="OWASP DAST agent findings API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["GET", "POST", "PATCH"])

store = FindingsStore()
pending_store = PendingFindingsStore()
token_store = TokenStore()
api = APIRouter(prefix="/api")


# --- findings -----------------------------------------------------------

@api.get("/apps")
def list_apps():
    return store.list_apps()


@api.get("/findings")
def list_findings(app_name: Optional[str] = None):
    return [dict(row) for row in store.all(app_name=app_name)]


@api.get("/summary/severity")
def severity_summary(app_name: Optional[str] = None):
    return store.severity_summary(app_name=app_name)


@api.get("/summary/category")
def category_summary(app_name: Optional[str] = None):
    return store.category_summary(app_name=app_name)


class FindingStatusUpdate(BaseModel):
    status: FindingStatus


@api.patch("/findings/{finding_id}")
def update_finding_status(finding_id: int, body: FindingStatusUpdate):
    store.update_status(finding_id, body.status)
    return {"id": finding_id, "status": body.status.value}


# --- settings -------------------------------------------------------------

class SettingsUpdate(BaseModel):
    provider: Optional[str] = None
    anthropic_api_key: Optional[str] = None
    agent_model: Optional[str] = None
    azure_foundry_endpoint: Optional[str] = None
    azure_foundry_api_key: Optional[str] = None
    zap_api_url: Optional[str] = None
    zap_api_key: Optional[str] = None
    slack_webhook_url: Optional[str] = None
    token_limit: Optional[int] = None
    ai_enabled: Optional[bool] = None
    skip_info_findings: Optional[bool] = None


def _settings_view() -> dict:
    s = runtime_settings.get_settings()
    return {
        "provider": s["provider"],
        "anthropic_api_key_set": bool(s["anthropic_api_key"]),
        "anthropic_api_key_masked": runtime_settings.masked(s["anthropic_api_key"]),
        "agent_model": s["agent_model"],
        "azure_foundry_endpoint": s["azure_foundry_endpoint"],
        "azure_foundry_api_key_set": bool(s["azure_foundry_api_key"]),
        "azure_foundry_api_key_masked": runtime_settings.masked(s["azure_foundry_api_key"]),
        "zap_api_url": s["zap_api_url"],
        "zap_api_key_set": bool(s["zap_api_key"]),
        "slack_webhook_url_set": bool(s["slack_webhook_url"]),
        "token_limit": s["token_limit"],
        "ai_enabled": s["ai_enabled"],
        "skip_info_findings": s["skip_info_findings"],
    }


@api.get("/settings")
def get_settings_endpoint():
    return _settings_view()


@api.post("/settings")
def update_settings_endpoint(body: SettingsUpdate):
    runtime_settings.update_settings(**body.model_dump(exclude_none=True))
    return _settings_view()


# --- scans (no API key required) ---------------------------------------

class ScanRequest(BaseModel):
    target_url: str
    app_name: Optional[str] = None


@api.post("/scan")
def trigger_scan(body: ScanRequest):
    if not body.target_url.startswith(("http://", "https://")):
        raise HTTPException(400, "Enter a full URL, including http:// or https://")
    started = scan_runner.start_scan(body.target_url, app_name=body.app_name)
    if not started:
        raise HTTPException(409, "A scan is already running. Wait for it to finish before starting another.")
    return {"status": "started", "target_url": body.target_url, "app_name": body.app_name}


@api.get("/scan/status")
def scan_status():
    return scan_runner.status()


# --- pending findings + AI triage approval ------------------------------

@api.get("/pending")
def pending_summary(app_name: Optional[str] = None):
    rows = pending_store.pending(app_name=app_name)
    return {
        "count": len(rows),
        "by_category": pending_store.pending_summary(app_name=app_name),
        "findings": [dict(row) for row in rows],
    }


class TriageRequest(BaseModel):
    app_name: Optional[str] = None


@api.post("/triage")
def trigger_triage(body: TriageRequest):
    if not runtime_settings.get_settings()["ai_enabled"]:
        raise HTTPException(400, "AI integration is turned off. Enable it on the Settings tab before approving triage.")
    if not runtime_settings.has_api_key():
        raise HTTPException(400, "Add your Anthropic API key (or Azure Foundry endpoint + key) on the Settings tab before approving AI triage.")
    pending_count = len(pending_store.pending(app_name=body.app_name))
    if pending_count == 0:
        raise HTTPException(400, "Nothing pending - run a scan first.")
    token_limit = runtime_settings.get_settings()["token_limit"]
    if not token_store.has_budget(token_limit):
        raise HTTPException(
            400, f"Token budget ({token_limit}) already reached. Raise the limit or reset usage in Settings."
        )
    started = triage_job.start_triage(app_name=body.app_name, token_limit=token_limit)
    if not started:
        raise HTTPException(409, "Triage is already running. Wait for it to finish before starting another.")
    return {"status": "started", "app_name": body.app_name, "pending_count": pending_count}


@api.get("/triage/status")
def triage_status():
    return triage_job.status()


# --- token governance -----------------------------------------------

@api.get("/tokens")
def token_usage():
    settings_view = runtime_settings.get_settings()
    used = token_store.total_used()
    limit = settings_view["token_limit"]
    return {
        "used": used,
        "limit": limit,
        "remaining": max(limit - used, 0) if limit else None,
        "by_category": token_store.usage_by_category(),
    }


@api.post("/tokens/reset")
def reset_token_usage():
    token_store.reset()
    return token_usage()


app.include_router(api)

_frontend_dir = Path(__file__).parent / "frontend"
app.mount("/", StaticFiles(directory=str(_frontend_dir), html=True), name="frontend")
