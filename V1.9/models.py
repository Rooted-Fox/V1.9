"""Shared data models for findings flowing through the pipeline."""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class OwaspCategory(str, Enum):
    A01_ACCESS_CONTROL       = "A01:broken_access_control"
    A02_MISCONFIGURATION     = "A02:security_misconfiguration"
    A03_SUPPLY_CHAIN         = "A03:software_supply_chain_failures"
    A04_CRYPTO_FAILURES      = "A04:cryptographic_failures"
    A05_INJECTION            = "A05:injection"
    A06_INSECURE_DESIGN      = "A06:insecure_design"
    A07_AUTH_FAILURES        = "A07:authentication_failures"
    A08_INTEGRITY_FAILURES   = "A08:software_data_integrity_failures"
    A09_LOGGING_FAILURES     = "A09:logging_alerting_failures"
    A10_EXCEPTIONAL          = "A10:mishandling_exceptional_conditions"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, Enum):
    OPEN = "open"
    IN_REVIEW = "in_review"
    PATCHED = "patched"
    DISMISSED = "dismissed"


class RawFinding(BaseModel):
    """A finding straight out of the DAST scanner, before agent triage."""

    tool: str
    category: OwaspCategory
    title: str
    url: Optional[str] = None
    app_name: Optional[str] = None  # stamped by the orchestrator, not the scanner
    raw_severity: Optional[str] = None
    description: str = ""
    evidence: str = ""  # HTTP request/response context from the live scan


class TriagedFinding(BaseModel):
    """A finding after an OWASP agent has reviewed it."""

    id: Optional[int] = None
    tool: str
    category: OwaspCategory
    title: str
    url: Optional[str] = None
    app_name: str = "unspecified"
    severity: Severity
    exploitable: bool
    rationale: str
    remediation: Optional[str] = None  # guidance on how to fix it
    status: FindingStatus = FindingStatus.OPEN
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
