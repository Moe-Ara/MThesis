from __future__ import annotations

from pydantic import BaseModel, Field


class FeedbackRequest(BaseModel):
    verdict: str = Field(..., pattern="^(tp|fp|nmi)$")
    severity_override: float | None = None
    analyst: str | None = None


class TraceRequest(BaseModel):
    action: str
    analyst: str | None = None


