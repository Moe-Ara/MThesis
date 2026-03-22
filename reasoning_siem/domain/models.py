from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional


@dataclass(frozen=True)
class NormalizedEvent:
    event_id: str
    timestamp: datetime
    event_type: str
    severity: float
    src_ip: str
    dest_ip: str
    user: str
    asset_id: str
    failed_logins: int
    suspicious_processes: int
    ip_reputation: float
    geo_anomaly: bool
    malware_family: Optional[str] = None
    tags: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class EnrichmentContext:
    asset_criticality: float
    user_privilege: float
    exposure: float
    time_sensitivity: float


@dataclass(frozen=True)
class EventEnvelope:
    event: NormalizedEvent
    context: EnrichmentContext


@dataclass(frozen=True)
class FeatureContribution:
    feature: str
    value: float
    weight: float
    contribution: float


@dataclass
class IncidentCandidate:
    incident_id: str
    event_id: str
    event_type: str
    asset_id: str
    user: str
    timestamp: datetime
    evidence_score_raw: float
    evidence_score: float
    context_multiplier: float
    context_breakdown: Dict[str, float]
    confidence: float
    risk_score: float
    top_reasons: List[FeatureContribution]
    feature_vector: Dict[str, float]


@dataclass
class WeightSet:
    bias: float
    weights: Dict[str, float]
    min_weight: float
    max_weight: float
    updated_at: datetime
    version: int


@dataclass(frozen=True)
class FeedbackEvent:
    feedback_id: str
    incident_id: str
    analyst: str
    verdict: str
    severity_override: float
    timestamp: datetime
    predicted_risk: float


@dataclass(frozen=True)
class WeightChange:
    feature: str
    old: float
    new: float
    delta: float


@dataclass(frozen=True)
class WeightDiff:
    diff_id: str
    feedback_id: str
    timestamp: datetime
    changes: List[WeightChange]


@dataclass(frozen=True)
class TraceEvent:
    trace_id: str
    incident_id: str
    analyst: str
    action: str
    timestamp: datetime


@dataclass(frozen=True)
class Recommendation:
    action: str
    count: int


