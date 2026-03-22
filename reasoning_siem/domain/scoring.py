from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

from .models import EnrichmentContext, EventEnvelope, FeatureContribution, IncidentCandidate, WeightSet


@dataclass(frozen=True)
class FeatureContext:
    asset_event_count: int
    user_event_count: int
    window_hours: int


def clamp(value: float, min_value: float, max_value: float) -> float:
    return max(min_value, min(value, max_value))


class FeatureExtractor:
    @staticmethod
    def extract(envelope: EventEnvelope, feature_context: FeatureContext) -> Dict[str, float]:
        event = envelope.event
        features: Dict[str, float] = {}

        features["severity"] = clamp(event.severity, 0.0, 1.0)
        features["auth_failure"] = 0.0
        if event.event_type in {"auth_failure", "brute_force"}:
            features["auth_failure"] = clamp(event.failed_logins / 10.0, 0.0, 1.0)

        features["malware_presence"] = 1.0 if event.event_type in {"malware", "ransomware"} or event.malware_family else 0.0
        features["lateral_movement"] = 1.0 if event.event_type == "lateral_movement" else 0.0
        features["data_exfil"] = 1.0 if event.event_type == "data_exfiltration" else 0.0
        features["suspicious_processes"] = clamp(event.suspicious_processes / 5.0, 0.0, 1.0)
        features["geo_anomaly"] = 1.0 if event.geo_anomaly else 0.0
        features["ip_reputation"] = clamp(event.ip_reputation, 0.0, 1.0)

        features["asset_burst"] = clamp(feature_context.asset_event_count / 5.0, 0.0, 1.0)
        features["user_burst"] = clamp(feature_context.user_event_count / 5.0, 0.0, 1.0)

        return features


class ContextMultiplier:
    @staticmethod
    def compute(context: EnrichmentContext) -> Dict[str, float]:
        asset_multiplier = 1.0 + 0.6 * clamp(context.asset_criticality, 0.0, 1.0)
        user_multiplier = 1.0 + 0.4 * clamp(context.user_privilege, 0.0, 1.0)
        exposure_multiplier = 1.0 + 0.5 * clamp(context.exposure, 0.0, 1.0)
        time_multiplier = 1.0 + 0.3 * clamp(context.time_sensitivity, 0.0, 1.0)

        return {
            "asset_criticality": asset_multiplier,
            "user_privilege": user_multiplier,
            "exposure": exposure_multiplier,
            "time_sensitivity": time_multiplier,
        }


class ConfidenceEstimator:
    @staticmethod
    def estimate(features: Dict[str, float], context: EnrichmentContext) -> float:
        signal_count = sum(1 for value in features.values() if value >= 0.1)
        signal_strength = clamp(signal_count / 6.0, 0.0, 1.0)
        context_quality = (
            clamp(context.asset_criticality, 0.0, 1.0)
            + clamp(context.user_privilege, 0.0, 1.0)
            + clamp(context.exposure, 0.0, 1.0)
            + clamp(context.time_sensitivity, 0.0, 1.0)
        ) / 4.0

        confidence = 0.35 + (0.45 * signal_strength) + (0.2 * context_quality)
        return clamp(confidence, 0.1, 1.0)


class WeightedScoringModel:
    def __init__(self, weight_set: WeightSet, score_min: float = 0.0, score_max: float = 100.0):
        self.weight_set = weight_set
        self.score_min = score_min
        self.score_max = score_max

    def score(self, envelope: EventEnvelope, feature_context: FeatureContext, incident_id: str) -> IncidentCandidate:
        """risk_score = (bias + sum(weight_i * feature_i)) * context_multiplier * confidence"""
        features = FeatureExtractor.extract(envelope, feature_context)
        evidence_score_raw = self.weight_set.bias
        for feature, value in features.items():
            evidence_score_raw += self.weight_set.weights.get(feature, 0.0) * value
        evidence_score = clamp(evidence_score_raw, self.score_min, self.score_max)

        context_breakdown = ContextMultiplier.compute(envelope.context)
        context_multiplier = 1.0
        for value in context_breakdown.values():
            context_multiplier *= value

        confidence = ConfidenceEstimator.estimate(features, envelope.context)

        risk_score_raw = evidence_score_raw * context_multiplier * confidence
        risk_score = clamp(risk_score_raw, self.score_min, self.score_max)

        contributions: List[FeatureContribution] = []
        for feature, value in features.items():
            weight = self.weight_set.weights.get(feature, 0.0)
            contribution = weight * value
            contributions.append(FeatureContribution(feature=feature, value=value, weight=weight, contribution=contribution))
        contributions.sort(key=lambda item: abs(item.contribution), reverse=True)
        top_reasons = contributions[:6]

        return IncidentCandidate(
            incident_id=incident_id,
            event_id=envelope.event.event_id,
            event_type=envelope.event.event_type,
            asset_id=envelope.event.asset_id,
            user=envelope.event.user,
            timestamp=envelope.event.timestamp,
            evidence_score_raw=evidence_score_raw,
            evidence_score=evidence_score,
            context_multiplier=context_multiplier,
            context_breakdown=context_breakdown,
            confidence=confidence,
            risk_score=risk_score,
            top_reasons=top_reasons,
            feature_vector=features,
        )


