from datetime import datetime

import pytest

from reasoning_siem.domain.models import EnrichmentContext, EventEnvelope, NormalizedEvent, WeightSet
from reasoning_siem.domain.scoring import FeatureContext, WeightedScoringModel


def test_scoring_formula_and_top_reasons():
    weight_set = WeightSet(
        bias=5.0,
        weights={
            "severity": 20.0,
            "malware_presence": 30.0,
            "asset_burst": 10.0,
        },
        min_weight=-40.0,
        max_weight=60.0,
        updated_at=datetime.utcnow(),
        version=1,
    )

    event = NormalizedEvent(
        event_id="evt-100",
        timestamp=datetime(2026, 2, 20, 12, 0, 0),
        event_type="malware",
        severity=0.8,
        src_ip="10.0.0.5",
        dest_ip="172.16.0.8",
        user="alice",
        asset_id="srv-app-01",
        failed_logins=0,
        suspicious_processes=2,
        ip_reputation=0.7,
        geo_anomaly=False,
        malware_family="Redline",
        tags=[],
    )

    context = EnrichmentContext(
        asset_criticality=0.5,
        user_privilege=0.4,
        exposure=0.2,
        time_sensitivity=0.1,
    )

    envelope = EventEnvelope(event=event, context=context)
    feature_context = FeatureContext(asset_event_count=3, user_event_count=0, window_hours=24)

    model = WeightedScoringModel(weight_set)
    candidate = model.score(envelope, feature_context, incident_id="inc-evt-100")

    expected_evidence = 5.0 + (20.0 * 0.8) + (30.0 * 1.0) + (10.0 * 0.6)
    assert candidate.evidence_score_raw == pytest.approx(expected_evidence, abs=0.01)

    asset_mult = 1.0 + 0.6 * 0.5
    user_mult = 1.0 + 0.4 * 0.4
    exposure_mult = 1.0 + 0.5 * 0.2
    time_mult = 1.0 + 0.3 * 0.1
    context_multiplier = asset_mult * user_mult * exposure_mult * time_mult

    signal_count = len([value for value in candidate.feature_vector.values() if value >= 0.1])
    signal_strength = min(1.0, signal_count / 6.0)
    context_quality = (0.5 + 0.4 + 0.2 + 0.1) / 4.0
    confidence = 0.35 + (0.45 * signal_strength) + (0.2 * context_quality)

    expected_risk = expected_evidence * context_multiplier * confidence
    assert candidate.risk_score == pytest.approx(expected_risk, abs=0.05)

    top_features = [reason.feature for reason in candidate.top_reasons[:3]]
    assert top_features[0] == "malware_presence"
    assert "severity" in top_features


