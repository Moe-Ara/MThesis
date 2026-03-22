from datetime import datetime, timedelta

from reasoning_siem.domain.models import TraceEvent
from reasoning_siem.domain.recommender import TraceRecommender


def test_recommender_orders_by_transition_counts():
    now = datetime.utcnow()
    traces = [
        TraceEvent("t1", "inc-1", "a", "open_incident", now),
        TraceEvent("t2", "inc-1", "a", "review_auth_logs", now + timedelta(minutes=1)),
        TraceEvent("t3", "inc-1", "a", "check_vpn_logs", now + timedelta(minutes=2)),
        TraceEvent("t4", "inc-2", "b", "open_incident", now),
        TraceEvent("t5", "inc-2", "b", "review_auth_logs", now + timedelta(minutes=1)),
        TraceEvent("t6", "inc-2", "b", "isolate_host", now + timedelta(minutes=2)),
    ]

    recommender = TraceRecommender()
    model = recommender.build_model(traces)

    recommendations = recommender.recommend("open_incident", model, limit=2)

    assert recommendations
    assert recommendations[0].action == "review_auth_logs"
    assert recommendations[0].count == 2


def test_recommender_fallbacks_to_start_counts():
    now = datetime.utcnow()
    traces = [
        TraceEvent("t1", "inc-1", "a", "open_incident", now),
        TraceEvent("t2", "inc-1", "a", "review_auth_logs", now + timedelta(minutes=1)),
        TraceEvent("t3", "inc-2", "b", "open_incident", now),
        TraceEvent("t4", "inc-2", "b", "check_vpn_logs", now + timedelta(minutes=1)),
    ]

    recommender = TraceRecommender()
    model = recommender.build_model(traces)

    recommendations = recommender.recommend(None, model, limit=1)
    assert recommendations[0].action == "open_incident"
    assert recommendations[0].count == 2
