from datetime import datetime, timedelta

from reasoning_siem.application.services.analytics_service import AnalyticsService
from reasoning_siem.domain.models import FeedbackEvent, WeightChange, WeightDiff
from reasoning_siem.infrastructure.persistence import FileStore
from reasoning_siem.infrastructure.repositories.diff_repo import WeightDiffRepository
from reasoning_siem.infrastructure.repositories.feedback_repo import FeedbackRepository


def test_analytics_counters_and_trend(tmp_path):
    store = FileStore(tmp_path)
    feedback_repo = FeedbackRepository(store)
    diff_repo = WeightDiffRepository(store)

    day_one = datetime(2026, 3, 8, 10, 0, 0)
    day_two = datetime(2026, 3, 9, 11, 0, 0)

    feedback_repo.append(
        FeedbackEvent("fb-1", "inc-1", "a", "fp", 1.0, day_one, 55.0)
    )
    feedback_repo.append(
        FeedbackEvent("fb-2", "inc-2", "b", "tp", 1.0, day_two, 70.0)
    )
    feedback_repo.append(
        FeedbackEvent("fb-3", "inc-3", "c", "fp", 1.0, day_two + timedelta(hours=1), 40.0)
    )

    diff_repo.append(
        WeightDiff(
            "diff-1",
            "fb-1",
            day_one,
            [WeightChange("severity", 18.0, 16.0, -2.0)],
        )
    )
    diff_repo.append(
        WeightDiff(
            "diff-2",
            "fb-2",
            day_two,
            [WeightChange("malware_presence", 32.0, 34.0, 2.0)],
        )
    )

    service = AnalyticsService(feedback_repo, diff_repo)
    counters = service.counters()
    assert counters["total"] == 3
    assert counters["fp"] == 2
    assert counters["tp"] == 1

    trend = service.feedback_trend(days=2)
    assert len(trend) == 2

    summary = service.weight_change_summary(limit=2)
    assert summary["increase"]
    assert summary["decrease"]
