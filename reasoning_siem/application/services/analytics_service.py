from __future__ import annotations

from collections import Counter, defaultdict
from typing import Dict, List

from ..infrastructure.repositories.diff_repo import WeightDiffRepository
from ..infrastructure.repositories.feedback_repo import FeedbackRepository


class AnalyticsService:
    def __init__(self, feedback_repo: FeedbackRepository, diff_repo: WeightDiffRepository):
        self.feedback_repo = feedback_repo
        self.diff_repo = diff_repo

    def feedback_trend(self, days: int = 7) -> List[Dict[str, float]]:
        events = self.feedback_repo.list_events()
        if not events:
            return []
        by_date = defaultdict(list)
        for event in events:
            day = event.timestamp.date().isoformat()
            by_date[day].append(event)

        dates = sorted(by_date.keys())[-days:]
        trend = []
        for day in dates:
            items = by_date[day]
            total = len(items)
            fp = len([item for item in items if item.verdict == "fp"])
            rate = (fp / total) if total else 0.0
            trend.append({"date": day, "fp_rate": rate, "total": total})
        return trend

    def weight_change_summary(self, limit: int = 5) -> Dict[str, List[Dict[str, float]]]:
        diffs = self.diff_repo.list_diffs()
        increase = Counter()
        decrease = Counter()
        for diff in diffs:
            for change in diff.changes:
                if change.delta > 0:
                    increase[change.feature] += change.delta
                elif change.delta < 0:
                    decrease[change.feature] += abs(change.delta)
        top_increase = [
            {"feature": feature, "delta": delta}
            for feature, delta in increase.most_common(limit)
        ]
        top_decrease = [
            {"feature": feature, "delta": delta}
            for feature, delta in decrease.most_common(limit)
        ]
        return {"increase": top_increase, "decrease": top_decrease}

    def counters(self) -> Dict[str, float]:
        events = self.feedback_repo.list_events()
        total = len(events)
        fp = len([event for event in events if event.verdict == "fp"])
        tp = len([event for event in events if event.verdict == "tp"])
        nmi = len([event for event in events if event.verdict == "nmi"])
        return {
            "total": total,
            "fp": fp,
            "tp": tp,
            "nmi": nmi,
            "fp_rate": (fp / total) if total else 0.0,
        }

    def recent_weight_diffs(self, limit: int = 12) -> List[dict]:
        diffs = self.diff_repo.list_diffs()
        diffs_sorted = sorted(diffs, key=lambda item: item.timestamp, reverse=True)
        results = []
        for diff in diffs_sorted[:limit]:
            results.append(
                {
                    "diff_id": diff.diff_id,
                    "feedback_id": diff.feedback_id,
                    "timestamp": diff.timestamp.isoformat(),
                    "changes": [
                        {
                            "feature": change.feature,
                            "old": change.old,
                            "new": change.new,
                            "delta": change.delta,
                        }
                        for change in diff.changes
                    ],
                }
            )
        return results


