from typing import Any, Dict, Optional

from intelligence.core.base import Planner


class HybridPlanner(Planner):
    def __init__(self, local_planner: Planner, remote_planner: Optional[Planner] = None):
        self.local_planner = local_planner
        self.remote_planner = remote_planner

    def plan(self, alert: Dict[str, Any], assessment: Dict[str, Any]) -> Dict[str, Any]:
        try:
            return self.local_planner.plan(alert, assessment)
        except Exception:
            pass
        if self.remote_planner:
            try:
                return self.remote_planner.plan(alert, assessment)
            except Exception:
                pass
        return self.local_planner.plan(alert, assessment)
