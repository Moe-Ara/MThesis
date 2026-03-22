from __future__ import annotations

from datetime import datetime
from typing import Dict

from ..persistence import FileStore
from ...domain.models import WeightSet


DEFAULT_WEIGHTS: Dict[str, float] = {
    "severity": 18.0,
    "auth_failure": 12.0,
    "malware_presence": 32.0,
    "lateral_movement": 26.0,
    "data_exfil": 38.0,
    "suspicious_processes": 10.0,
    "geo_anomaly": 8.0,
    "ip_reputation": 14.0,
    "asset_burst": 16.0,
    "user_burst": 10.0,
}


class WeightRepository:
    def __init__(self, store: FileStore, filename: str = "weights.json"):
        self.store = store
        self.filename = filename

    def load(self) -> WeightSet:
        payload = self.store.read_json(self.filename, default=None)
        if not payload:
            weight_set = WeightSet(
                bias=6.0,
                weights=DEFAULT_WEIGHTS.copy(),
                min_weight=-40.0,
                max_weight=60.0,
                updated_at=datetime.utcnow(),
                version=1,
            )
            self.save(weight_set)
            return weight_set
        return WeightSet(
            bias=payload["bias"],
            weights=payload["weights"],
            min_weight=payload["min_weight"],
            max_weight=payload["max_weight"],
            updated_at=datetime.fromisoformat(payload["updated_at"]),
            version=payload.get("version", 1),
        )

    def save(self, weight_set: WeightSet) -> None:
        payload = {
            "bias": weight_set.bias,
            "weights": weight_set.weights,
            "min_weight": weight_set.min_weight,
            "max_weight": weight_set.max_weight,
            "updated_at": weight_set.updated_at.isoformat(),
            "version": weight_set.version,
        }
        self.store.write_json(self.filename, payload)


