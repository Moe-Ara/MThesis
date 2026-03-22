from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from ..persistence import FileStore
from ...domain.models import EnrichmentContext, EventEnvelope, NormalizedEvent


class EventRepository:
    def __init__(self, store: FileStore, filename: str = "events.json"):
        self.store = store
        self.filename = filename

    def list_events(self) -> List[EventEnvelope]:
        data = self.store.read_json(self.filename, default=[])
        return [self._from_record(record) for record in data]

    def get_event(self, event_id: str) -> Optional[EventEnvelope]:
        for envelope in self.list_events():
            if envelope.event.event_id == event_id:
                return envelope
        return None

    def save_events(self, envelopes: List[EventEnvelope]) -> None:
        payload = [self._to_record(envelope) for envelope in envelopes]
        self.store.write_json(self.filename, payload)

    def _from_record(self, record: dict) -> EventEnvelope:
        event = record["event"]
        context = record["context"]
        normalized_event = NormalizedEvent(
            event_id=event["event_id"],
            timestamp=datetime.fromisoformat(event["timestamp"]),
            event_type=event["event_type"],
            severity=event["severity"],
            src_ip=event["src_ip"],
            dest_ip=event["dest_ip"],
            user=event["user"],
            asset_id=event["asset_id"],
            failed_logins=event["failed_logins"],
            suspicious_processes=event["suspicious_processes"],
            ip_reputation=event["ip_reputation"],
            geo_anomaly=event["geo_anomaly"],
            malware_family=event.get("malware_family"),
            tags=event.get("tags", []),
        )
        enrichment = EnrichmentContext(
            asset_criticality=context["asset_criticality"],
            user_privilege=context["user_privilege"],
            exposure=context["exposure"],
            time_sensitivity=context["time_sensitivity"],
        )
        return EventEnvelope(event=normalized_event, context=enrichment)

    def _to_record(self, envelope: EventEnvelope) -> dict:
        return {
            "event": {
                "event_id": envelope.event.event_id,
                "timestamp": envelope.event.timestamp.isoformat(),
                "event_type": envelope.event.event_type,
                "severity": envelope.event.severity,
                "src_ip": envelope.event.src_ip,
                "dest_ip": envelope.event.dest_ip,
                "user": envelope.event.user,
                "asset_id": envelope.event.asset_id,
                "failed_logins": envelope.event.failed_logins,
                "suspicious_processes": envelope.event.suspicious_processes,
                "ip_reputation": envelope.event.ip_reputation,
                "geo_anomaly": envelope.event.geo_anomaly,
                "malware_family": envelope.event.malware_family,
                "tags": envelope.event.tags,
            },
            "context": {
                "asset_criticality": envelope.context.asset_criticality,
                "user_privilege": envelope.context.user_privilege,
                "exposure": envelope.context.exposure,
                "time_sensitivity": envelope.context.time_sensitivity,
            },
        }


