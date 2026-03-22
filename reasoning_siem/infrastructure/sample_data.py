from __future__ import annotations

from datetime import datetime, timedelta
import random
from typing import List

from .persistence import FileStore
from .repositories.events_repo import EventRepository
from .repositories.traces_repo import TraceRepository
from ..domain.models import EnrichmentContext, EventEnvelope, NormalizedEvent, TraceEvent


EVENT_TYPES = [
    "auth_failure",
    "malware",
    "lateral_movement",
    "data_exfiltration",
    "suspicious_process",
    "port_scan",
]

ASSETS = [
    "srv-app-01",
    "db-core-02",
    "vpn-gw-01",
    "laptop-23",
    "workstation-14",
    "git-runner-01",
    "hr-files-02",
]

USERS = [
    "alice",
    "bob",
    "carla",
    "dave",
    "svc_backup",
    "svc_ci",
    "admin_ops",
]

ACTIONS = [
    "open_incident",
    "check_asset_owner",
    "review_auth_logs",
    "check_vpn_logs",
    "check_dns_logs",
    "run_endpoint_scan",
    "validate_hash",
    "request_more_info",
    "isolate_host",
    "escalate_tp",
    "close_fp",
]


def seed_if_missing(store: FileStore, event_repo: EventRepository, trace_repo: TraceRepository) -> None:
    existing = store.read_json(event_repo.filename, default=None)
    if existing:
        return
    envelopes = generate_events(count=26, seed=42)
    event_repo.save_events(envelopes)
    seed_traces(trace_repo, envelopes)


def generate_events(count: int, seed: int) -> List[EventEnvelope]:
    rng = random.Random(seed)
    now = datetime.utcnow()
    envelopes: List[EventEnvelope] = []

    for idx in range(count):
        event_type = rng.choices(EVENT_TYPES, weights=[4, 2, 2, 1, 3, 2], k=1)[0]
        asset_id = rng.choice(ASSETS)
        user = rng.choice(USERS)

        severity_base = {
            "auth_failure": 0.45,
            "malware": 0.8,
            "lateral_movement": 0.75,
            "data_exfiltration": 0.9,
            "suspicious_process": 0.55,
            "port_scan": 0.4,
        }[event_type]
        severity = min(1.0, max(0.1, severity_base + rng.uniform(-0.15, 0.15)))

        failed_logins = rng.randint(4, 16) if event_type == "auth_failure" else rng.randint(0, 2)
        suspicious_processes = rng.randint(1, 4) if event_type in {"malware", "suspicious_process"} else rng.randint(0, 2)
        geo_anomaly = rng.random() < 0.25 if event_type in {"auth_failure", "port_scan"} else rng.random() < 0.1
        ip_reputation = min(1.0, max(0.05, rng.uniform(0.2, 0.95) if event_type != "port_scan" else rng.uniform(0.1, 0.5)))
        malware_family = "Redline" if event_type == "malware" and rng.random() > 0.5 else None

        timestamp = now - timedelta(hours=rng.randint(0, 18), minutes=rng.randint(0, 59))

        event = NormalizedEvent(
            event_id=f"evt-{idx:03d}",
            timestamp=timestamp,
            event_type=event_type,
            severity=severity,
            src_ip=f"10.0.{rng.randint(1, 8)}.{rng.randint(5, 220)}",
            dest_ip=f"172.16.{rng.randint(1, 5)}.{rng.randint(10, 220)}",
            user=user,
            asset_id=asset_id,
            failed_logins=failed_logins,
            suspicious_processes=suspicious_processes,
            ip_reputation=ip_reputation,
            geo_anomaly=geo_anomaly,
            malware_family=malware_family,
            tags=["known_bad"] if ip_reputation > 0.8 else [],
        )

        asset_criticality = 0.85 if asset_id in {"db-core-02", "hr-files-02"} else 0.55
        if "srv" in asset_id or "vpn" in asset_id:
            asset_criticality = min(1.0, asset_criticality + 0.1)

        user_privilege = 0.85 if user in {"admin_ops", "svc_backup"} else 0.4
        exposure = 0.8 if asset_id in {"vpn-gw-01"} else 0.5
        time_sensitivity = 0.8 if event_type in {"data_exfiltration", "malware"} else 0.45
        time_sensitivity = min(1.0, time_sensitivity + rng.uniform(-0.1, 0.15))

        context = EnrichmentContext(
            asset_criticality=min(1.0, max(0.2, asset_criticality + rng.uniform(-0.1, 0.1))),
            user_privilege=min(1.0, max(0.1, user_privilege + rng.uniform(-0.1, 0.1))),
            exposure=min(1.0, max(0.1, exposure + rng.uniform(-0.1, 0.1))),
            time_sensitivity=min(1.0, max(0.1, time_sensitivity)),
        )

        envelopes.append(EventEnvelope(event=event, context=context))

    return envelopes


def seed_traces(trace_repo: TraceRepository, envelopes: List[EventEnvelope]) -> None:
    rng = random.Random(99)
    now = datetime.utcnow()
    for envelope in envelopes[:6]:
        incident_id = f"inc-{envelope.event.event_id}"
        sequence_length = rng.randint(4, 7)
        actions = ["open_incident"]
        actions.extend(rng.sample(ACTIONS[1:-2], k=sequence_length - 2))
        actions.append(rng.choice(["close_fp", "escalate_tp"]))

        for idx, action in enumerate(actions):
            trace = TraceEvent(
                trace_id=f"trace-{incident_id}-{idx}",
                incident_id=incident_id,
                analyst="seed",
                action=action,
                timestamp=now - timedelta(minutes=(sequence_length - idx) * 5),
            )
            trace_repo.append(trace)


