from pathlib import Path

from reasoning_siem.infrastructure.persistence import FileStore
from reasoning_siem.infrastructure.repositories.events_repo import EventRepository
from reasoning_siem.infrastructure.repositories.traces_repo import TraceRepository
from reasoning_siem.infrastructure.sample_data import seed_if_missing


if __name__ == "__main__":
    base_dir = Path(__file__).resolve().parents[1] / "data"
    store = FileStore(base_dir)
    event_repo = EventRepository(store)
    trace_repo = TraceRepository(store)
    seed_if_missing(store, event_repo, trace_repo)
    print("Sample data ready in", base_dir)


