"""Blackboard that agents share state and events through."""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Callable, Dict, List, Sequence, Tuple

Listener = Callable[[str, Any], None]


class Blackboard:
    """Thread-unsafe blackboard supporting state + event listeners."""

    def __init__(self) -> None:
        self._state: Dict[str, Any] = {}
        self._history: List[Tuple[str, Any]] = []
        self._listeners: Dict[str, List[Listener]] = defaultdict(list)

    def set(self, key: str, value: Any) -> None:
        """Write a key/value and notify listeners registered for the key."""
        self._state[key] = value
        self._history.append((key, value))
        for listener in self._listeners.get(key, []):
            listener(key, value)

    def get(self, key: str, default: Any = None) -> Any:
        """Read a key from the board."""
        return self._state.get(key, default)

    def publish(self, topic: str, payload: Any) -> None:
        """Push a notification to any listener subscribed to the topic."""
        self._history.append((topic, payload))
        for listener in self._listeners.get(topic, []):
            listener(topic, payload)

    def subscribe(self, topic: str, listener: Listener) -> None:
        """Register a callback to be executed whenever the topic is updated."""
        self._listeners[topic].append(listener)

    def history(self) -> List[Tuple[str, Any]]:
        """Return a copy of all writes/publishes."""
        return list(self._history)

    def merge(self, data: Dict[str, Any]) -> None:
        """Merge multiple key/values and emit notifications for each."""
        for key, value in data.items():
            self.set(key, value)
