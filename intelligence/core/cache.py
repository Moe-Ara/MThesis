from typing import Any, Dict, List


class LruCache:
    def __init__(self, max_size: int) -> None:
        self.max_size = max(max_size, 0)
        self._store: Dict[str, Dict[str, Any]] = {}
        self._order: List[str] = []

    def get(self, key: str) -> Dict[str, Any] | None:
        return self._store.get(key)

    def set(self, key: str, value: Dict[str, Any]) -> None:
        if self.max_size <= 0:
            return
        if key in self._store:
            self._store[key] = value
            return
        self._store[key] = value
        self._order.append(key)
        while len(self._order) > self.max_size:
            oldest = self._order.pop(0)
            self._store.pop(oldest, None)

    def size(self) -> int:
        return self.max_size

    def count(self) -> int:
        return len(self._store)
