"""Core definitions for the project knowledge base."""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Sequence


@dataclass
class KnowledgeEntry:
    """Represents a single fact or procedure in the knowledge base."""

    title: str
    content: str
    commands: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    @property
    def summary(self) -> str:
        """Return the first line of the content as a quick summary."""
        for line in self.content.splitlines():
            stripped = line.strip()
            if stripped:
                return stripped
        return ""

    @classmethod
    def from_dict(cls, raw: dict) -> "KnowledgeEntry":
        return cls(
            title=raw.get("title", "untitled"),
            content=raw.get("content", ""),
            commands=list(raw.get("commands", [])),
            tags=list(raw.get("tags", [])),
        )


class KnowledgeBase:
    """Simple in-memory knowledge base for agents."""

    def __init__(self, entries: Sequence[KnowledgeEntry]) -> None:
        self._entries = list(entries)

    @classmethod
    def load(cls, path: Path) -> "KnowledgeBase":
        raw = path.read_text(encoding="utf-8")
        entries = []
        for line in raw.splitlines():
            if not line.strip():
                continue
            entries.append(KnowledgeEntry.from_dict(json.loads(line)))
        return cls(entries)

    def search(self, query: str, max_results: int = 5) -> List[KnowledgeEntry]:
        tokens = [token for token in query.lower().split() if token]
        scored = []
        for entry in self._entries:
            haystack = " ".join([entry.title, entry.content, " ".join(entry.tags)]).lower()
            score = sum(1 for token in tokens if token in haystack)
            if score or not tokens:
                scored.append((score, entry))
        if not scored:
            scored = [(0, entry) for entry in self._entries]
        scored.sort(key=lambda pair: pair[0], reverse=True)
        return [entry for _, entry in scored[:max_results]]

    def entries(self) -> List[KnowledgeEntry]:
        return list(self._entries)
