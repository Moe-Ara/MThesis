"""Simple decision tree helpers used by agents at runtime."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional


Context = Dict[str, Any]
Condition = Callable[[Context], bool]


@dataclass
class DecisionNode:
    """Single node in the decision tree."""

    name: str
    condition: Optional[Condition] = None
    action: Optional[Any] = None
    children: List["DecisionNode"] = field(default_factory=list)

    def add_child(self, child: "DecisionNode") -> DecisionNode:
        self.children.append(child)
        return child

    def evaluate(self, context: Context) -> Optional["DecisionNode"]:
        """Return the matching child node for the context."""
        for child in self.children:
            if child.condition is None or child.condition(context):
                return child
        return None


class DecisionTree:
    """Tree that traverses nodes by evaluating each branch's condition."""

    def __init__(self, root: DecisionNode) -> None:
        self.root = root

    def decide(self, context: Context) -> Any:
        """Walk the tree with the provided context and execute the first matching action."""
        current = self.root
        while current:
            next_node = current.evaluate(context)
            if not next_node:
                break
            current = next_node
        return current.action if current else None

    def find_node(self, name: str) -> Optional[DecisionNode]:
        """Locate a node by name (pre-order traversal)."""
        return self._find(self.root, name)

    def _find(self, node: DecisionNode, name: str) -> Optional[DecisionNode]:
        if node.name == name:
            return node
        for child in node.children:
            found = self._find(child, name)
            if found:
                return found
        return None
