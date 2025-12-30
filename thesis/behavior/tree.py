"""Behavior tree primitives that agents can edit at runtime."""

from __future__ import annotations

import itertools
from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, List, Optional, Sequence


_ID_COUNTER = itertools.count(1)


class BehaviorNode(ABC):
    """Base node that can be part of a behavior tree."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.children: List["BehaviorNode"] = []
        self.node_id = next(_ID_COUNTER)

    def add_child(self, child: "BehaviorNode") -> "BehaviorNode":
        self.children.append(child)
        return child

    def remove_child(self, node_id: int) -> None:
        self.children = [child for child in self.children if child.node_id != node_id]

    @abstractmethod
    def tick(self, context: Dict[str, Any]) -> bool:
        """Execute this node against the provided context."""


class SequenceNode(BehaviorNode):
    """Executes children in order until one fails."""

    def tick(self, context: Dict[str, Any]) -> bool:
        for child in self.children:
            if not child.tick(context):
                return False
        return True


class SelectorNode(BehaviorNode):
    """Returns success if any child succeeds."""

    def tick(self, context: Dict[str, Any]) -> bool:
        for child in self.children:
            if child.tick(context):
                return True
        return False


class ActionNode(BehaviorNode):
    """Leaf node that executes a callback action."""

    def __init__(self, name: str, action: Callable[[Dict[str, Any]], bool]) -> None:
        super().__init__(name)
        self.action = action

    def tick(self, context: Dict[str, Any]) -> bool:
        return self.action(context)


class BehaviorTree:
    """Wraps behavior nodes and exposes runtime modification helpers."""

    def __init__(self, root: BehaviorNode) -> None:
        self.root = root

    def tick(self, context: Dict[str, Any]) -> bool:
        """Run the behavior tree once for the provided context."""
        return self.root.tick(context)

    def find_node(self, node_id: int) -> Optional[BehaviorNode]:
        return self._find(self.root, node_id)

    def _find(self, node: BehaviorNode, node_id: int) -> Optional[BehaviorNode]:
        if node.node_id == node_id:
            return node
        for child in node.children:
            result = self._find(child, node_id)
            if result:
                return result
        return None

    def replace_node(self, node_id: int, replacement: BehaviorNode) -> bool:
        """Swap an existing node with a replacement."""
        parent = self._find_parent(self.root, node_id)
        if not parent:
            if self.root.node_id == node_id:
                self.root = replacement
                return True
            return False
        for idx, child in enumerate(parent.children):
            if child.node_id == node_id:
                parent.children[idx] = replacement
                return True
        return False

    def _find_parent(
        self, current: BehaviorNode, target_id: int
    ) -> Optional[BehaviorNode]:
        for child in current.children:
            if child.node_id == target_id:
                return current
            found = self._find_parent(child, target_id)
            if found:
                return found
        return None

    def add_child(self, parent_id: int, child: BehaviorNode) -> bool:
        parent = self.find_node(parent_id)
        if parent:
            parent.add_child(child)
            return True
        return False

    def remove_node(self, node_id: int) -> bool:
        parent = self._find_parent(self.root, node_id)
        if parent:
            parent.remove_child(node_id)
            return True
        if self.root.node_id == node_id:
            self.root = SequenceNode("root")
            return True
        return False
