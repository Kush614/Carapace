"""Detect the *true* intent of a tool call (spec §5.2, §7.3).

``detected_intent`` is computed here from the tool and its arguments — never
trusted from the agent's declaration. Rule R1 compares the two; any mismatch
is a hard DENY (the scope-creep / intent-violation defence).
"""

from __future__ import annotations

from typing import Any, Mapping

from .tool_registry import canonical_name, get_spec
from .topology import Topology
from .types import ClassificationError, IntentClass


def _require(tool_args: Mapping[str, Any], key: str, tool: str) -> str:
    value = tool_args.get(key)
    if not value:
        raise ClassificationError(f"{tool}: missing required arg {key!r}")
    return str(value)


def classify_intent(
    tool: str, tool_args: Mapping[str, Any], topology: Topology
) -> IntentClass:
    """Return the detected intent class, or raise to fail closed."""
    spec = get_spec(tool)  # raises UnknownToolError for unknown tools
    name = canonical_name(tool)

    if not spec.arg_aware and spec.base_intent is not None:
        return spec.base_intent

    if name == "migrate_vm":
        vm_id = _require(tool_args, "vm_id", name)
        target_node = _require(tool_args, "target_node", name)
        current_node = topology.node_of_vm(vm_id)
        # Same site => reversible; crossing a site boundary is destructive.
        if topology.same_site(current_node, target_node):
            return IntentClass.REMEDIATE_REVERSIBLE
        return IntentClass.REMEDIATE_DESTRUCTIVE

    if name == "isolate_network_device":
        # Always destructive; only the *radius* is argument-aware.
        return IntentClass.REMEDIATE_DESTRUCTIVE

    raise ClassificationError(f"no intent rule for tool {tool!r}")
