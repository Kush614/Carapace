"""Classify the maximum blast radius of a tool call (spec §5.4, §7.5)."""

from __future__ import annotations

from typing import Any, Mapping

from .intent_classifier import _require
from .tool_registry import canonical_name, get_spec
from .topology import Topology
from .types import BlastRadius, ClassificationError


def classify_blast_radius(
    tool: str, tool_args: Mapping[str, Any], topology: Topology
) -> BlastRadius:
    """Return the blast radius, or raise to fail closed."""
    spec = get_spec(tool)
    name = canonical_name(tool)

    if not spec.arg_aware and spec.base_radius is not None:
        return spec.base_radius

    if name == "migrate_vm":
        vm_id = _require(tool_args, "vm_id", name)
        target_node = _require(tool_args, "target_node", name)
        current_node = topology.node_of_vm(vm_id)
        if topology.same_site(current_node, target_node):
            return BlastRadius.NODE
        return BlastRadius.SITE

    if name == "isolate_network_device":
        device_id = _require(tool_args, "device_id", name)
        role = topology.role_of_device(device_id)
        if role == "spine":
            return BlastRadius.SITE  # isolating a spine darkens the site
        if role == "leaf":
            return BlastRadius.VLAN
        raise ClassificationError(f"unhandled device role {role!r} for {device_id!r}")

    raise ClassificationError(f"no blast-radius rule for tool {tool!r}")
