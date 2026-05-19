"""Registry of infrastructure tools the agent may call (spec §8).

The registry is the single source of truth for *which tools exist* and their
*static* intent / blast-radius defaults. Tools whose classification depends on
arguments (``migrate_vm``, ``isolate_network_device``) carry ``arg_aware=True``
and are resolved by the classifiers using topology.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .types import BlastRadius, IntentClass, UnknownToolError


@dataclass(frozen=True, slots=True)
class ToolSpec:
    name: str
    base_intent: Optional[IntentClass]  # None => argument-aware
    base_radius: Optional[BlastRadius]  # None => argument-aware
    arg_aware: bool
    description: str


_SPECS: tuple[ToolSpec, ...] = (
    ToolSpec(
        "get_telemetry",
        IntentClass.OBSERVE,
        BlastRadius.NONE,
        False,
        "Read metrics for a node/metric.",
    ),
    ToolSpec(
        "read_logs",
        IntentClass.OBSERVE,
        BlastRadius.NONE,
        False,
        "Read N lines from a log source.",
    ),
    ToolSpec(
        "propose_action",
        IntentClass.RECOMMEND,
        BlastRadius.NONE,
        False,
        "Surface a plan for a human; takes no action.",
    ),
    ToolSpec(
        "restart_workload",
        IntentClass.REMEDIATE_REVERSIBLE,
        BlastRadius.WORKLOAD,
        False,
        "Restart a single workload.",
    ),
    ToolSpec(
        "migrate_vm",
        None,  # reversible intra-site / destructive cross-site
        None,  # node intra-site / site cross-site
        True,
        "Migrate a VM to a target node.",
    ),
    ToolSpec(
        "throttle_power",
        IntentClass.REMEDIATE_DESTRUCTIVE,
        BlastRadius.NODE,
        False,
        "Throttle a node's power draw.",
    ),
    ToolSpec(
        "isolate_vlan",
        IntentClass.REMEDIATE_DESTRUCTIVE,
        BlastRadius.VLAN,
        False,
        "Isolate a network segment.",
    ),
    ToolSpec(
        "isolate_network_device",
        IntentClass.REMEDIATE_DESTRUCTIVE,
        None,  # vlan (leaf) / site (spine) by device lookup
        True,
        "Isolate a network device; radius depends on device role.",
    ),
    ToolSpec(
        "quarantine_node",
        IntentClass.REMEDIATE_DESTRUCTIVE,
        BlastRadius.NODE,
        False,
        "Quarantine a node.",
    ),
)

TOOLS: dict[str, ToolSpec] = {s.name: s for s in _SPECS}

#: ``network.isolate`` appears in the spec's envelope/decision examples (§5.1,
#: §6.2) as an alias of ``isolate_network_device``.
_ALIASES: dict[str, str] = {"network.isolate": "isolate_network_device"}


def canonical_name(tool: str) -> str:
    return _ALIASES.get(tool, tool)


def get_spec(tool: str) -> ToolSpec:
    """Return the spec for ``tool`` (resolving aliases) or fail closed."""
    name = canonical_name(tool)
    try:
        return TOOLS[name]
    except KeyError:
        raise UnknownToolError(f"unregistered tool: {tool!r}") from None
