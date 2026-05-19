"""Edge-infrastructure topology used for argument-aware classification.

The decision engine is a pure function; argument-aware classifiers (e.g.
``migrate_vm`` is reversible intra-site but destructive cross-site) need to
know the shape of the deployment. We pass that shape in explicitly as an
immutable :class:`Topology` so the classifiers stay pure and testable.

:func:`default_mock_topology` builds the hackathon demo substrate (spec §8):
3 sites, 4 compute nodes + 1 spine switch per site, 12 workloads.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping

from .types import ClassificationError


@dataclass(frozen=True, slots=True)
class Topology:
    """An immutable snapshot of the edge deployment."""

    node_site: Mapping[str, str] = field(default_factory=dict)
    node_role: Mapping[str, str] = field(default_factory=dict)  # compute|spine|leaf
    vm_node: Mapping[str, str] = field(default_factory=dict)  # vm_id -> current node
    vlan_site: Mapping[str, str] = field(default_factory=dict)
    device_role: Mapping[str, str] = field(default_factory=dict)  # spine|leaf
    device_site: Mapping[str, str] = field(default_factory=dict)

    # -- lookups; every miss fails closed (spec §6.3) -------------------- #

    def site_of_node(self, node_id: str) -> str:
        try:
            return self.node_site[node_id]
        except KeyError:
            raise ClassificationError(f"unknown node: {node_id!r}") from None

    def role_of_node(self, node_id: str) -> str:
        try:
            return self.node_role[node_id]
        except KeyError:
            raise ClassificationError(f"unknown node: {node_id!r}") from None

    def node_of_vm(self, vm_id: str) -> str:
        try:
            return self.vm_node[vm_id]
        except KeyError:
            raise ClassificationError(f"unknown workload: {vm_id!r}") from None

    def role_of_device(self, device_id: str) -> str:
        try:
            return self.device_role[device_id]
        except KeyError:
            raise ClassificationError(f"unknown network device: {device_id!r}") from None

    def same_site(self, node_a: str, node_b: str) -> bool:
        return self.site_of_node(node_a) == self.site_of_node(node_b)


def default_mock_topology() -> Topology:
    """The 3-site Veea-style demo substrate from spec §8."""
    sites = ("sj-01", "sj-02", "oak-01")

    node_site: dict[str, str] = {}
    node_role: dict[str, str] = {}
    vm_node: dict[str, str] = {}
    vlan_site: dict[str, str] = {}
    device_role: dict[str, str] = {}
    device_site: dict[str, str] = {}

    vm_counter = 1
    for site in sites:
        # 4 compute nodes per site.
        site_nodes = [f"node-{site}-{i:02d}" for i in range(1, 5)]
        for node in site_nodes:
            node_site[node] = site
            node_role[node] = "compute"

        # 1 spine switch per site — addressable as a node *and* a device.
        spine = f"spine-switch-{site}"
        node_site[spine] = site
        node_role[spine] = "spine"
        device_role[spine] = "spine"
        device_site[spine] = site

        # 2 leaf switches per site (vlan-scoped blast radius).
        for leaf_suffix in ("a", "b"):
            leaf = f"leaf-switch-{site}-{leaf_suffix}"
            node_site[leaf] = site
            node_role[leaf] = "leaf"
            device_role[leaf] = "leaf"
            device_site[leaf] = site

        # 2 VLANs per site.
        for vlan_id in (10, 20):
            vlan_site[f"vlan-{site}-{vlan_id}"] = site

        # 4 workloads per site -> 12 total, round-robin across compute nodes.
        for j in range(4):
            vm_node[f"vm-{vm_counter:02d}"] = site_nodes[j]
            vm_counter += 1

    return Topology(
        node_site=node_site,
        node_role=node_role,
        vm_node=vm_node,
        vlan_site=vlan_site,
        device_role=device_role,
        device_site=device_site,
    )
