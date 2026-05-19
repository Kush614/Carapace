import pytest

from carapace.blast_radius import classify_blast_radius
from carapace.topology import default_mock_topology
from carapace.types import BlastRadius, ClassificationError, UnknownToolError

TOPO = default_mock_topology()


@pytest.mark.parametrize(
    "tool,args,expected",
    [
        ("get_telemetry", {}, BlastRadius.NONE),
        ("read_logs", {"source": "syslog", "n": 10}, BlastRadius.NONE),
        ("propose_action", {"plan": "x"}, BlastRadius.NONE),
        ("restart_workload", {"workload_id": "vm-01"}, BlastRadius.WORKLOAD),
        ("throttle_power", {"node_id": "node-sj-01-01", "pct": 50}, BlastRadius.NODE),
        ("quarantine_node", {"node_id": "node-sj-01-01"}, BlastRadius.NODE),
        ("isolate_vlan", {"vlan_id": "vlan-sj-01-10"}, BlastRadius.VLAN),
    ],
)
def test_static_tool_radius(tool, args, expected):
    assert classify_blast_radius(tool, args, TOPO) is expected


def test_migrate_vm_intra_site_radius_is_node():
    assert (
        classify_blast_radius(
            "migrate_vm", {"vm_id": "vm-01", "target_node": "node-sj-01-02"}, TOPO
        )
        is BlastRadius.NODE
    )


def test_migrate_vm_cross_site_radius_is_site():
    assert (
        classify_blast_radius(
            "migrate_vm", {"vm_id": "vm-01", "target_node": "node-oak-01-01"}, TOPO
        )
        is BlastRadius.SITE
    )


def test_isolate_spine_is_site_radius():
    assert (
        classify_blast_radius(
            "isolate_network_device", {"device_id": "spine-switch-sj-01"}, TOPO
        )
        is BlastRadius.SITE
    )


def test_isolate_leaf_is_vlan_radius():
    assert (
        classify_blast_radius(
            "network.isolate", {"device_id": "leaf-switch-sj-01-a"}, TOPO
        )
        is BlastRadius.VLAN
    )


def test_unknown_tool_fails_closed():
    with pytest.raises(UnknownToolError):
        classify_blast_radius("nukeitall", {}, TOPO)


def test_unknown_device_fails_closed():
    with pytest.raises(ClassificationError):
        classify_blast_radius(
            "isolate_network_device", {"device_id": "ghost-switch"}, TOPO
        )
