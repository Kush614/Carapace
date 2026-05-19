import pytest

from carapace.intent_classifier import classify_intent
from carapace.topology import default_mock_topology
from carapace.types import ClassificationError, IntentClass, UnknownToolError

TOPO = default_mock_topology()


@pytest.mark.parametrize(
    "tool,args,expected",
    [
        ("get_telemetry", {"node_id": "node-sj-01-01"}, IntentClass.OBSERVE),
        ("read_logs", {"source": "syslog", "n": 50}, IntentClass.OBSERVE),
        ("propose_action", {"plan": "drain node"}, IntentClass.RECOMMEND),
        ("restart_workload", {"workload_id": "vm-01"}, IntentClass.REMEDIATE_REVERSIBLE),
        ("throttle_power", {"node_id": "node-sj-01-01", "pct": 50}, IntentClass.REMEDIATE_DESTRUCTIVE),
        ("isolate_vlan", {"vlan_id": "vlan-sj-01-10"}, IntentClass.REMEDIATE_DESTRUCTIVE),
        ("quarantine_node", {"node_id": "node-sj-01-01"}, IntentClass.REMEDIATE_DESTRUCTIVE),
    ],
)
def test_static_tool_intents(tool, args, expected):
    assert classify_intent(tool, args, TOPO) is expected


def test_migrate_vm_intra_site_is_reversible():
    # vm-01 lives on node-sj-01-01; node-sj-01-03 is the same site.
    intent = classify_intent(
        "migrate_vm", {"vm_id": "vm-01", "target_node": "node-sj-01-03"}, TOPO
    )
    assert intent is IntentClass.REMEDIATE_REVERSIBLE


def test_migrate_vm_cross_site_is_destructive():
    intent = classify_intent(
        "migrate_vm", {"vm_id": "vm-01", "target_node": "node-oak-01-01"}, TOPO
    )
    assert intent is IntentClass.REMEDIATE_DESTRUCTIVE


def test_isolate_network_device_intent_is_always_destructive():
    spine = classify_intent(
        "isolate_network_device", {"device_id": "spine-switch-sj-01"}, TOPO
    )
    leaf = classify_intent(
        "isolate_network_device", {"device_id": "leaf-switch-sj-01-a"}, TOPO
    )
    assert spine is IntentClass.REMEDIATE_DESTRUCTIVE
    assert leaf is IntentClass.REMEDIATE_DESTRUCTIVE


def test_network_isolate_alias_resolves():
    assert (
        classify_intent("network.isolate", {"device_id": "spine-switch-sj-01"}, TOPO)
        is IntentClass.REMEDIATE_DESTRUCTIVE
    )


def test_unknown_tool_fails_closed():
    with pytest.raises(UnknownToolError):
        classify_intent("rm_minus_rf", {}, TOPO)


def test_missing_required_arg_fails_closed():
    with pytest.raises(ClassificationError):
        classify_intent("migrate_vm", {"vm_id": "vm-01"}, TOPO)


def test_unknown_workload_fails_closed():
    with pytest.raises(ClassificationError):
        classify_intent(
            "migrate_vm", {"vm_id": "vm-99", "target_node": "node-sj-01-02"}, TOPO
        )
