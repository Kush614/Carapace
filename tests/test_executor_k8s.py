"""K8s executor — command construction + token gating, no cluster."""

import pytest

from carapace.executor_k8s import (
    ISOLATE_NP,
    K8sExecutor,
    argv_apply,
    argv_delete_all_np,
    isolate_networkpolicy,
)


def test_networkpolicy_is_deny_all_for_namespace():
    y = isolate_networkpolicy("site-sj-01")
    assert "kind: NetworkPolicy" in y
    assert f"name: {ISOLATE_NP}" in y
    assert "namespace: site-sj-01" in y
    assert "ingress: []" in y and "egress: []" in y
    assert "policyTypes: [Ingress, Egress]" in y


def test_argv_builders():
    assert argv_apply() == ["kubectl", "apply", "-f", "-"]
    assert argv_delete_all_np() == ["kubectl", "delete", "networkpolicy",
                                    "--all", "-A"]


def test_token_single_use_and_expiry():
    clk = [1000.0]
    ex = K8sExecutor(mode="mock", now=lambda: clk[0])
    tok = ex.mint_token("network.isolate", "site-sj-01")
    ex.isolate("site-sj-01", tok)                       # ok
    with pytest.raises(PermissionError):                # replay
        ex.isolate("site-sj-01", tok)
    tok2 = ex.mint_token("network.isolate", "site-sj-02")
    clk[0] += 6                                         # past 5s TTL
    with pytest.raises(PermissionError):
        ex.isolate("site-sj-02", tok2)


def test_token_must_match_action_and_target():
    ex = K8sExecutor(mode="mock")
    tok = ex.mint_token("network.isolate", "site-sj-01")
    with pytest.raises(PermissionError):
        ex.isolate("site-sj-02", tok)                   # wrong target
    with pytest.raises(PermissionError):
        ex.isolate("site-sj-01", "cp-exec-bogus")       # invalid token


def test_mock_isolate_then_state_then_reset():
    ex = K8sExecutor(mode="mock")
    cs0 = ex.cluster_state()
    assert cs0["any_isolated"] is False
    assert all(s["network_policies"] == [] for s in cs0["sites"])

    tok = ex.mint_token("network.isolate", "site-sj-01")
    ex.isolate("site-sj-01", tok)
    cs1 = ex.cluster_state()
    sj = next(s for s in cs1["sites"] if s["name"] == "site-sj-01")
    assert sj["network_policies"] == [ISOLATE_NP]
    assert all(p["reachable"] is False for p in sj["pods"])
    other = next(s for s in cs1["sites"] if s["name"] == "site-sj-02")
    assert other["network_policies"] == []              # blast = one site

    ex.reset()
    assert ex.cluster_state()["any_isolated"] is False


def test_kube_mode_uses_runner_and_fails_closed():
    calls = []

    def fake(argv, stdin=None):
        calls.append((argv, stdin))
        return (0, "networkpolicy/carapace-isolate created", "")

    ex = K8sExecutor(mode="kube", runner=fake)
    tok = ex.mint_token("network.isolate", "site-sj-01")
    r = ex.isolate("site-sj-01", tok)
    assert r["applied"] and r["mode"] == "kube"
    assert calls[0][0] == ["kubectl", "apply", "-f", "-"]
    assert "name: carapace-isolate" in calls[0][1]

    def fail(argv, stdin=None):
        return (1, "", "forbidden")

    ex2 = K8sExecutor(mode="kube", runner=fail)
    t2 = ex2.mint_token("network.isolate", "site-sj-01")
    with pytest.raises(RuntimeError):
        ex2.isolate("site-sj-01", t2)


def test_mock_has_no_cluster():
    assert K8sExecutor(mode="mock").has_cluster() is False


def test_unknown_site_rejected():
    ex = K8sExecutor(mode="mock")
    tok = ex.mint_token("network.isolate", "site-nope")
    with pytest.raises(ValueError):
        ex.isolate("site-nope", tok)
