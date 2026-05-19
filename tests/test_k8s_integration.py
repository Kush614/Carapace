"""REAL Kubernetes integration test (runs only in CI, against a live kind
cluster with Calico). Proves the deny-all NetworkPolicy the executor
applies actually *severs real traffic*, then heals.

Gated by env CARAPACE_K8S_LIVE=1 so the normal 128-test suite stays green
on machines with no cluster (collected → skipped, never errors).

CI does the cluster bring-up (kind + Calico + manifests); this test only
exercises carapace.executor_k8s against it and asserts real connectivity
changes via an ephemeral curl pod.
"""

import os
import subprocess
import time

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("CARAPACE_K8S_LIVE") != "1",
    reason="real kind cluster only (CI: CARAPACE_K8S_LIVE=1)",
)

from carapace.executor_k8s import ISOLATE_NP, K8sExecutor  # noqa: E402

SRC_NS = "site-sj-02"
TARGET = "site-sj-01"
SPINE = "http://spine.site-sj-01.svc.cluster.local"


def _kubectl(*args, **kw):
    return subprocess.run(["kubectl", *args], capture_output=True,
                          text=True, timeout=kw.get("timeout", 60))


def _curl_from_sj02(timeout_s=4) -> bool:
    """True iff an ephemeral pod in site-sj-02 can reach site-sj-01's spine."""
    r = subprocess.run(
        ["kubectl", "run", f"probe-{int(time.time()*1000)%100000}",
         "-n", SRC_NS, "--image=curlimages/curl:8.10.1", "--restart=Never",
         "--rm", "-i", "--quiet", "--command", "--",
         "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
         "-m", str(timeout_s), SPINE],
        capture_output=True, text=True, timeout=90)
    return "200" in (r.stdout or "")


def _wait(predicate, tries=18, gap=5):
    for _ in range(tries):
        if predicate():
            return True
        time.sleep(gap)
    return False


def test_real_networkpolicy_severs_and_heals_traffic():
    ex = K8sExecutor(mode="kube")

    # 1. baseline: cross-site connectivity works (no NetworkPolicy yet).
    assert _wait(_curl_from_sj02), "baseline: sj-02 → sj-01 spine must work"

    # 2. real isolation via the token-gated executor.
    tok = ex.mint_token("network.isolate", TARGET)
    res = ex.isolate(TARGET, tok)
    assert res["applied"] and res["mode"] == "kube"
    assert ISOLATE_NP in _kubectl(
        "get", "networkpolicy", "-n", TARGET, "-o", "name").stdout

    # 3. Calico now enforces deny-all → traffic is really cut.
    assert _wait(lambda: not _curl_from_sj02()), \
        "after isolate: sj-02 → sj-01 must be severed (real enforcement)"

    # 4. heal.
    ex.reset()
    assert "carapace-isolate" not in _kubectl(
        "get", "networkpolicy", "-A").stdout

    # 5. connectivity restored.
    assert _wait(_curl_from_sj02), "after reset: connectivity must restore"


def test_cluster_state_reflects_real_isolation():
    ex = K8sExecutor(mode="kube")
    cs0 = ex.cluster_state()
    assert any(s["name"] == TARGET for s in cs0["sites"])

    tok = ex.mint_token("network.isolate", TARGET)
    ex.isolate(TARGET, tok)
    cs1 = ex.cluster_state()
    sj = next(s for s in cs1["sites"] if s["name"] == TARGET)
    assert ISOLATE_NP in sj["network_policies"]
    assert cs1["any_isolated"] is True

    ex.reset()
    assert ex.cluster_state()["any_isolated"] is False
