"""Real Kubernetes executor — token-gated `kubectl` against a kind cluster.

This is the action layer's hands. It runs **real** `kubectl` (apply a
deny-all NetworkPolicy = total site isolation; delete to heal) and only
ever when handed a valid, unexpired, single-use execution token.

Design for testability + the spec's §17 fallback:

* a ``runner`` callable ``(argv, stdin) -> (rc, out, err)`` is injected,
  so command construction is unit-testable with a fake and no cluster;
* ``mode="mock"`` (env ``CARAPACE_EXECUTOR=mock``) keeps a tiny in-memory
  cluster so the API + frontend run with **no Docker/kind** — the
  spec-sanctioned SIM path. ``mode="kube"`` shells out to real kubectl.

Nothing here trusts the agent: no token, no kubectl.
"""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

SITES = ("site-sj-01", "site-sj-02", "site-oak-01")
ISOLATE_NP = "carapace-isolate"
TOKEN_TTL = 5.0  # seconds (spec)

Runner = Callable[[list, Optional[str]], tuple]


def _subprocess_runner(argv: list, stdin: Optional[str] = None) -> tuple:
    p = subprocess.run(
        argv, input=stdin, capture_output=True, text=True, timeout=30
    )
    return p.returncode, p.stdout, p.stderr


def isolate_networkpolicy(namespace: str) -> str:
    """The deny-all NetworkPolicy YAML applied to isolate a site (spec §3.2).

    Real, instant, total: pods stay Running but unreachable.
    """
    return (
        "apiVersion: networking.k8s.io/v1\n"
        "kind: NetworkPolicy\n"
        "metadata:\n"
        f"  name: {ISOLATE_NP}\n"
        f"  namespace: {namespace}\n"
        "spec:\n"
        "  podSelector: {}\n"
        "  policyTypes: [Ingress, Egress]\n"
        "  ingress: []\n"
        "  egress: []\n"
    )


# -- command builders (pure — unit-tested without a cluster) -------------- #

def argv_apply() -> list:
    return ["kubectl", "apply", "-f", "-"]


def argv_delete_all_np() -> list:
    return ["kubectl", "delete", "networkpolicy", "--all", "-A"]


def argv_rollout_restart(ns: str) -> list:
    return ["kubectl", "rollout", "restart", "deployment", "-n", ns]


def argv_get_json(kind: str, ns: str) -> list:
    return ["kubectl", "get", kind, "-n", ns, "-o", "json"]


@dataclass
class ExecToken:
    value: str
    action: str
    target: str
    expires_at: float
    redeemed: bool = False


@dataclass
class K8sExecutor:
    mode: str = "kube"  # "kube" | "mock"
    runner: Runner = _subprocess_runner
    now: Callable[[], float] = time.monotonic
    _tokens: dict = field(default_factory=dict)
    _mock_isolated: set = field(default_factory=set)

    @classmethod
    def from_env(cls) -> "K8sExecutor":
        mode = os.environ.get("CARAPACE_EXECUTOR", "kube").lower()
        return cls(mode="mock" if mode == "mock" else "kube")

    # -- token lifecycle ------------------------------------------------- #

    def mint_token(self, action: str, target: str) -> str:
        tok = "cp-exec-" + secrets.token_urlsafe(16)
        self._tokens[tok] = ExecToken(
            tok, action, target, self.now() + TOKEN_TTL
        )
        return tok

    def _redeem(self, token: str, action: str, target: str) -> ExecToken:
        t = self._tokens.get(token)
        if t is None:
            raise PermissionError("invalid execution token")
        if t.redeemed:
            raise PermissionError("token already redeemed")
        if self.now() > t.expires_at:
            raise PermissionError("token expired")
        if t.action != action or t.target != target:
            raise PermissionError("token does not match action/target")
        t.redeemed = True
        return t

    # -- actions --------------------------------------------------------- #

    def isolate(self, site: str, token: str) -> dict:
        """Apply the deny-all NetworkPolicy to ``site``. Token-gated."""
        if site not in SITES:
            raise ValueError(f"unknown site {site!r}")
        self._redeem(token, "network.isolate", site)
        if self.mode == "mock":
            self._mock_isolated.add(site)
            return {"applied": True, "site": site, "mode": "mock",
                    "networkpolicy": ISOLATE_NP}
        rc, out, err = self.runner(argv_apply(), isolate_networkpolicy(site))
        if rc != 0:
            raise RuntimeError(f"kubectl apply failed: {err.strip()}")
        return {"applied": True, "site": site, "mode": "kube",
                "networkpolicy": ISOLATE_NP, "kubectl": out.strip()}

    def reset(self) -> dict:
        """Delete every NetworkPolicy + restart deployments (heal)."""
        if self.mode == "mock":
            self._mock_isolated.clear()
            return {"reset": True, "mode": "mock"}
        rc, out, err = self.runner(argv_delete_all_np(), None)
        for ns in SITES:
            self.runner(argv_rollout_restart(ns), None)
        return {"reset": True, "mode": "kube", "kubectl": out.strip(),
                "rc": rc}

    # -- observation ----------------------------------------------------- #

    def _site_pods(self, ns: str) -> list:
        if self.mode == "mock":
            iso = ns in self._mock_isolated
            return [{"name": f"nginx-r{i}", "status": "Running",
                     "reachable": not iso} for i in range(1, 5)]
        rc, out, _ = self.runner(argv_get_json("pods", ns), None)
        pods = []
        try:
            for it in json.loads(out).get("items", []):
                ph = it.get("status", {}).get("phase", "Unknown")
                pods.append({"name": it["metadata"]["name"],
                             "status": ph, "reachable": True})
        except (ValueError, KeyError):
            pass
        return pods

    def _site_nps(self, ns: str) -> list:
        if self.mode == "mock":
            return [ISOLATE_NP] if ns in self._mock_isolated else []
        rc, out, _ = self.runner(argv_get_json("networkpolicy", ns), None)
        try:
            return [i["metadata"]["name"]
                    for i in json.loads(out).get("items", [])]
        except (ValueError, KeyError):
            return []

    def cluster_state(self) -> dict:
        """The §7.4 SSE shape the 3D fabric + witness panels consume."""
        sites = []
        isolated = set()
        for ns in SITES:
            nps = self._site_nps(ns)
            if ISOLATE_NP in nps:
                isolated.add(ns)
        for ns in SITES:
            nps = self._site_nps(ns)
            down = ns in isolated
            reach = [o for o in SITES
                     if o != ns and o not in isolated and not down]
            sites.append({
                "name": ns,
                "pods": self._site_pods(ns),
                "spine_reachable_from": reach,
                "network_policies": nps,
            })
        return {"sites": sites, "any_isolated": bool(isolated),
                "executor_mode": self.mode}

    def has_cluster(self) -> bool:
        """True if a real cluster answers (drives /v1/health.kind_cluster)."""
        if self.mode == "mock":
            return False
        try:
            rc, _, _ = self.runner(["kubectl", "version",
                                    "--client=false", "-o", "json"], None)
            return rc == 0
        except Exception:
            return False
