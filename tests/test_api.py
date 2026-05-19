"""Carapace action-gate HTTP service (carapace/api.py)."""

import time

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from carapace.api import create_app  # noqa: E402

TRUSTED_CTX = {
    "chunk_id": "telemetry:thermal:node-sj-01-03",
    "content": "78C rising",
    "trust_level": "trusted",
}
SCEN_A = {
    "intent": "remediate_reversible",
    "target": "vm-03",
    "tool": "migrate_vm",
    "tool_args": {"vm_id": "vm-03", "target_node": "node-sj-01-01"},
    "source_signals": ["telemetry:thermal:node-sj-01-03"],
}
SCEN_D = {
    "intent": "remediate_destructive",
    "target": "spine-switch-sj-01",
    "tool": "isolate_network_device",
    "tool_args": {"device_id": "spine-switch-sj-01"},
    "source_signals": ["telemetry:thermal:node-sj-01-03"],
}
LT_INJECTION = {
    "_lobstertrap": {
        "verdict": "DENY",
        "ingress": {
            "detected": {"contains_injection_patterns": True, "risk_score": 1.0},
            "mismatches": [], "action": "DENY",
        },
    }
}


def _client(tmp_path, **kw):
    app = create_app(audit_path=tmp_path / "audit.ndjson", **kw)
    c = TestClient(app)
    c.post("/v1/context", json=TRUSTED_CTX)
    return c


def test_allow_then_single_use_execute(tmp_path):
    c = _client(tmp_path)
    r = c.post("/v1/check", json={"envelope": SCEN_A}).json()
    assert r["decision"] == "ALLOW" and "execution_token" in r
    tok = r["execution_token"]

    ex = c.post("/v1/execute", json={"execution_token": tok,
                "tool": "migrate_vm",
                "tool_args": SCEN_A["tool_args"]})
    assert ex.status_code == 200 and ex.json()["executed"] is True

    # Single-use: replay is refused.
    again = c.post("/v1/execute", json={"execution_token": tok,
                   "tool": "migrate_vm", "tool_args": SCEN_A["tool_args"]})
    assert again.status_code == 403


def test_token_expires(tmp_path):
    c = _client(tmp_path, token_ttl=0.05)
    tok = c.post("/v1/check", json={"envelope": SCEN_A}).json()["execution_token"]
    time.sleep(0.07)
    ex = c.post("/v1/execute", json={"execution_token": tok,
                "tool": "migrate_vm", "tool_args": SCEN_A["tool_args"]})
    assert ex.status_code == 403 and "expired" in ex.json()["detail"]


def test_money_shot_quarantine_no_token(tmp_path):
    c = _client(tmp_path)
    r = c.post("/v1/check", json={"envelope": SCEN_A,
               "lobstertrap": LT_INJECTION}).json()
    assert r["decision"] == "QUARANTINE"
    assert r["base_decision"] == "DENY"
    assert "execution_token" not in r
    assert "blocked" in r["user_message"].lower()


def test_execute_rejected_without_valid_token(tmp_path):
    c = _client(tmp_path)
    ex = c.post("/v1/execute", json={"execution_token": "nope",
                "tool": "migrate_vm", "tool_args": {}})
    assert ex.status_code == 403


def test_human_review_flow_records_reviewer(tmp_path):
    c = _client(tmp_path)
    r = c.post("/v1/check", json={"envelope": SCEN_D}).json()
    assert r["decision"] == "HUMAN_REVIEW" and r["rule_fired"] == "R4"
    rid = r["review_id"]
    assert c.get(r["poll_url"]).json()["status"] == "pending"

    appr = c.post(f"/v1/review/{rid}",
                  json={"approve": True, "reviewer": "alice@ops"}).json()
    assert appr["status"] == "approved" and "execution_token" in appr

    audit = c.get("/v1/audit").json()
    assert audit["intact"] is True
    assert any(e["payload"].get("reviewer") == "alice@ops"
               for e in audit["entries"])


def test_unknown_tool_fails_closed(tmp_path):
    c = _client(tmp_path)
    r = c.post("/v1/check", json={"envelope": {
        "intent": "remediate_destructive", "tool": "format_all_disks",
        "tool_args": {}, "source_signals": ["telemetry:thermal:node-sj-01-03"]}})
    assert r.json()["decision"] == "DENY" and r.json()["rule_fired"] == "R9"


def test_audit_chain_intact_and_healthz(tmp_path):
    c = _client(tmp_path)
    c.post("/v1/check", json={"envelope": SCEN_A})
    c.post("/v1/check", json={"envelope": SCEN_A, "lobstertrap": LT_INJECTION})
    h = c.get("/healthz").json()
    assert h["status"] == "ok" and h["audit_chain_intact"] is True
    assert c.get("/v1/audit").json()["count"] >= 2
