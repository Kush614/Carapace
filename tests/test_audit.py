"""Tamper-evident unified audit chain (carapace/audit.py)."""

import json

from carapace import compose, default_mock_topology
from carapace.audit import AuditChain
from carapace.types import ContextChunk, IntentClass, IntentEnvelope, TrustLevel

TOPO = default_mock_topology()
STORE = {
    "telemetry:thermal:node-sj-01-03": ContextChunk(
        "telemetry:thermal:node-sj-01-03", "78C", TrustLevel.TRUSTED
    )
}
ENV = IntentEnvelope(
    intent=IntentClass.REMEDIATE_REVERSIBLE,
    target="vm-03",
    tool="migrate_vm",
    tool_args={"vm_id": "vm-03", "target_node": "node-sj-01-01"},
    source_signals=("telemetry:thermal:node-sj-01-03",),
)
LT_LINE = {
    "request_id": "req-1",
    "direction": "ingress",
    "action": "DENY",
    "rule": "block_prompt_injection",
}


def test_append_and_verify_clean_chain(tmp_path):
    chain = AuditChain(tmp_path / "audit.ndjson")
    chain.append_lobstertrap(LT_LINE)
    chain.append(compose(ENV, STORE, TOPO, None))
    chain.append(compose(ENV, STORE, TOPO, {"_lobstertrap": {"verdict": "DENY",
                  "ingress": {"detected": {"contains_injection_patterns": True,
                  "risk_score": 1.0}, "mismatches": [], "action": "DENY"}}}))
    ok, broken = chain.verify()
    assert ok is True and broken is None
    assert len(list(chain.entries())) == 3


def test_unified_chain_interleaves_both_layers(tmp_path):
    chain = AuditChain(tmp_path / "a.ndjson")
    chain.append_lobstertrap(LT_LINE)
    chain.append(compose(ENV, STORE, TOPO, None))
    kinds = [e["kind"] for e in chain.entries()]
    assert kinds == ["lobstertrap", "carapace"]


def test_tampering_breaks_the_chain(tmp_path):
    p = tmp_path / "a.ndjson"
    chain = AuditChain(p)
    chain.append(compose(ENV, STORE, TOPO, None))
    chain.append(compose(ENV, STORE, TOPO, None))
    chain.append(compose(ENV, STORE, TOPO, None))

    lines = p.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[1])
    assert tampered["payload"]["decision"] == "ALLOW"  # sanity: originally ALLOW
    tampered["payload"]["decision"] = "DENY"  # forge the verdict to differ
    lines[1] = json.dumps(tampered, default=str)
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok, broken = AuditChain(p).verify()
    assert ok is False
    assert broken == 1


def test_deleting_a_line_breaks_the_chain(tmp_path):
    p = tmp_path / "a.ndjson"
    chain = AuditChain(p)
    for _ in range(3):
        chain.append(compose(ENV, STORE, TOPO, None))
    lines = p.read_text(encoding="utf-8").splitlines()
    p.write_text("\n".join([lines[0], lines[2]]) + "\n", encoding="utf-8")
    ok, broken = AuditChain(p).verify()
    assert ok is False


def test_chain_resumes_across_reopen(tmp_path):
    p = tmp_path / "a.ndjson"
    AuditChain(p).append(compose(ENV, STORE, TOPO, None))
    reopened = AuditChain(p)  # must recover seq + last hash
    reopened.append(compose(ENV, STORE, TOPO, None))
    ok, _ = reopened.verify()
    assert ok is True
    seqs = [e["seq"] for e in reopened.entries()]
    assert seqs == [0, 1]


def test_entries_are_json_and_carry_signed_hash(tmp_path):
    chain = AuditChain(tmp_path / "a.ndjson")
    e = chain.append(compose(ENV, STORE, TOPO, None))
    assert e["signed_hash"].startswith("sha256:")
    assert e["entry_hash"].startswith("sha256:")
    assert e["prev_hash"] == "sha256:" + "0" * 64  # genesis
    json.dumps(e)
