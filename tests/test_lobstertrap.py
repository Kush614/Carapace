"""Carapace ↔ Lobster Trap composition (carapace/lobstertrap.py).

Covers the parser against the real proxy contract (internal/metadata/types.go),
the monotone fold, and end-to-end composition incl. DENY→QUARANTINE escalation.
"""

import json

import pytest

from carapace import (
    compose,
    evaluate,
    fold_lt_signal,
    parse_lt_metadata,
)
from carapace.decision_engine import build_inputs
from carapace.topology import default_mock_topology
from carapace.types import (
    BlastRadius,
    ContextChunk,
    Decision,
    DecisionInputs,
    IntentClass,
    IntentEnvelope,
    TrustLevel,
)

TOPO = default_mock_topology()

TRUSTED = ContextChunk("telemetry:thermal:node-sj-01-03", "78C", TrustLevel.TRUSTED)
STORE = {TRUSTED.chunk_id: TRUSTED}

# A reversible, trusted, intra-site migration — Scenario A. Standalone => ALLOW R7.
SCENARIO_A = IntentEnvelope(
    intent=IntentClass.REMEDIATE_REVERSIBLE,
    target="vm-03",
    tool="migrate_vm",
    tool_args={"vm_id": "vm-03", "target_node": "node-sj-01-01"},
    justification="Thermal anomaly; drain workload.",
    source_signals=("telemetry:thermal:node-sj-01-03",),
)

# Shaped exactly like the proxy's _lobstertrap ResponseHeaders.
LT_INJECTION = {
    "_lobstertrap": {
        "request_id": "req-1",
        "verdict": "DENY",
        "ingress": {
            "declared": {"declared_intent": "observe", "agent_id": "ops-agent-1"},
            "detected": {
                "intent_category": "network",
                "risk_score": 1.0,
                "contains_injection_patterns": True,
                "contains_exfiltration": True,
                "contains_obfuscation": True,
                "target_paths": ["~/.ssh/id_rsa"],
                "target_domains": ["pastebin.com"],
                "target_commands": ["rm -rf /"],
            },
            "mismatches": [
                {"field": "intent", "declared": "observe",
                 "detected": "network", "severity": "critical"}
            ],
            "action": "DENY",
            "rule_name": "block_prompt_injection",
        },
        "egress": None,
    }
}

LT_CLEAN = {
    "_lobstertrap": {
        "request_id": "req-2",
        "verdict": "ALLOW",
        "ingress": {
            "declared": {"declared_intent": "remediate_reversible"},
            "detected": {
                "intent_category": "general",
                "risk_score": 0.04,
                "contains_injection_patterns": False,
            },
            "mismatches": [],
            "action": "ALLOW",
        },
        "egress": {"detected": {"risk_score": 0.0,
                                "contains_credentials": False}, "action": "ALLOW"},
    }
}


def _lt_risk(score: float) -> dict:
    return {
        "_lobstertrap": {
            "request_id": "req-r",
            "verdict": "ALLOW",
            "ingress": {
                "detected": {"intent_category": "general", "risk_score": score},
                "mismatches": [],
                "action": "ALLOW",
            },
        }
    }


# --------------------------- parser ---------------------------------------- #


def test_parse_absent_metadata_is_not_present():
    assert parse_lt_metadata(None).present is False
    assert parse_lt_metadata({}).present is False
    assert parse_lt_metadata({"choices": []}).present is False


def test_parse_full_response_and_bare_block_equivalent():
    a = parse_lt_metadata(LT_INJECTION)
    b = parse_lt_metadata(LT_INJECTION["_lobstertrap"])
    assert a.present and b.present
    assert a.verdict == b.verdict == "DENY"
    assert a.injection is True and a.exfiltration is True
    assert a.risk_score == 1.0
    assert a.target_domains == ("pastebin.com",)
    assert a.mismatches == ("intent (critical)",)


def test_parse_drops_info_severity_mismatches():
    payload = {
        "_lobstertrap": {
            "verdict": "ALLOW",
            "ingress": {
                "detected": {"risk_score": 0.0},
                "mismatches": [
                    {"field": "paths", "severity": "info"},
                    {"field": "intent", "severity": "warning"},
                ],
                "action": "ALLOW",
            },
        }
    }
    assert parse_lt_metadata(payload).mismatches == ("intent (warning)",)


def test_parse_worst_risk_across_ingress_egress_and_null_targets():
    payload = {
        "_lobstertrap": {
            "verdict": "ALLOW",
            "ingress": {"detected": {"risk_score": 0.2, "target_paths": None},
                        "action": "ALLOW"},
            "egress": {"detected": {"risk_score": 0.8,
                                    "contains_credentials": True}, "action": "DENY"},
        }
    }
    sig = parse_lt_metadata(payload)
    assert sig.risk_score == 0.8
    assert sig.credentials is True
    assert sig.target_paths == ()


# ---------------------------- fold ----------------------------------------- #

BASE = DecisionInputs(
    declared_intent=IntentClass.REMEDIATE_REVERSIBLE,
    detected_intent=IntentClass.REMEDIATE_REVERSIBLE,
    effective_provenance=TrustLevel.TRUSTED,
    blast_radius=BlastRadius.WORKLOAD,  # unused by fold
    injection_flag=False,
)


def test_fold_absent_is_identity():
    folded, notes = fold_lt_signal(BASE, parse_lt_metadata(None))
    assert folded == BASE
    assert notes == []


def test_fold_injection_sets_flag():
    folded, notes = fold_lt_signal(BASE, parse_lt_metadata(LT_INJECTION))
    assert folded.injection_flag is True
    assert any("conversation layer" in n for n in notes)


def test_fold_high_risk_forces_untrusted():
    folded, _ = fold_lt_signal(BASE, parse_lt_metadata(_lt_risk(0.7)))
    assert folded.effective_provenance is TrustLevel.UNTRUSTED


def test_fold_mid_risk_downgrades_one_notch():
    folded, _ = fold_lt_signal(BASE, parse_lt_metadata(_lt_risk(0.4)))
    assert folded.effective_provenance is TrustLevel.SEMI_TRUSTED


def test_fold_is_monotone_never_loosens():
    # Clean LT signal must not raise trust or clear an existing injection flag.
    tainted = DecisionInputs(
        BASE.declared_intent, BASE.detected_intent,
        TrustLevel.UNTRUSTED, BASE.blast_radius, True,
    )
    folded, notes = fold_lt_signal(tainted, parse_lt_metadata(LT_CLEAN))
    assert folded.injection_flag is True
    assert folded.effective_provenance is TrustLevel.UNTRUSTED
    assert notes == []


# -------------------------- compose ---------------------------------------- #


def test_compose_without_lt_equals_evaluate():
    c = compose(SCENARIO_A, STORE, TOPO, None)
    e = evaluate(SCENARIO_A, STORE, TOPO)
    assert c.decision is e.decision is Decision.ALLOW
    assert c.rule_fired == e.rule_fired == "R7"
    assert c.lobstertrap is None
    assert c.composition_notes == ()


def test_compose_money_shot_escalates_deny_to_quarantine():
    # Infra context is clean (trusted source, reversible, intra-site) — the
    # core engine alone would ALLOW. Lobster Trap caught conversation-layer
    # injection on the same turn; Carapace blocks the *action* and escalates.
    rec = compose(SCENARIO_A, STORE, TOPO, LT_INJECTION)
    assert rec.base_decision is Decision.DENY
    assert rec.rule_fired == "R2"
    assert rec.decision is Decision.QUARANTINE
    assert rec.injection_flag is True
    assert rec.lobstertrap["verdict"] == "DENY"
    assert "defense in depth" in rec.rule_explanation.lower()
    assert rec.composition_notes


def test_compose_risk_tightens_without_injection():
    # No injection, but LT risk_score 0.7 forces provenance untrusted, so a
    # reversible action that would pass (R7) now fails closed (R9).
    rec = compose(SCENARIO_A, STORE, TOPO, _lt_risk(0.7))
    assert rec.decision is Decision.DENY
    assert rec.rule_fired == "R9"
    assert rec.base_decision is Decision.DENY  # not escalated (no corroboration)
    assert rec.effective_provenance is TrustLevel.UNTRUSTED


def test_compose_clean_lt_leaves_allow():
    rec = compose(SCENARIO_A, STORE, TOPO, LT_CLEAN)
    assert rec.decision is Decision.ALLOW
    assert rec.rule_fired == "R7"
    assert rec.lobstertrap["present"] is True


def test_compose_failclosed_unknown_tool_with_lt_present():
    env = IntentEnvelope(
        intent=IntentClass.REMEDIATE_DESTRUCTIVE,
        target="x",
        tool="format_all_disks",
        tool_args={},
        source_signals=("telemetry:thermal:node-sj-01-03",),
    )
    rec = compose(env, STORE, TOPO, LT_INJECTION)
    assert rec.decision is Decision.DENY
    assert rec.rule_fired == "R9"
    assert rec.lobstertrap is not None  # still recorded for audit


def test_compose_record_is_json_safe():
    rec = compose(SCENARIO_A, STORE, TOPO, LT_INJECTION)
    json.dumps(rec.to_dict())


@pytest.mark.parametrize("payload", [LT_INJECTION, LT_CLEAN, _lt_risk(0.5), None])
def test_compose_never_raises(payload):
    compose(SCENARIO_A, STORE, TOPO, payload)
