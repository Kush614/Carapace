"""Agent logic — network-free (fake HTTP client). The live path is
exercised by demo/run_live.py, not the unit suite.
"""

import json

import pytest

from carapace.agent import (
    AgentConfig,
    _extract_envelope,
    _tool_catalog,
    propose_action,
)
from carapace.types import IntentClass

CFG = AgentConfig(api_key="test-key")


class _Resp:
    def __init__(self, payload):
        self._p = payload

    def json(self):
        return self._p


class _Client:
    def __init__(self, payload=None, raise_exc=None):
        self._p = payload
        self._raise = raise_exc

    def post(self, *a, **k):
        if self._raise:
            raise self._raise
        return _Resp(self._p)


def _completion(content, lt=None):
    p = {"choices": [{"message": {"content": content}}]}
    if lt is not None:
        p["_lobstertrap"] = lt
    return p


def test_tool_catalog_lists_registered_tools():
    cat = _tool_catalog()
    assert "migrate_vm" in cat and "isolate_network_device" in cat


def test_extract_envelope_clean_json():
    env = _extract_envelope(json.dumps({
        "intent": "remediate_reversible", "tool": "migrate_vm",
        "tool_args": {"vm_id": "vm-03", "target_node": "node-sj-01-01"},
        "target": "vm-03", "justification": "drain", "source_signals": ["t1"],
        "agent_confidence": 0.8, "estimated_blast_radius": "node"}))
    assert env is not None
    assert env.intent is IntentClass.REMEDIATE_REVERSIBLE
    assert env.tool == "migrate_vm"
    assert env.source_signals == ("t1",)


def test_extract_envelope_tolerates_surrounding_prose():
    env = _extract_envelope(
        'Sure! Here is the plan:\n{"intent":"observe","tool":"get_telemetry",'
        '"tool_args":{"node_id":"n1"},"target":"n1","justification":"x",'
        '"source_signals":[],"agent_confidence":0.5}\nHope that helps.')
    assert env is not None and env.intent is IntentClass.OBSERVE


def test_extract_envelope_invalid_returns_none():
    assert _extract_envelope("no json here") is None
    assert _extract_envelope('{"intent": "bogus", "tool": "x"}') is None


def test_from_env_requires_key(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    with pytest.raises(RuntimeError):
        AgentConfig.from_env()


def test_propose_action_parses_envelope():
    payload = _completion(
        json.dumps({"intent": "observe", "tool": "get_telemetry",
                    "tool_args": {"node_id": "n1"}, "target": "n1",
                    "justification": "check", "source_signals": ["s1"],
                    "agent_confidence": 0.9}),
        lt={"verdict": "ALLOW", "ingress": {"detected": {"risk_score": 0.0}}})
    prop = propose_action("g", "s", [{"id": "s1", "trust": "trusted"}],
                          config=CFG, client=_Client(payload))
    assert prop.blocked_by_lt is False
    assert prop.envelope is not None and prop.envelope.tool == "get_telemetry"
    assert prop.lt["verdict"] == "ALLOW"


def test_propose_action_detects_lt_block():
    payload = _completion(
        "[LOBSTER TRAP] Blocked: prompt injection detected.",
        lt={"verdict": "DENY", "ingress": {"action": "DENY",
            "rule_name": "block_prompt_injection",
            "detected": {"contains_injection_patterns": True}}})
    prop = propose_action("g", "s", [{"id": "x", "trust": "untrusted"}],
                          config=CFG, client=_Client(payload))
    assert prop.blocked_by_lt is True
    assert prop.envelope is None
    assert prop.lt["verdict"] == "DENY"


def test_propose_action_network_error_is_captured():
    prop = propose_action("g", "s", [], config=CFG,
                          client=_Client(raise_exc=RuntimeError("proxy down")))
    assert prop.envelope is None
    assert "proxy down" in prop.error
