"""Demo API gate logic (executor in mock mode — no cluster). SSE endpoints
are infinite generators and intentionally not exercised here.
"""

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402


def _client(monkeypatch):
    monkeypatch.setenv("CARAPACE_EXECUTOR", "mock")
    import importlib
    import carapace.demo_api as d
    importlib.reload(d)
    return TestClient(d.create_app())


def test_health_reports_mock_no_cluster(monkeypatch):
    r = _client(monkeypatch).get("/v1/health").json()
    assert r["status"] == "ok"
    assert r["kind_cluster"] is False
    assert r["executor_mode"] == "mock"
    assert r["gate"] is None


def test_inject_requires_gate_first(monkeypatch):
    c = _client(monkeypatch)
    assert c.post("/v1/inject").status_code == 409


def test_gate_off_bypasses_and_executes(monkeypatch):
    c = _client(monkeypatch)
    assert c.post("/v1/gate", json={"state": "OFF"}).json()["gate"] == "OFF"
    j = c.post("/v1/inject").json()
    assert j["decision"] == "BYPASSED"
    assert j["executed"] is True          # kubectl WAS called (no gate)


def test_gate_on_quarantines_and_does_not_execute(monkeypatch):
    c = _client(monkeypatch)
    c.post("/v1/gate", json={"state": "ON"})
    j = c.post("/v1/inject").json()
    assert j["decision"] == "QUARANTINE"
    assert j["base_decision"] == "DENY"   # R2, escalated by LT corroboration
    assert j["executed"] is False         # kubectl NEVER called


def test_reset_clears_gate(monkeypatch):
    c = _client(monkeypatch)
    c.post("/v1/gate", json={"state": "ON"})
    assert c.post("/v1/reset").json()["reset"] is True
    assert c.get("/v1/health").json()["gate"] is None


def test_bad_gate_value_rejected(monkeypatch):
    c = _client(monkeypatch)
    assert c.post("/v1/gate", json={"state": "MAYBE"}).status_code == 400


def test_chat_pinned_question_answered_offline(monkeypatch):
    # No GEMINI_API_KEY in test env -> Gemini path raises -> KB fallback.
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    c = _client(monkeypatch)
    j = c.post("/v1/chat", json={"message": "what is carapace?"}).json()
    assert j["source"] == "kb"
    assert "action-layer" in j["answer"].lower()


def test_chat_unknown_falls_back_to_about(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    c = _client(monkeypatch)
    j = c.post("/v1/chat", json={"message": "zxqw unrelated nonsense"}).json()
    assert j["source"] == "kb" and "About page" in j["answer"]


def test_chat_requires_message_or_image(monkeypatch):
    c = _client(monkeypatch)
    assert c.post("/v1/chat", json={}).status_code == 400
