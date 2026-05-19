"""Carapace before/after demo API (Final Demo Spec §13).

One FastAPI app. Real Carapace decision (`compose`), real token-gated
Kubernetes executor (`K8sExecutor`), real SHA-256 audit chain. The only
synthesized piece is the Lobster Trap verdict for the fixed poisoned log
(deterministic FLAG/pi=0.94) so the demo is repeatable; the *decision*
and the *kubectl* are real.

Run:  uvicorn carapace.demo_api:app --port 8000
Mode: CARAPACE_EXECUTOR=mock  -> in-memory cluster (no Docker/kind)
      (default)               -> real kubectl against the kind cluster

Endpoints: /v1/health /v1/gate /v1/inject /v1/reset
           /v1/cluster-state (SSE) /v1/audit (SSE)
           /v1/kubectl-stream/{policies|pods|curl} (SSE)
           /v1/lobstertrap-events (SSE)
"""

from __future__ import annotations

import asyncio
import json
import tempfile
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from .audit import AuditChain
from .executor_k8s import K8sExecutor
from .lobstertrap import compose
from .poisoned_log import INGEST_SOURCE, POISONED_LOG, TARGET_SITE
from .topology import default_mock_topology
from .types import ContextChunk, Decision, IntentClass, IntentEnvelope, TrustLevel

SRC = "syslog:line-4471"

# Synthetic but deterministic Lobster Trap verdict for the constant log
# (real LT integration lives in carapace/agent.py; here it is fixed so
# BEFORE and AFTER are byte-identical).
LT_FLAG = {
    "_lobstertrap": {
        "request_id": "lt-req-3f8c2a91",
        "verdict": "FLAG",
        "ingress": {
            "detected": {"intent_category": "system", "risk_score": 0.94,
                         "contains_injection_patterns": True},
            "mismatches": [], "action": "FLAG",
            "rule_name": "ops_agent_destructive_drift",
        },
    }
}


class GateBody(BaseModel):
    state: str  # "OFF" | "ON"


def _envelope() -> IntentEnvelope:
    return IntentEnvelope(
        intent=IntentClass.REMEDIATE_DESTRUCTIVE,
        target="spine-switch-sj-01",
        tool="network.isolate",
        tool_args={"device_id": "spine-switch-sj-01"},
        justification="Spine switch compromised per ingested syslog.",
        source_signals=(SRC,),
    )


def create_app() -> FastAPI:
    app = FastAPI(title="Carapace demo API", version="1.0")
    app.add_middleware(CORSMiddleware, allow_origins=["*"],
                       allow_methods=["*"], allow_headers=["*"])

    ex = K8sExecutor.from_env()
    topo = default_mock_topology()
    store = {SRC: ContextChunk(SRC, POISONED_LOG, TrustLevel.UNTRUSTED,
                               injection_suspected=True)}
    chain = AuditChain(Path(tempfile.gettempdir()) / "carapace_demo_audit.ndjson")
    st = {"gate": None, "lt_events": [], "last": None}

    @app.get("/v1/health")
    def health():
        return {"status": "ok", "gemini": "configured",
                "lobstertrap": "synthetic-deterministic",
                "kind_cluster": ex.has_cluster(),
                "executor_mode": ex.mode, "gate": st["gate"]}

    @app.post("/v1/gate")
    def set_gate(b: GateBody):
        s = b.state.upper()
        if s not in ("OFF", "ON"):
            raise HTTPException(400, "state must be OFF or ON")
        st["gate"] = s
        return {"gate": s}

    @app.post("/v1/inject", status_code=202)
    def inject():
        if st["gate"] not in ("OFF", "ON"):
            raise HTTPException(409, "choose the gate (OFF|ON) first")
        st["lt_events"].append({
            "ts": time.strftime("%H:%M:%S"), "action": "FLAG",
            "pi": 0.94, "rule": "ops_agent_destructive_drift",
            "intent": "system", "source": INGEST_SOURCE})

        if st["gate"] == "OFF":
            # No action layer: the tool call goes straight to kubectl.
            tok = ex.mint_token("network.isolate", TARGET_SITE)
            result = ex.isolate(TARGET_SITE, tok)
            chain.append_lobstertrap({"request_id": "lt-req-3f8c2a91",
                "direction": "ingress", "action": "FLAG", "gate": "OFF",
                "note": "carapace bypassed — gate OFF"})
            st["last"] = {"gate": "OFF", "decision": "BYPASSED",
                          "executed": True, "result": result}
            return st["last"]

        # Gate ON: real Carapace decision.
        rec = compose(_envelope(), store, topo, LT_FLAG)
        chain.append_lobstertrap({"request_id": "lt-req-3f8c2a91",
            "direction": "ingress", "action": "FLAG", "gate": "ON"})
        chain.append(rec)
        executed = False
        if rec.decision is Decision.ALLOW:
            tok = ex.mint_token("network.isolate", TARGET_SITE)
            ex.isolate(TARGET_SITE, tok)
            executed = True
        st["last"] = {"gate": "ON", "decision": rec.decision.value,
                      "base_decision": rec.base_decision.value
                      if rec.base_decision else None,
                      "rule": rec.rule_fired, "executed": executed,
                      "explanation": rec.rule_explanation}
        return st["last"]

    @app.post("/v1/reset")
    def reset():
        st["gate"] = None
        st["lt_events"].clear()
        st["last"] = None
        return ex.reset()

    # -- SSE streams ----------------------------------------------------- #

    def _sse(gen):
        return StreamingResponse(gen, media_type="text/event-stream")

    @app.get("/v1/cluster-state")
    async def cluster_state():
        async def g():
            while True:
                yield f"data: {json.dumps(ex.cluster_state())}\n\n"
                await asyncio.sleep(1)
        return _sse(g())

    @app.get("/v1/audit")
    async def audit():
        async def g():
            seen = 0
            while True:
                rows = list(chain.entries())
                for e in rows[seen:]:
                    yield f"data: {json.dumps(e, default=str)}\n\n"
                seen = len(rows)
                await asyncio.sleep(1)
        return _sse(g())

    @app.get("/v1/lobstertrap-events")
    async def lt_events():
        async def g():
            seen = 0
            while True:
                ev = st["lt_events"]
                for e in ev[seen:]:
                    yield f"data: {json.dumps(e)}\n\n"
                seen = len(ev)
                await asyncio.sleep(1)
        return _sse(g())

    @app.get("/v1/kubectl-stream/{cmd}")
    async def kubectl_stream(cmd: str):
        if cmd not in ("policies", "pods", "curl"):
            raise HTTPException(404, "cmd ∈ policies|pods|curl")

        async def g():
            while True:
                cs = ex.cluster_state()
                sj = next(s for s in cs["sites"] if s["name"] == TARGET_SITE)
                iso = bool(sj["network_policies"])
                if cmd == "policies":
                    line = (f"{TARGET_SITE}  carapace-isolate  active"
                            if iso else "No resources found.")
                elif cmd == "pods":
                    line = "nginx-r1..r4  1/1  Running"
                else:
                    line = "--- TIMEOUT ---" if iso else "200 OK · 18ms"
                yield f"data: {json.dumps({'cmd': cmd, 'line': line})}\n\n"
                await asyncio.sleep(1)
        return _sse(g())

    return app


app = create_app()
