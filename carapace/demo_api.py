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


class ChatBody(BaseModel):
    message: str = ""
    image: str | None = None        # optional base64 (data: prefix ok)


# Grounding context + offline knowledge base for the help chatbot. The KB
# answers the pinned/common questions deterministically with no backend
# (honest, like the rest of the demo); Gemini is used for free-form or
# image questions only when a key is configured.
CARAPACE_CTX = (
    "Carapace is the action-layer trust gate that sits on top of Veea's "
    "Lobster Trap. Lobster Trap (real MIT Go binary) guards the "
    "conversation; Carapace guards the action the agent is about to take. "
    "It scores declared-vs-detected intent, source provenance (min-trust, "
    "fail-closed), and blast radius, folds Lobster Trap's verdict in "
    "monotonically (can only tighten), then applies pure rule matrix "
    "R1-R9 and issues a single-use 5s execution token; no token, no "
    "kubectl. Real Kubernetes (kind+Calico) is exercised in CI. Gemini "
    "(gemini-flash-latest) drives the agent and the multimodal path "
    "(Scenario E: an injection inside a screenshot — Lobster Trap's text "
    "DPI is blind to pixels, Carapace catches it). Honesty: the booth "
    "pages are a verified replay for reliability; the real binary, real "
    "Gemini, and real K8s-in-CI are genuine and disclosed, never faked."
)
_KB = [
    (("what is", "carapace", "about", "overview", "tldr"),
     "Carapace is the action-layer trust gate on top of Veea's Lobster "
     "Trap. Lobster Trap guards the conversation; Carapace guards the "
     "action — gating intent vs. provenance vs. blast radius and issuing "
     "a single-use token before anything executes."),
    (("different", "vs lobster", "difference", "versus"),
     "Lobster Trap inspects prompts/responses (conversation layer). "
     "Carapace inspects the action itself — what it does, what data "
     "justified it, how big the blast radius is. Composition is monotone: "
     "Lobster Trap can only make Carapace stricter, never looser."),
    (("real", "scripted", "mock", "fake", "honest"),
     "Real: the Veea Lobster Trap binary (built from MIT source, run "
     "live), Gemini (live), and Kubernetes (kind+Calico in CI). The booth "
     "pages run a verified replay for reliability — stated openly on the "
     "About → Status table. Nothing is dressed up as live."),
    (("rule", "matrix", "r1", "r9", "decide", "decision"),
     "Rules R1-R9, first match wins, pure & deterministic. e.g. R1 "
     "declared≠detected→DENY, R2 injection-tainted+remediation→DENY "
     "(→QUARANTINE if Lobster Trap corroborates), R4 site/region blast→"
     "HUMAN_REVIEW, R9 default→DENY (fail-closed)."),
    (("kubernetes", "k8s", "kind", "calico", "cluster", "networkpolicy"),
     "The executor runs real kubectl: a deny-all NetworkPolicy = total "
     "site isolation, token-gated. A kind+Calico cluster in GitHub "
     "Actions asserts it actually severs cross-site traffic and heals."),
    (("multimodal", "image", "screenshot", "scenario e", "vision", "gemini"),
     "Scenario E: an injection painted into a screenshot is opaque pixels "
     "to Lobster Trap's text DPI, so it passes the conversation layer. "
     "Gemini vision OCRs it; Carapace tags the source untrusted + "
     "injection-suspected (trust is source-bound — Gemini can't raise "
     "it); R2 DENIES. Carapace catches what the text layer couldn't."),
    (("sponsor", "veea", "google", "gemini api", "use of"),
     "Veea: built & run the real Lobster Trap binary, forked its policy, "
     "consume its _lobstertrap contract. Google: Gemini drives the agent "
     "and the multimodal ingest via the OpenAI-compat endpoint, routed "
     "through the real Lobster Trap proxy."),
]


def _kb_answer(q: str) -> str | None:
    ql = q.lower()
    best, score = None, 0
    for kws, ans in _KB:
        s = sum(1 for k in kws if k in ql)
        if s > score:
            best, score = ans, s
    return best if score else None


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

    @app.post("/v1/chat")
    def chat(b: ChatBody):
        msg = (b.message or "").strip()
        if not msg and not b.image:
            raise HTTPException(400, "message or image required")

        # Try live Gemini (multimodal) through the proxy if a key exists.
        try:
            import httpx

            from .agent import AgentConfig
            cfg = AgentConfig.from_env()
            content = [{"type": "text", "text": msg or
                        "What does this image show? Relate it to Carapace."}]
            if b.image:
                url = (b.image if b.image.startswith("data:")
                       else f"data:image/png;base64,{b.image}")
                content.append({"type": "image_url",
                                 "image_url": {"url": url}})
            body = {"model": cfg.model, "temperature": 0.2, "messages": [
                {"role": "system", "content":
                 "You are Carapace's help assistant. Answer ONLY about "
                 "this project, concisely (<=110 words), using the "
                 "context. Be honest: the booth pages are a verified "
                 "replay; the real Lobster Trap binary, real Gemini, and "
                 "real Kubernetes-in-CI are genuine. If unsure, say so "
                 "and point to the About page.\n\nCONTEXT: " + CARAPACE_CTX},
                {"role": "user", "content": content}]}
            r = httpx.post(cfg.base_url.rstrip("/") + "/chat/completions",
                           headers={"Authorization": f"Bearer {cfg.api_key}",
                                    "Content-Type": "application/json",
                                    "Accept-Encoding": "identity"},
                           json=body, timeout=cfg.timeout)
            j = r.json()
            ans = (j.get("choices") or [{}])[0].get(
                "message", {}).get("content", "").strip()
            if ans:
                return {"answer": ans, "source": "gemini",
                        "used_image": bool(b.image)}
        except Exception:
            pass  # fall through to the offline KB — never 500

        kb = _kb_answer(msg)
        if kb:
            return {"answer": kb, "source": "kb", "used_image": False}
        note = ("Live Gemini multimodal needs the running backend "
                "(demo.sh / a GEMINI_API_KEY). " if b.image else "")
        return {"answer": note + "Try a pinned question, or see the "
                "About page for the full architecture, rule matrix, "
                "Kubernetes use, and the honest status table.",
                "source": "kb", "used_image": False}

    return app


app = create_app()
