"""Carapace action-gate HTTP service (spec §10).

The enforcement boundary: the mock infrastructure executor runs a tool **only**
when presented with a valid, unexpired, single-use execution token minted by
``/v1/check``. No token, no execution.

Endpoints
---------
* ``POST /v1/context``       register a provenance-tagged context chunk (§7.1)
* ``POST /v1/check``         decide on an IntentEnvelope (+ optional Lobster
                             Trap ``_lobstertrap`` metadata) → token / review
* ``POST /v1/execute``       redeem a token; apply the mock infra effect
* ``POST /v1/review/{id}``   human approves/denies a HUMAN_REVIEW (§7.8)
* ``GET  /v1/review/{id}``   poll a pending review
* ``GET  /v1/audit``         the signed, hash-chained unified trail
* ``GET  /healthz``

Requires the optional ``api`` extra (fastapi, uvicorn, pydantic).
"""

from __future__ import annotations

import secrets
import time
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .audit import AuditChain
from .lobstertrap import compose
from .topology import Topology, default_mock_topology
from .types import ContextChunk, Decision, IntentEnvelope, TrustLevel

TOKEN_TTL_SECONDS = 5.0  # spec §10: 5 s TTL for the MVP
_REVIEW_DECISIONS = {Decision.HUMAN_REVIEW}
_BLOCKED = {Decision.DENY, Decision.QUARANTINE}


# --------------------------- wire models ----------------------------------- #


class EnvelopeIn(BaseModel):
    intent: str
    target: str = ""
    tool: str
    tool_args: dict[str, Any] = Field(default_factory=dict)
    justification: str = ""
    source_signals: list[str] = Field(default_factory=list)
    agent_confidence: float = 0.0
    estimated_blast_radius: Optional[str] = None


class CheckRequest(BaseModel):
    envelope: EnvelopeIn
    lobstertrap: Optional[dict[str, Any]] = None
    agent_id: str = "agent"


class ContextIn(BaseModel):
    chunk_id: str
    content: str = ""
    trust_level: str  # trusted | semi_trusted | untrusted
    injection_suspected: bool = False
    source_id: str = ""


class ExecuteRequest(BaseModel):
    execution_token: str
    tool: str
    tool_args: dict[str, Any] = Field(default_factory=dict)


class ReviewDecision(BaseModel):
    approve: bool
    reviewer: str
    note: str = ""


# ----------------------------- executor ------------------------------------ #


class MockExecutor:
    """In-memory edge substrate. Applies effects and tracks SLA cost (§9)."""

    def __init__(self) -> None:
        self.applied: list[dict[str, Any]] = []
        self.sla_cost_usd: float = 0.0

    def apply(self, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        # Crude blast-cost model purely for the demo's cost counter.
        cost = {
            "isolate_network_device": 47000.0,
            "network.isolate": 47000.0,
            "isolate_vlan": 8000.0,
            "quarantine_node": 3000.0,
            "throttle_power": 1500.0,
            "migrate_vm": 200.0,
            "restart_workload": 50.0,
        }.get(tool, 0.0)
        self.sla_cost_usd += cost
        effect = {"tool": tool, "args": args, "sla_cost_delta_usd": cost}
        self.applied.append(effect)
        return {"status": "applied", **effect}


# ------------------------------- app --------------------------------------- #


def _canon_args(args: dict[str, Any]) -> str:
    import json

    return json.dumps(args, sort_keys=True, separators=(",", ":"), default=str)


def create_app(
    *,
    audit_path: str | Path = "audit.ndjson",
    topology: Optional[Topology] = None,
    token_ttl: float = TOKEN_TTL_SECONDS,
) -> FastAPI:
    app = FastAPI(title="Carapace action-gate", version="0.1.0")
    # The 3D frontend is opened from file:// (origin "null"); allow it to
    # call the gate in LIVE mode. Demo posture — tighten for production.
    app.add_middleware(
        CORSMiddleware, allow_origins=["*"], allow_methods=["*"],
        allow_headers=["*"],
    )
    topo = topology or default_mock_topology()
    chain = AuditChain(audit_path)
    chunks: dict[str, ContextChunk] = {}
    tokens: dict[str, dict[str, Any]] = {}
    reviews: dict[str, dict[str, Any]] = {}
    executor = MockExecutor()

    def _mint_token(rec_audit_id: str, tool: str, args: dict[str, Any]) -> str:
        tok = "cp-tok-" + secrets.token_urlsafe(18)
        tokens[tok] = {
            "audit_id": rec_audit_id,
            "tool": tool,
            "args": _canon_args(args),
            "expires_at": time.monotonic() + token_ttl,
            "redeemed": False,
        }
        return tok

    @app.get("/healthz")
    def healthz() -> dict[str, Any]:
        ok, broken = chain.verify()
        return {"status": "ok", "audit_chain_intact": ok,
                "audit_break_at": broken, "sla_cost_usd": executor.sla_cost_usd}

    @app.post("/v1/context")
    def add_context(c: ContextIn) -> dict[str, Any]:
        chunks[c.chunk_id] = ContextChunk(
            chunk_id=c.chunk_id,
            content=c.content,
            trust_level=TrustLevel(c.trust_level),
            injection_suspected=c.injection_suspected,
            source_id=c.source_id,
        )
        return {"registered": c.chunk_id, "total": len(chunks)}

    def _do_check(req: CheckRequest):
        env = IntentEnvelope.from_dict(req.envelope.model_dump())
        rec = compose(env, chunks, topo, req.lobstertrap)
        entry = chain.append(rec)
        return env, rec, entry["audit_id"]

    @app.post("/v1/check")
    def check(req: CheckRequest) -> dict[str, Any]:
        env, rec, audit_id = _do_check(req)
        body: dict[str, Any] = {
            "decision": rec.decision.value,
            "base_decision": rec.base_decision.value if rec.base_decision else None,
            "rule_fired": rec.rule_fired,
            "rule_explanation": rec.rule_explanation,
            "audit_id": audit_id,
            "composition_notes": list(rec.composition_notes),
            "lobstertrap": rec.lobstertrap,
        }
        if rec.decision is Decision.ALLOW:
            body["execution_token"] = _mint_token(audit_id, env.tool, dict(env.tool_args))
        elif rec.decision in _REVIEW_DECISIONS:
            rid = "rev-" + secrets.token_urlsafe(10)
            reviews[rid] = {"status": "pending", "audit_id": audit_id,
                            "tool": env.tool, "tool_args": dict(env.tool_args),
                            "rule": rec.rule_fired}
            body["review_id"] = rid
            body["poll_url"] = f"/v1/review/{rid}"
        else:  # DENY / QUARANTINE
            body["user_message"] = (
                f"Action blocked ({rec.decision.value}): {rec.rule_explanation}"
            )
        return body

    @app.post("/v1/execute")
    def execute(req: ExecuteRequest) -> dict[str, Any]:
        t = tokens.get(req.execution_token)
        if t is None:
            raise HTTPException(403, "invalid execution token")
        if t["redeemed"]:
            raise HTTPException(403, "token already redeemed")
        if time.monotonic() > t["expires_at"]:
            raise HTTPException(403, "token expired")
        if t["tool"] != req.tool or t["args"] != _canon_args(req.tool_args):
            raise HTTPException(403, "token does not match tool/args")
        t["redeemed"] = True
        result = executor.apply(req.tool, req.tool_args)
        chain.append_lobstertrap(
            {"request_id": t["audit_id"], "direction": "execute",
             "action": "APPLIED", "tool": req.tool}
        )
        return {"executed": True, "audit_id": t["audit_id"], "result": result}

    @app.get("/v1/review/{review_id}")
    def get_review(review_id: str) -> dict[str, Any]:
        r = reviews.get(review_id)
        if r is None:
            raise HTTPException(404, "unknown review")
        return r

    @app.post("/v1/review/{review_id}")
    def decide_review(review_id: str, d: ReviewDecision) -> dict[str, Any]:
        r = reviews.get(review_id)
        if r is None:
            raise HTTPException(404, "unknown review")
        if r["status"] != "pending":
            raise HTTPException(409, f"review already {r['status']}")
        # Reviewer identity goes into the audit chain (spec §9 Scenario D).
        chain.append_lobstertrap(
            {"request_id": r["audit_id"], "direction": "human_review",
             "action": "APPROVE" if d.approve else "DENY",
             "reviewer": d.reviewer, "note": d.note}
        )
        if d.approve:
            r["status"] = "approved"
            r["execution_token"] = _mint_token(r["audit_id"], r["tool"], r["tool_args"])
            return {"status": "approved", "execution_token": r["execution_token"]}
        r["status"] = "denied"
        return {"status": "denied"}

    @app.get("/v1/audit")
    def get_audit(since: int = 0, limit: int = 200) -> dict[str, Any]:
        rows = [e for e in chain.entries() if e["seq"] >= since][:limit]
        ok, broken = chain.verify()
        return {"intact": ok, "break_at": broken, "count": len(rows),
                "entries": rows}

    return app


app = create_app()
