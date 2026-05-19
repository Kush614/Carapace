"""Carapace ↔ Lobster Trap composition layer.

Veea's **Lobster Trap** (github.com/veeainc/lobstertrap) is a deep-prompt-
inspection proxy that guards the *conversation layer*: it inspects every
prompt/response between the agent and the model, and emits a bidirectional
``_lobstertrap`` metadata block (declared-vs-detected intent, risk score,
injection/exfiltration/credential flags, verdict).

**Carapace** guards the *action layer*: it gates the infrastructure tool the
agent is about to execute (provenance, blast radius, declared-vs-detected
*action* intent — the rule matrix R1–R9).

This module is the seam where Carapace sits *on top of* Lobster Trap. It:

1. parses the ``_lobstertrap`` metadata into a typed :class:`LobsterTrapSignal`;
2. **folds** that conversation-layer evidence into Carapace's
   :class:`DecisionInputs` — strictly *monotone toward caution*: Lobster Trap
   can only ever make Carapace more restrictive, never less (fail-closed
   composition);
3. composes a unified decision, escalating an injection-tainted block to
   ``QUARANTINE`` when both layers agree, so the verdict vocabulary matches
   Lobster Trap's own action set.

If no ``_lobstertrap`` metadata is present (Lobster Trap not in the path),
Carapace degrades gracefully to standalone behaviour — absence neither
tightens nor loosens the decision.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Optional

from .decision_engine import (
    RULESET_VERSION,
    assemble_record,
    build_inputs,
    decide,
)
from .topology import Topology
from .types import (
    ContextChunk,
    Decision,
    DecisionInputs,
    DecisionRecord,
    DecisionResult,
    IntentEnvelope,
    TrustLevel,
)

# Lobster Trap actions that signal it was unhappy with this turn.
_LT_BLOCKING = {"DENY", "QUARANTINE", "HUMAN_REVIEW", "RATE_LIMIT"}

# (signal attribute, human label) pairs that, if Lobster Trap raised them on
# the turn that produced this action, taint the action's justification chain.
_TAINT_SIGNALS: tuple[tuple[str, str], ...] = (
    ("injection", "prompt injection"),
    ("obfuscation", "obfuscation/evasion"),
    ("exfiltration", "data exfiltration"),
    ("credentials", "credential exposure"),
    ("role_impersonation", "role impersonation"),
    ("malware_request", "malware request"),
)


@dataclass(frozen=True, slots=True)
class LobsterTrapSignal:
    """Typed view of a ``_lobstertrap`` metadata block."""

    present: bool
    request_id: str = ""
    verdict: str = ""
    ingress_action: str = ""
    egress_action: str = ""
    intent_category: str = ""
    risk_score: float = 0.0
    injection: bool = False
    obfuscation: bool = False
    exfiltration: bool = False
    credentials: bool = False
    pii: bool = False
    role_impersonation: bool = False
    malware_request: bool = False
    mismatches: tuple[str, ...] = ()
    target_paths: tuple[str, ...] = ()
    target_domains: tuple[str, ...] = ()
    target_commands: tuple[str, ...] = ()
    raw: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "present": self.present,
            "request_id": self.request_id,
            "verdict": self.verdict,
            "ingress_action": self.ingress_action,
            "egress_action": self.egress_action,
            "intent_category": self.intent_category,
            "risk_score": self.risk_score,
            "injection": self.injection,
            "obfuscation": self.obfuscation,
            "exfiltration": self.exfiltration,
            "credentials": self.credentials,
            "pii": self.pii,
            "role_impersonation": self.role_impersonation,
            "malware_request": self.malware_request,
            "mismatches": list(self.mismatches),
            "target_paths": list(self.target_paths),
            "target_domains": list(self.target_domains),
            "target_commands": list(self.target_commands),
        }


def _as_tuple(v: Any) -> tuple[str, ...]:
    if not v:
        return ()
    if isinstance(v, (list, tuple)):
        return tuple(str(x) for x in v)
    return (str(v),)


def _any_bool(key: str, *blocks: Mapping[str, Any]) -> bool:
    """True if ``key`` is truthy in any of the detected blocks (ingress|egress)."""
    return any(bool(b.get(key)) for b in blocks if isinstance(b, Mapping))


def _parse_mismatches(raw: Any) -> tuple[str, ...]:
    """Labels of declared-vs-detected mismatches Lobster Trap considers
    actionable. ``info``-severity mismatches are ignored so benign notes
    don't force a block.
    """
    if not isinstance(raw, (list, tuple)):
        return ()
    out: list[str] = []
    for m in raw:
        if isinstance(m, Mapping):
            sev = str(m.get("severity", "")).lower()
            if sev and sev not in ("critical", "warning"):
                continue
            field_name = str(m.get("field", "?"))
            out.append(f"{field_name} ({sev or 'unspecified'})")
        elif m:
            out.append(str(m))
    return tuple(out)


def parse_lt_metadata(payload: Optional[Mapping[str, Any]]) -> LobsterTrapSignal:
    """Parse a ``_lobstertrap`` block (or a response containing one).

    Defensive: missing keys degrade to safe defaults; an absent block yields
    ``present=False`` so the decision is unaffected.
    """
    if not payload or not isinstance(payload, Mapping):
        return LobsterTrapSignal(present=False)

    if "_lobstertrap" in payload:
        lt = payload["_lobstertrap"]
    elif any(k in payload for k in ("verdict", "ingress", "egress", "request_id")):
        lt = payload  # caller passed the bare _lobstertrap block
    else:
        lt = None  # a plain response with no Lobster Trap metadata
    if not isinstance(lt, Mapping) or not lt:
        return LobsterTrapSignal(present=False)

    ingress = lt.get("ingress", {}) if isinstance(lt.get("ingress"), Mapping) else {}
    egress = lt.get("egress", {}) if isinstance(lt.get("egress"), Mapping) else {}
    det_in = ingress.get("detected", {}) if isinstance(ingress.get("detected"), Mapping) else {}
    det_eg = egress.get("detected", {}) if isinstance(egress.get("detected"), Mapping) else {}

    ingress_action = str(ingress.get("action", ""))
    egress_action = str(egress.get("action", ""))
    verdict = str(lt.get("verdict") or ingress_action or egress_action)

    # risk_score: take the worst across ingress/egress detected blocks.
    risk = 0.0
    for d in (det_in, det_eg):
        try:
            risk = max(risk, float(d.get("risk_score", 0.0) or 0.0))
        except (TypeError, ValueError):
            pass

    return LobsterTrapSignal(
        present=True,
        request_id=str(lt.get("request_id", "")),
        verdict=verdict,
        ingress_action=ingress_action,
        egress_action=egress_action,
        intent_category=str(det_in.get("intent_category", "")),
        risk_score=risk,
        injection=_any_bool("contains_injection_patterns", det_in, det_eg),
        obfuscation=_any_bool("contains_obfuscation", det_in, det_eg),
        exfiltration=_any_bool("contains_exfiltration", det_in, det_eg),
        credentials=_any_bool("contains_credentials", det_in, det_eg),
        pii=_any_bool("contains_pii", det_in, det_eg),
        role_impersonation=_any_bool("contains_role_impersonation", det_in, det_eg),
        malware_request=_any_bool("contains_malware_request", det_in, det_eg),
        mismatches=_parse_mismatches(ingress.get("mismatches") or lt.get("mismatches")),
        target_paths=_as_tuple(det_in.get("target_paths")),
        target_domains=_as_tuple(det_in.get("target_domains")),
        target_commands=_as_tuple(det_in.get("target_commands")),
        raw=dict(lt),
    )


def _downgrade(level: TrustLevel) -> TrustLevel:
    """Lower trust by exactly one notch (never below untrusted)."""
    if level == TrustLevel.TRUSTED:
        return TrustLevel.SEMI_TRUSTED
    if level == TrustLevel.SEMI_TRUSTED:
        return TrustLevel.UNTRUSTED
    return TrustLevel.UNTRUSTED


def fold_lt_signal(
    inputs: DecisionInputs,
    sig: LobsterTrapSignal,
    *,
    risk_review_threshold: float = 0.6,
    risk_untrust_threshold: float = 0.3,
) -> tuple[DecisionInputs, list[str]]:
    """Fold Lobster Trap's conversation-layer verdict into the action inputs.

    Strictly monotone toward caution: ``injection_flag`` is only ever set
    (never cleared) and ``effective_provenance`` is only ever lowered. Lobster
    Trap therefore cannot loosen a Carapace decision — only tighten it.
    """
    if not sig.present:
        return inputs, []

    notes: list[str] = []
    injection = inputs.injection_flag
    trust = inputs.effective_provenance

    taint_reasons = [
        label for attr, label in _TAINT_SIGNALS if getattr(sig, attr)
    ]
    if taint_reasons:
        injection = True
        notes.append(
            "Lobster Trap flagged this turn at the conversation layer: "
            + ", ".join(taint_reasons)
        )
    if sig.mismatches:
        injection = True
        notes.append(
            "Lobster Trap reported declared-vs-detected mismatch(es): "
            + ", ".join(sig.mismatches)
        )
    if sig.verdict.upper() in _LT_BLOCKING:
        injection = True
        notes.append(f"Lobster Trap verdict on this turn was {sig.verdict}.")

    if sig.risk_score >= risk_review_threshold:
        if trust != TrustLevel.UNTRUSTED:
            notes.append(
                f"Lobster Trap risk_score {sig.risk_score:.2f} ≥ "
                f"{risk_review_threshold}: provenance forced to untrusted."
            )
        trust = TrustLevel.UNTRUSTED
    elif sig.risk_score >= risk_untrust_threshold:
        new_trust = _downgrade(trust)
        if new_trust != trust:
            notes.append(
                f"Lobster Trap risk_score {sig.risk_score:.2f} ≥ "
                f"{risk_untrust_threshold}: provenance downgraded "
                f"{trust.value} → {new_trust.value}."
            )
        trust = new_trust

    folded = DecisionInputs(
        declared_intent=inputs.declared_intent,
        detected_intent=inputs.detected_intent,
        effective_provenance=trust,
        blast_radius=inputs.blast_radius,
        injection_flag=injection,
    )
    return folded, notes


def _maybe_escalate(
    result: DecisionResult, sig: LobsterTrapSignal
) -> DecisionResult:
    """Escalate an injection-tainted block (R2) to QUARANTINE when Lobster
    Trap independently corroborates the conversation-layer compromise.

    Defense in depth: both layers agreeing means *isolate and preserve for
    forensics*, not merely refuse.
    """
    corroborated = sig.present and (
        sig.injection
        or sig.obfuscation
        or sig.exfiltration
        or bool(sig.mismatches)
        or sig.verdict.upper() in {"DENY", "QUARANTINE"}
    )
    if result.decision is Decision.DENY and result.rule_fired == "R2" and corroborated:
        return DecisionResult(
            Decision.QUARANTINE,
            "R2",
            result.rule_explanation
            + " Escalated DENY → QUARANTINE: Lobster Trap independently "
            "flagged this turn at the conversation layer (defense in depth).",
        )
    return result


def compose(
    envelope: IntentEnvelope,
    chunk_store: Mapping[str, ContextChunk],
    topology: Topology,
    lt_payload: Optional[Mapping[str, Any]] = None,
    *,
    ruleset_version: str = RULESET_VERSION,
    audit_id: Optional[str] = None,
    risk_review_threshold: float = 0.6,
    risk_untrust_threshold: float = 0.3,
) -> DecisionRecord:
    """Carapace decision *composed with* Lobster Trap's conversation-layer verdict.

    Equivalent to :func:`carapace.evaluate` when ``lt_payload`` carries no
    ``_lobstertrap`` block.
    """
    built = build_inputs(envelope, chunk_store, topology)
    sig = parse_lt_metadata(lt_payload)

    if built.failclosed is not None:
        # Classification already failed closed; LT can't make it safer.
        return assemble_record(
            envelope,
            built,
            built.inputs,
            built.failclosed,
            ruleset_version=ruleset_version,
            audit_id=audit_id,
            lobstertrap=sig.to_dict() if sig.present else None,
            composition_notes=(),
            base_decision=built.failclosed.decision,
        )

    folded, notes = fold_lt_signal(
        built.inputs,
        sig,
        risk_review_threshold=risk_review_threshold,
        risk_untrust_threshold=risk_untrust_threshold,
    )
    base = decide(folded)
    final = _maybe_escalate(base, sig)

    return assemble_record(
        envelope,
        built,
        folded,
        final,
        ruleset_version=ruleset_version,
        audit_id=audit_id,
        lobstertrap=sig.to_dict() if sig.present else None,
        composition_notes=tuple(notes),
        base_decision=base.decision,
    )
