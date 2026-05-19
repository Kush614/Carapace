"""The Carapace decision engine (spec §6, §7.6).

:func:`decide` is a *pure, deterministic* function of the five inputs in
:class:`DecisionInputs`. No I/O, no clocks, no randomness — the same inputs
and ruleset version always yield the same decision, so historical decisions
replay exactly.

:func:`evaluate` is the orchestrator: it runs the classifiers and the
provenance resolver, fails closed on any error (spec §6.3), then calls
:func:`decide` and assembles an audit-ready :class:`DecisionRecord`.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from .blast_radius import classify_blast_radius
from .intent_classifier import classify_intent
from .provenance import resolve_provenance
from .topology import Topology
from .types import (
    BlastRadius,
    ClassificationError,
    ContextChunk,
    Decision,
    DecisionInputs,
    DecisionRecord,
    DecisionResult,
    IntentEnvelope,
    ProvenanceResult,
    REMEDIATION_INTENTS,
    IntentClass,
    TrustLevel,
)
from typing import Mapping, Optional

RULESET_VERSION = "rs-2026-05-18-a"

# Canonical, hashable description of the rule matrix (spec §6.1). Editing a
# rule changes the hash, so replays are pinned to the exact ruleset.
_RULES: tuple[tuple[str, str, str], ...] = (
    ("R1", "detected_intent != declared_intent", "DENY"),
    ("R2", "injection_flag and detected_intent in remediate_*", "DENY"),
    ("R3", "effective_provenance == untrusted and detected == remediate_destructive", "DENY"),
    ("R4", "blast_radius in {site, region}", "HUMAN_REVIEW"),
    ("R5", "detected == remediate_destructive and blast_radius in {vlan, node}", "HUMAN_REVIEW"),
    ("R6", "effective_provenance == semi_trusted and detected == remediate_destructive", "HUMAN_REVIEW"),
    ("R7", "detected == remediate_reversible and effective_provenance != untrusted", "ALLOW"),
    ("R8", "detected_intent in {observe, recommend}", "ALLOW"),
    ("R9", "default", "DENY"),
)


def ruleset_hash() -> str:
    """Stable SHA-256 over the ruleset version + rule definitions."""
    payload = json.dumps(
        {"version": RULESET_VERSION, "rules": _RULES},
        sort_keys=True,
        separators=(",", ":"),
    )
    return "sha256:" + hashlib.sha256(payload.encode()).hexdigest()


def decide(i: DecisionInputs) -> DecisionResult:
    """Apply the rule matrix in order; first match wins (spec §6.1)."""
    # R1 — declared intent must match the intent we detect from the tool.
    if i.detected_intent != i.declared_intent:
        return DecisionResult(
            Decision.DENY,
            "R1",
            "Declared intent does not match the tool's detected intent "
            "(intent violation / scope creep).",
        )

    # R2 — an injection-suspected source cannot drive a remediation.
    # Spec §6.1 scopes R2 to all remediate_* intents (broader than the §5.5
    # prose, which says destructive); the rule matrix is authoritative and
    # the broader reading is the fail-closed one.
    if i.injection_flag and i.detected_intent in REMEDIATION_INTENTS:
        return DecisionResult(
            Decision.DENY,
            "R2",
            "Injection-suspected source cited in a remediation action.",
        )

    # R3 — untrusted provenance can never authorise a destructive action.
    if (
        i.effective_provenance == TrustLevel.UNTRUSTED
        and i.detected_intent == IntentClass.REMEDIATE_DESTRUCTIVE
    ):
        return DecisionResult(
            Decision.DENY,
            "R3",
            "Untrusted provenance for a destructive action.",
        )

    # R4 — site/region blast radius always needs a human, any intent.
    if i.blast_radius in (BlastRadius.SITE, BlastRadius.REGION):
        return DecisionResult(
            Decision.HUMAN_REVIEW,
            "R4",
            "Site/region blast radius requires human review.",
        )

    # R5 — destructive action at vlan/node scope needs a human.
    if i.detected_intent == IntentClass.REMEDIATE_DESTRUCTIVE and i.blast_radius in (
        BlastRadius.VLAN,
        BlastRadius.NODE,
    ):
        return DecisionResult(
            Decision.HUMAN_REVIEW,
            "R5",
            "Destructive action at vlan/node scope requires human review.",
        )

    # R6 — destructive action justified only by semi-trusted context.
    if (
        i.effective_provenance == TrustLevel.SEMI_TRUSTED
        and i.detected_intent == IntentClass.REMEDIATE_DESTRUCTIVE
    ):
        return DecisionResult(
            Decision.HUMAN_REVIEW,
            "R6",
            "Destructive action justified only by semi-trusted context.",
        )

    # R7 — reversible remediation backed by at least semi-trusted context.
    if (
        i.detected_intent == IntentClass.REMEDIATE_REVERSIBLE
        and i.effective_provenance != TrustLevel.UNTRUSTED
    ):
        return DecisionResult(
            Decision.ALLOW,
            "R7",
            "Reversible remediation backed by trusted/semi-trusted context.",
        )

    # R8 — read-only / advisory actions are always allowed.
    if i.detected_intent in (IntentClass.OBSERVE, IntentClass.RECOMMEND):
        return DecisionResult(
            Decision.ALLOW,
            "R8",
            "Read-only or advisory action.",
        )

    # R9 — anything not explicitly allowed is denied. Fail-closed.
    return DecisionResult(
        Decision.DENY,
        "R9",
        "Uncovered case — fail-closed default deny.",
    )


def _signed_hash(inputs: DecisionInputs, result: DecisionResult) -> str:
    """Content hash binding the inputs + outcome to the ruleset.

    True append-only signing lives in the audit layer; this is the
    deterministic content digest that layer chains over.
    """
    payload = json.dumps(
        {
            "declared_intent": inputs.declared_intent.value,
            "detected_intent": inputs.detected_intent.value,
            "effective_provenance": inputs.effective_provenance.value,
            "blast_radius": inputs.blast_radius.value,
            "injection_flag": inputs.injection_flag,
            "decision": result.decision.value,
            "rule_fired": result.rule_fired,
            "ruleset": ruleset_hash(),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return "sha256:" + hashlib.sha256(payload.encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class BuiltInputs:
    """Result of classification + provenance, before ``decide()``.

    This is the seam the composition layer hooks into: callers can fold extra
    trust signals (e.g. Lobster Trap's conversation-layer verdict) into
    ``inputs`` before deciding. ``failclosed`` is set iff a classifier raised;
    in that case ``inputs`` is the best-effort tuple used only for hashing.
    """

    inputs: DecisionInputs
    prov: ProvenanceResult
    detected: Optional[IntentClass]
    blast: Optional[BlastRadius]
    failclosed: Optional[DecisionResult]


def build_inputs(
    envelope: IntentEnvelope,
    chunk_store: Mapping[str, ContextChunk],
    topology: Topology,
) -> BuiltInputs:
    """Run provenance + classifiers; fail closed on any classifier error.

    Never raises — a :class:`ClassificationError` becomes a fail-closed DENY
    (spec §6.3), surfaced via ``BuiltInputs.failclosed``.
    """
    # Provenance never raises (it fails closed internally); classifiers can.
    prov = resolve_provenance(envelope.source_signals, chunk_store)
    detected: Optional[IntentClass] = None
    blast: Optional[BlastRadius] = None

    try:
        detected = classify_intent(envelope.tool, envelope.tool_args, topology)
        blast = classify_blast_radius(envelope.tool, envelope.tool_args, topology)
    except ClassificationError as exc:
        failclosed = DecisionResult(
            Decision.DENY, "R9", f"Fail-closed: classification error ({exc})."
        )
        inputs = DecisionInputs(
            declared_intent=envelope.intent,
            detected_intent=detected or envelope.intent,
            effective_provenance=prov.effective_trust,
            blast_radius=blast or BlastRadius.REGION,
            injection_flag=prov.injection_flag,
        )
        return BuiltInputs(inputs, prov, detected, blast, failclosed)

    inputs = DecisionInputs(
        declared_intent=envelope.intent,
        detected_intent=detected,
        effective_provenance=prov.effective_trust,
        blast_radius=blast,
        injection_flag=prov.injection_flag,
    )
    return BuiltInputs(inputs, prov, detected, blast, None)


def assemble_record(
    envelope: IntentEnvelope,
    built: BuiltInputs,
    inputs: DecisionInputs,
    result: DecisionResult,
    *,
    ruleset_version: str = RULESET_VERSION,
    audit_id: Optional[str] = None,
    lobstertrap: Optional[dict] = None,
    composition_notes: tuple[str, ...] = (),
    base_decision: Optional[Decision] = None,
) -> DecisionRecord:
    """Bind decision + inputs + provenance into an audit-ready record."""
    return DecisionRecord(
        decision=result.decision,
        rule_fired=result.rule_fired,
        rule_explanation=result.rule_explanation,
        declared_intent=envelope.intent,
        detected_intent=built.detected,
        tool=envelope.tool,
        target=envelope.target,
        effective_provenance=inputs.effective_provenance,
        blast_radius=built.blast,
        injection_flag=inputs.injection_flag,
        cited_sources=built.prov.sources,
        estimated_blast_radius=envelope.estimated_blast_radius,
        agent_confidence=envelope.agent_confidence,
        ruleset_version=ruleset_version,
        ruleset_hash=ruleset_hash(),
        signed_hash=_signed_hash(inputs, result),
        audit_id=audit_id,
        lobstertrap=lobstertrap,
        composition_notes=composition_notes,
        base_decision=base_decision,
    )


def evaluate(
    envelope: IntentEnvelope,
    chunk_store: Mapping[str, ContextChunk],
    topology: Topology,
    *,
    ruleset_version: str = RULESET_VERSION,
    audit_id: Optional[str] = None,
) -> DecisionRecord:
    """Classify, resolve provenance, decide, and build an audit record.

    Any classifier/resolver failure is converted to a fail-closed DENY
    (spec §6.3) — the engine never throws on bad input. Behaviour is
    unchanged from v0.1; this now delegates to :func:`build_inputs`.
    """
    built = build_inputs(envelope, chunk_store, topology)
    result = built.failclosed or decide(built.inputs)
    return assemble_record(
        envelope,
        built,
        built.inputs,
        result,
        ruleset_version=ruleset_version,
        audit_id=audit_id,
    )
