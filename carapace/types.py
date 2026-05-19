"""Core value types for the Carapace policy engine.

Everything here is a frozen, JSON-serializable data type or an enum. No I/O,
no side effects — these types are shared by the pure decision engine and the
classifiers, and are safe to hash, replay, and audit.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, Mapping, Optional, Sequence


# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #


class IntentClass(str, Enum):
    """The four declared/detected intent classes (spec §5.2)."""

    OBSERVE = "observe"
    RECOMMEND = "recommend"
    REMEDIATE_REVERSIBLE = "remediate_reversible"
    REMEDIATE_DESTRUCTIVE = "remediate_destructive"


#: Intents that mutate production state (used by rule R2).
REMEDIATION_INTENTS: frozenset[IntentClass] = frozenset(
    {IntentClass.REMEDIATE_REVERSIBLE, IntentClass.REMEDIATE_DESTRUCTIVE}
)


class TrustLevel(str, Enum):
    """Provenance trust levels (spec §5.3)."""

    UNTRUSTED = "untrusted"
    SEMI_TRUSTED = "semi_trusted"
    TRUSTED = "trusted"


#: Severity ordering for trust. Lower == less trustworthy. ``effective
#: provenance`` is the *minimum* over all cited sources.
TRUST_ORDER: dict[TrustLevel, int] = {
    TrustLevel.UNTRUSTED: 0,
    TrustLevel.SEMI_TRUSTED: 1,
    TrustLevel.TRUSTED: 2,
}


def min_trust(levels: Iterable[TrustLevel]) -> TrustLevel:
    """Most-untrusted level across ``levels``.

    Empty input fails closed to ``UNTRUSTED`` — silence is not consent.
    """
    return min(levels, key=lambda lvl: TRUST_ORDER[lvl], default=TrustLevel.UNTRUSTED)


class BlastRadius(str, Enum):
    """Maximum blast radius of a tool (spec §5.4)."""

    NONE = "none"
    WORKLOAD = "workload"
    NODE = "node"
    VLAN = "vlan"
    SITE = "site"
    REGION = "region"


#: Severity ordering for blast radius. Lower == smaller blast.
BLAST_ORDER: dict[BlastRadius, int] = {
    BlastRadius.NONE: 0,
    BlastRadius.WORKLOAD: 1,
    BlastRadius.NODE: 2,
    BlastRadius.VLAN: 3,
    BlastRadius.SITE: 4,
    BlastRadius.REGION: 5,
}


class Decision(str, Enum):
    """Terminal decision emitted by the engine (spec §6).

    ``ALLOW``/``HUMAN_REVIEW``/``DENY`` are produced by the pure rule matrix.
    ``QUARANTINE`` is a *composition* outcome only: when Carapace blocks an
    injection-tainted action (R2) on a turn Lobster Trap also flagged at the
    conversation layer, the unified verdict escalates DENY → QUARANTINE so the
    vocabulary matches Lobster Trap's own action set (block + preserve for
    forensic review). ``decide()`` itself never returns QUARANTINE.
    """

    ALLOW = "ALLOW"
    HUMAN_REVIEW = "HUMAN_REVIEW"
    DENY = "DENY"
    QUARANTINE = "QUARANTINE"


# --------------------------------------------------------------------------- #
# Errors — raised by classifiers/resolvers, caught by the engine (fail-closed)
# --------------------------------------------------------------------------- #


class ClassificationError(Exception):
    """A classifier or resolver could not produce an answer.

    Per spec §6.3, the engine treats any such error as a hard DENY.
    """


class UnknownToolError(ClassificationError):
    """The cited tool is not in the registry."""


# --------------------------------------------------------------------------- #
# Data types
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class ContextChunk:
    """A provenance-tagged chunk of context the agent ingested (spec §7.1)."""

    chunk_id: str
    content: str
    trust_level: TrustLevel
    injection_suspected: bool = False
    source_id: str = ""
    ingested_at: str = ""
    hash: str = ""


@dataclass(frozen=True, slots=True)
class IntentEnvelope:
    """The declared-intent envelope wrapping every tool call (spec §5.1)."""

    intent: IntentClass
    target: str
    tool: str
    tool_args: Mapping[str, Any] = field(default_factory=dict)
    justification: str = ""
    source_signals: tuple[str, ...] = ()
    agent_confidence: float = 0.0
    estimated_blast_radius: Optional[BlastRadius] = None

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "IntentEnvelope":
        ebr = d.get("estimated_blast_radius")
        return cls(
            intent=IntentClass(d["intent"]),
            target=str(d.get("target", "")),
            tool=str(d["tool"]),
            tool_args=dict(d.get("tool_args", {})),
            justification=str(d.get("justification", "")),
            source_signals=tuple(d.get("source_signals", ())),
            agent_confidence=float(d.get("agent_confidence", 0.0)),
            estimated_blast_radius=BlastRadius(ebr) if ebr else None,
        )


@dataclass(frozen=True, slots=True)
class ResolvedSource:
    """One cited source after provenance resolution."""

    id: str
    trust: TrustLevel
    injection_suspected: bool
    resolved: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "trust": self.trust.value,
            "injection_suspected": self.injection_suspected,
            "resolved": self.resolved,
        }


@dataclass(frozen=True, slots=True)
class ProvenanceResult:
    """Outcome of resolving an envelope's ``source_signals``."""

    effective_trust: TrustLevel
    injection_flag: bool
    sources: tuple[ResolvedSource, ...]


@dataclass(frozen=True, slots=True)
class DecisionInputs:
    """The five inputs the rule matrix operates on (spec §6.1).

    The decision is a *pure deterministic function* of this tuple.
    """

    declared_intent: IntentClass
    detected_intent: IntentClass
    effective_provenance: TrustLevel
    blast_radius: BlastRadius
    injection_flag: bool


@dataclass(frozen=True, slots=True)
class DecisionResult:
    """The bare decision: which rule fired and why."""

    decision: Decision
    rule_fired: str
    rule_explanation: str


@dataclass(frozen=True, slots=True)
class DecisionRecord:
    """Full, audit-ready decision record (spec §6.2)."""

    decision: Decision
    rule_fired: str
    rule_explanation: str
    declared_intent: IntentClass
    detected_intent: Optional[IntentClass]
    tool: str
    target: str
    effective_provenance: TrustLevel
    blast_radius: Optional[BlastRadius]
    injection_flag: bool
    cited_sources: tuple[ResolvedSource, ...]
    estimated_blast_radius: Optional[BlastRadius]
    agent_confidence: float
    ruleset_version: str
    ruleset_hash: str
    signed_hash: str
    audit_id: Optional[str] = None
    # Composition layer (Carapace on top of Lobster Trap). Empty when Carapace
    # runs standalone — the core engine never populates these.
    lobstertrap: Optional[dict[str, Any]] = None
    composition_notes: tuple[str, ...] = ()
    base_decision: Optional[Decision] = None  # decide() output before LT escalation

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "rule_fired": self.rule_fired,
            "rule_explanation": self.rule_explanation,
            "declared_intent": self.declared_intent.value,
            "detected_intent": self.detected_intent.value
            if self.detected_intent
            else None,
            "tool": self.tool,
            "target": self.target,
            "effective_provenance": self.effective_provenance.value,
            "blast_radius": self.blast_radius.value if self.blast_radius else None,
            "injection_flag": self.injection_flag,
            "cited_sources": [s.to_dict() for s in self.cited_sources],
            "estimated_blast_radius": self.estimated_blast_radius.value
            if self.estimated_blast_radius
            else None,
            "agent_confidence": self.agent_confidence,
            "ruleset_version": self.ruleset_version,
            "ruleset_hash": self.ruleset_hash,
            "signed_hash": self.signed_hash,
            "audit_id": self.audit_id,
            "lobstertrap": self.lobstertrap,
            "composition_notes": list(self.composition_notes),
            "base_decision": self.base_decision.value
            if self.base_decision
            else None,
        }
