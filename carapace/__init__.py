"""Carapace — the action-layer trust boundary that sits on top of Veea's
Lobster Trap conversation-layer DPI proxy.

Public API:

    from carapace import evaluate, decide, default_mock_topology  # standalone
    from carapace import compose, parse_lt_metadata               # on Lobster Trap
"""

from .blast_radius import classify_blast_radius
from .decision_engine import (
    RULESET_VERSION,
    assemble_record,
    build_inputs,
    decide,
    evaluate,
    ruleset_hash,
)
from .lobstertrap import (
    LobsterTrapSignal,
    compose,
    fold_lt_signal,
    parse_lt_metadata,
)
from .policy import (
    load_action_policy,
    load_lt_policy,
    verify_action_policy_matches_engine,
)
from .intent_classifier import classify_intent
from .provenance import resolve_provenance
from .topology import Topology, default_mock_topology
from .tool_registry import TOOLS, ToolSpec, get_spec
from .types import (
    BlastRadius,
    ClassificationError,
    ContextChunk,
    Decision,
    DecisionInputs,
    DecisionRecord,
    DecisionResult,
    IntentClass,
    IntentEnvelope,
    ProvenanceResult,
    ResolvedSource,
    TrustLevel,
    UnknownToolError,
)

__version__ = "0.1.0"

__all__ = [
    "evaluate",
    "decide",
    "compose",
    "parse_lt_metadata",
    "fold_lt_signal",
    "LobsterTrapSignal",
    "load_action_policy",
    "load_lt_policy",
    "verify_action_policy_matches_engine",
    "build_inputs",
    "assemble_record",
    "ruleset_hash",
    "RULESET_VERSION",
    "classify_intent",
    "classify_blast_radius",
    "resolve_provenance",
    "Topology",
    "default_mock_topology",
    "TOOLS",
    "ToolSpec",
    "get_spec",
    "BlastRadius",
    "ClassificationError",
    "ContextChunk",
    "Decision",
    "DecisionInputs",
    "DecisionRecord",
    "DecisionResult",
    "IntentClass",
    "IntentEnvelope",
    "ProvenanceResult",
    "ResolvedSource",
    "TrustLevel",
    "UnknownToolError",
]
