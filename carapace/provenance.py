"""Resolve an envelope's cited sources to an effective trust level (spec §7.4).

Effective provenance is the *minimum* trust across every cited source. The
injection flag is the *disjunction* of every cited source's injection flag.
Any source that cannot be resolved is treated as untrusted **and**
injection-suspected — silence is not consent (spec §6.3).
"""

from __future__ import annotations

from typing import Mapping, Sequence

from .types import (
    ContextChunk,
    ProvenanceResult,
    ResolvedSource,
    TrustLevel,
    min_trust,
)


def resolve_provenance(
    source_signals: Sequence[str],
    chunk_store: Mapping[str, ContextChunk],
) -> ProvenanceResult:
    """Resolve ``source_signals`` against the tagged-context store."""
    resolved: list[ResolvedSource] = []

    for sig in source_signals:
        chunk = chunk_store.get(sig)
        if chunk is None:
            # Unresolvable citation -> fail closed.
            resolved.append(
                ResolvedSource(
                    id=sig,
                    trust=TrustLevel.UNTRUSTED,
                    injection_suspected=True,
                    resolved=False,
                )
            )
        else:
            resolved.append(
                ResolvedSource(
                    id=sig,
                    trust=chunk.trust_level,
                    injection_suspected=chunk.injection_suspected,
                    resolved=True,
                )
            )

    if not resolved:
        # No justification cited at all -> fail closed. R8 still lets benign
        # observe/recommend calls through; destructive calls hit R3.
        return ProvenanceResult(
            effective_trust=TrustLevel.UNTRUSTED,
            injection_flag=True,
            sources=(),
        )

    return ProvenanceResult(
        effective_trust=min_trust(s.trust for s in resolved),
        injection_flag=any(s.injection_suspected for s in resolved),
        sources=tuple(resolved),
    )
