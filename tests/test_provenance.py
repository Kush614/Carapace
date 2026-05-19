from carapace.provenance import resolve_provenance
from carapace.types import ContextChunk, TrustLevel


def _chunk(cid, trust, injection=False):
    return ContextChunk(chunk_id=cid, content="...", trust_level=trust, injection_suspected=injection)


STORE = {
    "telemetry:trusted": _chunk("telemetry:trusted", TrustLevel.TRUSTED),
    "runbook:semi": _chunk("runbook:semi", TrustLevel.SEMI_TRUSTED),
    "syslog:untrusted": _chunk("syslog:untrusted", TrustLevel.UNTRUSTED),
    "syslog:poisoned": _chunk("syslog:poisoned", TrustLevel.UNTRUSTED, injection=True),
}


def test_effective_trust_is_minimum():
    res = resolve_provenance(["telemetry:trusted", "runbook:semi"], STORE)
    assert res.effective_trust is TrustLevel.SEMI_TRUSTED
    assert res.injection_flag is False


def test_single_untrusted_source_drags_trust_down():
    res = resolve_provenance(["telemetry:trusted", "syslog:untrusted"], STORE)
    assert res.effective_trust is TrustLevel.UNTRUSTED


def test_injection_flag_is_disjunction():
    res = resolve_provenance(["telemetry:trusted", "syslog:poisoned"], STORE)
    assert res.injection_flag is True
    assert res.effective_trust is TrustLevel.UNTRUSTED


def test_unresolvable_source_fails_closed():
    res = resolve_provenance(["telemetry:trusted", "does-not-exist"], STORE)
    assert res.effective_trust is TrustLevel.UNTRUSTED
    assert res.injection_flag is True
    ghost = next(s for s in res.sources if s.id == "does-not-exist")
    assert ghost.resolved is False
    assert ghost.injection_suspected is True


def test_no_sources_cited_fails_closed():
    res = resolve_provenance([], STORE)
    assert res.effective_trust is TrustLevel.UNTRUSTED
    assert res.injection_flag is True
    assert res.sources == ()
