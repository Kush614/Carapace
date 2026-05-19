"""Exhaustive coverage of the rule matrix (spec §6.1). Each test pins the
exact rule that must fire, and verifies earlier rules do not shadow it.
"""

from carapace.decision_engine import decide, ruleset_hash
from carapace.types import (
    BlastRadius,
    Decision,
    DecisionInputs,
    IntentClass,
    TrustLevel,
)

OBS = IntentClass.OBSERVE
REC = IntentClass.RECOMMEND
REV = IntentClass.REMEDIATE_REVERSIBLE
DES = IntentClass.REMEDIATE_DESTRUCTIVE


def I(declared, detected, prov, blast, injection):
    return DecisionInputs(declared, detected, prov, blast, injection)


def test_R1_intent_mismatch_denies():
    r = decide(I(OBS, DES, TrustLevel.TRUSTED, BlastRadius.SITE, False))
    assert r.decision is Decision.DENY
    assert r.rule_fired == "R1"


def test_R2_injection_blocks_reversible_too():
    # Broader §6.1 reading: R2 covers all remediate_*, not just destructive.
    r = decide(I(REV, REV, TrustLevel.TRUSTED, BlastRadius.WORKLOAD, True))
    assert r.decision is Decision.DENY
    assert r.rule_fired == "R2"


def test_R2_injection_blocks_destructive():
    r = decide(I(DES, DES, TrustLevel.UNTRUSTED, BlastRadius.SITE, True))
    assert r.decision is Decision.DENY
    assert r.rule_fired == "R2"  # fires before R3/R4


def test_R3_untrusted_destructive_denies():
    r = decide(I(DES, DES, TrustLevel.UNTRUSTED, BlastRadius.NODE, False))
    assert r.decision is Decision.DENY
    assert r.rule_fired == "R3"  # fires before R5


def test_R4_site_radius_any_intent_reviews():
    r = decide(I(OBS, OBS, TrustLevel.UNTRUSTED, BlastRadius.REGION, False))
    assert r.decision is Decision.HUMAN_REVIEW
    assert r.rule_fired == "R4"


def test_R4_destructive_site_reviews():
    r = decide(I(DES, DES, TrustLevel.TRUSTED, BlastRadius.SITE, False))
    assert r.decision is Decision.HUMAN_REVIEW
    assert r.rule_fired == "R4"


def test_R5_destructive_node_reviews():
    r = decide(I(DES, DES, TrustLevel.TRUSTED, BlastRadius.NODE, False))
    assert r.decision is Decision.HUMAN_REVIEW
    assert r.rule_fired == "R5"


def test_R6_semi_trusted_destructive_reviews():
    r = decide(I(DES, DES, TrustLevel.SEMI_TRUSTED, BlastRadius.WORKLOAD, False))
    assert r.decision is Decision.HUMAN_REVIEW
    assert r.rule_fired == "R6"


def test_R7_reversible_trusted_allows():
    r = decide(I(REV, REV, TrustLevel.TRUSTED, BlastRadius.WORKLOAD, False))
    assert r.decision is Decision.ALLOW
    assert r.rule_fired == "R7"


def test_R7_reversible_semi_trusted_allows():
    r = decide(I(REV, REV, TrustLevel.SEMI_TRUSTED, BlastRadius.WORKLOAD, False))
    assert r.decision is Decision.ALLOW
    assert r.rule_fired == "R7"


def test_R8_observe_allows_even_with_untrusted_injected_source():
    # Reading poisoned input is safe; only *acting* on it is gated.
    r = decide(I(OBS, OBS, TrustLevel.UNTRUSTED, BlastRadius.NONE, True))
    assert r.decision is Decision.ALLOW
    assert r.rule_fired == "R8"


def test_R8_recommend_allows():
    r = decide(I(REC, REC, TrustLevel.UNTRUSTED, BlastRadius.NONE, True))
    assert r.decision is Decision.ALLOW
    assert r.rule_fired == "R8"


def test_R9_reversible_untrusted_falls_through_to_deny():
    # Not destructive (so R3 skips), untrusted (so R7 skips) -> fail-closed.
    r = decide(I(REV, REV, TrustLevel.UNTRUSTED, BlastRadius.WORKLOAD, False))
    assert r.decision is Decision.DENY
    assert r.rule_fired == "R9"


def test_ruleset_hash_is_stable_and_deterministic():
    h1 = ruleset_hash()
    h2 = ruleset_hash()
    assert h1 == h2
    assert h1.startswith("sha256:")
    assert len(h1) == len("sha256:") + 64


def test_decide_is_pure_and_deterministic():
    inp = I(DES, DES, TrustLevel.TRUSTED, BlastRadius.SITE, False)
    assert decide(inp) == decide(inp)
