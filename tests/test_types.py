from carapace.types import (
    BlastRadius,
    IntentClass,
    IntentEnvelope,
    TrustLevel,
    min_trust,
)


def test_min_trust_returns_most_untrusted():
    assert min_trust([TrustLevel.TRUSTED, TrustLevel.SEMI_TRUSTED]) is TrustLevel.SEMI_TRUSTED
    assert min_trust([TrustLevel.TRUSTED, TrustLevel.UNTRUSTED]) is TrustLevel.UNTRUSTED
    assert min_trust([TrustLevel.TRUSTED]) is TrustLevel.TRUSTED


def test_min_trust_empty_fails_closed():
    assert min_trust([]) is TrustLevel.UNTRUSTED


def test_enum_values_match_spec_strings():
    assert IntentClass.REMEDIATE_DESTRUCTIVE.value == "remediate_destructive"
    assert TrustLevel.SEMI_TRUSTED.value == "semi_trusted"
    assert BlastRadius.SITE.value == "site"


def test_envelope_from_dict_roundtrips_spec_example():
    env = IntentEnvelope.from_dict(
        {
            "intent": "remediate_destructive",
            "target": "spine-switch-sj-01",
            "tool": "network.isolate",
            "tool_args": {"device_id": "spine-switch-sj-01"},
            "justification": "Spine switch showing anomalous traffic per alert ALT-4471",
            "source_signals": ["syslog-ingest-3:line-4471"],
            "agent_confidence": 0.78,
            "estimated_blast_radius": "site",
        }
    )
    assert env.intent is IntentClass.REMEDIATE_DESTRUCTIVE
    assert env.estimated_blast_radius is BlastRadius.SITE
    assert env.source_signals == ("syslog-ingest-3:line-4471",)
    assert env.agent_confidence == 0.78
