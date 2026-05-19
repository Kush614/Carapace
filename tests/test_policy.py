"""Two-layer policy pack (carapace/policy.py + configs/)."""

from carapace.policy import (
    ACTION_POLICY_PATH,
    LT_POLICY_PATH,
    load_action_policy,
    load_lt_policy,
    verify_action_policy_matches_engine,
)


def test_action_policy_is_in_sync_with_engine():
    ok, problems = verify_action_policy_matches_engine()
    assert ok, f"action policy drifted from engine: {problems}"


def test_action_policy_has_all_nine_rules_in_order():
    rules = load_action_policy()["action_rules"]
    assert [r["id"] for r in rules] == [f"R{i}" for i in range(1, 10)]


def test_R2_escalates_to_quarantine_on_lt_corroboration():
    r2 = next(r for r in load_action_policy()["action_rules"] if r["id"] == "R2")
    assert r2["compose"]["escalate_to"] == "QUARANTINE"


def test_lt_policy_is_valid_and_forks_veea_defaults():
    pol = load_lt_policy()
    assert pol["default_action"] == "ALLOW"
    ingress = {r["name"] for r in pol["ingress_rules"]}
    # Upstream Veea security rules preserved.
    assert {"block_prompt_injection", "block_data_exfiltration",
            "block_obfuscation_evasion"} <= ingress
    # Carapace addition present.
    assert "log_remediation_turns" in ingress
    egress = {r["name"] for r in pol["egress_rules"]}
    assert "block_credential_leak" in egress


def test_lt_policy_allows_gemini_backend_domain():
    pol = load_lt_policy()
    assert "generativelanguage.googleapis.com" in pol["network"]["allowed_domains"]


def test_policy_files_exist_where_the_binary_expects_them():
    assert LT_POLICY_PATH.exists()
    assert ACTION_POLICY_PATH.exists()
