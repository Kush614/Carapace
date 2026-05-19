"""Policy-pack loading + drift verification.

Carapace ships a *two-layer* policy stack:

* ``configs/carapace_lt_policy.yaml``     — conversation layer, loaded by
  the real Veea Lobster Trap binary (the floor).
* ``configs/carapace_action_policy.yaml`` — action layer, the declarative
  mirror of the pure engine's rule matrix (the ceiling we add).

The engine (``carapace.decision_engine``) is the single source of truth.
:func:`verify_action_policy_matches_engine` proves the YAML has not
drifted from it (same rule ids, same actions, same order) — so the
policy-as-code artifact is *verified*, not rotting documentation.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .decision_engine import _RULES

# NOTE: ``yaml`` is imported lazily inside the loaders so that
# ``import carapace`` and the pure decision engine keep ZERO runtime
# dependencies. PyYAML is only needed if you actually load a policy file.

_CONFIGS = Path(__file__).resolve().parent.parent / "configs"
ACTION_POLICY_PATH = _CONFIGS / "carapace_action_policy.yaml"
LT_POLICY_PATH = _CONFIGS / "carapace_lt_policy.yaml"


def load_action_policy(path: str | Path = ACTION_POLICY_PATH) -> dict[str, Any]:
    import yaml

    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def load_lt_policy(path: str | Path = LT_POLICY_PATH) -> dict[str, Any]:
    import yaml

    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def verify_action_policy_matches_engine(
    path: str | Path = ACTION_POLICY_PATH,
) -> tuple[bool, list[str]]:
    """Return ``(ok, problems)``.

    Checks the action-policy YAML against ``decision_engine._RULES``:
    identical rule ids in identical order, identical actions, and
    descending priority. Any drift is a listed problem.
    """
    problems: list[str] = []
    pol = load_action_policy(path)
    rules = pol.get("action_rules", [])

    engine_ids = [rid for rid, _, _ in _RULES]
    engine_actions = {rid: act for rid, _, act in _RULES}

    yaml_ids = [str(r.get("id")) for r in rules]
    if yaml_ids != engine_ids:
        problems.append(
            f"rule id/order drift: yaml={yaml_ids} engine={engine_ids}"
        )

    for r in rules:
        rid = str(r.get("id"))
        want = engine_actions.get(rid)
        got = str(r.get("action"))
        if want is None:
            problems.append(f"{rid}: not in engine ruleset")
        elif got != want:
            problems.append(f"{rid}: action {got!r} != engine {want!r}")

    prios = [int(r.get("priority", -1)) for r in rules]
    if prios != sorted(prios, reverse=True):
        problems.append(f"priorities not strictly descending: {prios}")

    if str(pol.get("default_action")) != engine_actions.get("R9"):
        problems.append("default_action must equal R9's action (fail-closed)")

    return (not problems), problems
