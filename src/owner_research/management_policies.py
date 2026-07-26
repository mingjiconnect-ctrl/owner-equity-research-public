from __future__ import annotations

from dataclasses import dataclass

POLICY_REGISTRY_VERSION = "1.0.0"


@dataclass(frozen=True, slots=True)
class EvaluationPolicy:
    policy_id: str
    target_roles: frozenset[str]
    requires_baseline: bool
    value_kind: str
    allowed_directions: frozenset[str]


POLICIES: dict[str, EvaluationPolicy] = {
    "numeric_minimum": EvaluationPolicy(
        "numeric_minimum", frozenset({"lower_bound"}), False, "numeric",
        frozenset({"higher_is_better"}),
    ),
    "numeric_maximum": EvaluationPolicy(
        "numeric_maximum", frozenset({"upper_bound"}), False, "numeric",
        frozenset({"lower_is_better"}),
    ),
    "numeric_range": EvaluationPolicy(
        "numeric_range", frozenset({"lower_bound", "upper_bound"}), False, "numeric",
        frozenset({"exact"}),
    ),
    "numeric_point": EvaluationPolicy(
        "numeric_point", frozenset({"point"}), False, "numeric",
        frozenset({"exact"}),
    ),
    "growth_minimum": EvaluationPolicy(
        "growth_minimum", frozenset({"lower_bound"}), True, "numeric",
        frozenset({"higher_is_better"}),
    ),
    "growth_range": EvaluationPolicy(
        "growth_range", frozenset({"lower_bound", "upper_bound"}), True, "numeric",
        frozenset({"exact"}),
    ),
    "cumulative_minimum": EvaluationPolicy(
        "cumulative_minimum", frozenset({"lower_bound"}), False, "numeric",
        frozenset({"higher_is_better"}),
    ),
    "milestone_by_date": EvaluationPolicy(
        "milestone_by_date", frozenset({"milestone"}), False, "boolean",
        frozenset({"not_applicable"}),
    ),
    "maintain_or_improve": EvaluationPolicy(
        "maintain_or_improve", frozenset(), True, "numeric",
        frozenset({"higher_is_better", "lower_is_better"}),
    ),
    "policy_compliance": EvaluationPolicy(
        "policy_compliance", frozenset({"milestone"}), False, "boolean",
        frozenset({"not_applicable"}),
    ),
}


def policy(policy_id: str, version: str) -> EvaluationPolicy:
    if version != POLICY_REGISTRY_VERSION:
        raise ValueError(f"unsupported management policy version: {version}")
    try:
        return POLICIES[policy_id]
    except KeyError as exc:
        raise ValueError(f"unregistered management policy: {policy_id}") from exc
