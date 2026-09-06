"""Evidence-bound four-lens Score 2.0 and OwnerScorecard 1.0.

Scoring is a downstream interpretation layer.  It reads a completed composite
valuation only to apply the published recommendation thresholds; it never changes a
Fact, Assumption, model qualification, panel value, or target price.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date
from decimal import (
    ROUND_HALF_EVEN,
    Context,
    Decimal,
    DivisionByZero,
    InvalidOperation,
    Overflow,
    localcontext,
)
from typing import Any

from .fingerprints import canonical_sha256, to_json_value
from .research_bundle_validation import GRAPH_DOMAIN_TYPES
from .valuation_synthesis_types import (
    CompositeValuationResult,
    ExtensionContract,
    NamedHumanReviewAuthority,
    OwnerScorecard,
    ScoreV2,
    _graph_fingerprint,
    _graph_object_id,
    _object_fingerprint,
    extension_decimal_in_domain,
    retained_authority_replay_scope,
)

LENS_COMPONENTS: dict[str, tuple[str, ...]] = {
    "graham": (
        "normalized_earnings",
        "balance_sheet_strength",
        "asset_protection",
        "earnings_record",
        "margin_of_safety",
    ),
    "buffett": (
        "owner_earnings",
        "moat_durability",
        "management_candor",
        "capital_allocation",
        "long_run_economics",
    ),
    "munger": (
        "incentives",
        "accounting_complexity",
        "hidden_leverage",
        "terminal_risk",
        "inversion_failure_modes",
    ),
    "duan_yongping": (
        "good_business",
        "good_culture",
        "consumer_mindshare",
        "good_price",
        "not_understandable_risks",
    ),
}

_LENS_ORDER = tuple(LENS_COMPONENTS)
_COMPONENT_FIELDS = {
    "component_id",
    "status",
    "score",
    "confidence_percent",
    "rationale",
    "evidence_bindings",
    "missing_evidence",
    "red_flags",
}
_EVIDENCE_FIELDS = {"object_type", "object_id", "fingerprint"}
_RED_FLAG_FIELDS = {"code", "severity", "rationale", "evidence_bindings"}
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_MAX_COMPONENT_SCORE = Decimal(20)
_MAX_CONFIDENCE = Decimal(100)
SCORE_CALCULATION_PRECISION = 1100


def score_calculation_context() -> Context:
    """Return the complete deterministic Decimal context for score arithmetic."""

    return Context(
        prec=SCORE_CALCULATION_PRECISION,
        rounding=ROUND_HALF_EVEN,
        Emin=-999_999,
        Emax=999_999,
        capitals=1,
        clamp=0,
        flags=[],
        traps=[InvalidOperation, DivisionByZero, Overflow],
    )


class OwnerScorecardError(ValueError):
    """A score or recommendation lacks complete, closed evidence authority."""


def _score_gap_manifest_values(
    composite: CompositeValuationResult,
    review: NamedHumanReviewAuthority,
    lens: str,
    issue_codes: tuple[str, ...],
) -> dict[str, Any]:
    reviewed = to_json_value(review.reviewed_payload)
    return {
        "schema_version": "1.0.0",
        "authority_type": "composite-score-gap-authority",
        "lens": lens,
        "issuer_id": composite.issuer_id,
        "as_of_date": composite.basis_receipt["valuation_date"],
        "composite_valuation_fingerprint": composite.fingerprint,
        "planned_review_fingerprint": review.fingerprint,
        "planned_composite_valuation_fingerprint": reviewed[
            "composite_valuation_fingerprint"
        ],
        "issue_codes": list(issue_codes),
    }


@dataclass(frozen=True, slots=True)
class CompositeScoreGapAuthority:
    """Fail-closed authority for a review that cannot score an incomplete composite."""

    schema_version: str
    authority_id: str
    lens: str
    composite_valuation: CompositeValuationResult = field(repr=False)
    planned_review: NamedHumanReviewAuthority = field(repr=False)
    issue_codes: tuple[str, ...]
    authority_fingerprint: str

    def __post_init__(self) -> None:
        if (
            self.schema_version != "1.0.0"
            or self.lens not in LENS_COMPONENTS
            or type(self.composite_valuation) is not CompositeValuationResult
            or type(self.planned_review) is not NamedHumanReviewAuthority
        ):
            raise OwnerScorecardError("score gap authority type is invalid")
        try:
            self.composite_valuation.__post_init__()
            self.planned_review.__post_init__()
        except (OSError, TypeError, ValueError) as exc:
            raise OwnerScorecardError("score gap authority does not replay") from exc
        composite = self.composite_valuation
        review = self.planned_review
        reviewed = to_json_value(review.reviewed_payload)
        run_result = composite._run_result
        if (
            review.scope != f"score:{self.lens}"
            or review.issuer_id != composite.issuer_id
            or review.data_cutoff_date != composite.basis_receipt["valuation_date"]
            or review.graph != run_result.input_receipt.graph
            or review.research_bundle not in run_result.input_receipt.graph.research_bundles
            or _graph_fingerprint(review.graph) != run_result.input_receipt.graph_fingerprint
            or not isinstance(reviewed, dict)
            or set(reviewed)
            != {"components", "composite_valuation_fingerprint"}
            or type(reviewed["composite_valuation_fingerprint"]) is not str
            or _SHA256.fullmatch(reviewed["composite_valuation_fingerprint"]) is None
        ):
            raise OwnerScorecardError("score gap authority context is invalid")
        if composite.status not in {"blocked", "contested"} or composite.recommendation_eligible:
            raise OwnerScorecardError("score gap authority requires an ineligible composite")
        expected_issue = (
            f"composite_valuation_ineligible:{self.lens}"
            if reviewed["composite_valuation_fingerprint"] == composite.fingerprint
            else f"score_review_composite_mismatch:{self.lens}"
        )
        expected_issues = (expected_issue,)
        values = self._manifest_values()
        expected_fingerprint = canonical_sha256(values)
        expected_id = (
            f"composite-score-gap:{composite.issuer_id}:{self.lens}:"
            f"{expected_fingerprint[:24]}"
        )
        if (
            self.issue_codes != expected_issues
            or self.authority_fingerprint != expected_fingerprint
            or self.authority_id != expected_id
        ):
            raise OwnerScorecardError("score gap authority identity does not replay")

    def _manifest_values(self) -> dict[str, Any]:
        return _score_gap_manifest_values(
            self.composite_valuation,
            self.planned_review,
            self.lens,
            self.issue_codes,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._manifest_values(),
            "authority_id": self.authority_id,
            "authority_fingerprint": self.authority_fingerprint,
        }

    @property
    def fingerprint(self) -> str:
        return self.authority_fingerprint

    @property
    def graph(self) -> object:
        return self.planned_review.graph

    @property
    def research_bundle(self) -> object:
        return self.planned_review.research_bundle

    @property
    def evidence_bindings(self) -> tuple[object, ...]:
        return ()


def build_composite_score_gap_authority(
    *,
    composite_valuation: CompositeValuationResult,
    planned_review: NamedHumanReviewAuthority,
) -> CompositeScoreGapAuthority:
    """Bind an incomplete composite to a typed all-Unknown score authority."""

    if (
        type(composite_valuation) is not CompositeValuationResult
        or type(planned_review) is not NamedHumanReviewAuthority
    ):
        raise OwnerScorecardError("score gap authority requires exact retained inputs")
    reviewed = to_json_value(planned_review.reviewed_payload)
    if not isinstance(reviewed, dict) or set(reviewed) != {
        "components",
        "composite_valuation_fingerprint",
    }:
        raise OwnerScorecardError("score reviewed payload fields are not closed")
    lens = planned_review.scope.removeprefix("score:")
    issue = (
        f"composite_valuation_ineligible:{lens}"
        if reviewed["composite_valuation_fingerprint"] == composite_valuation.fingerprint
        else f"score_review_composite_mismatch:{lens}"
    )
    issue_codes = (issue,)
    values = _score_gap_manifest_values(
        composite_valuation,
        planned_review,
        lens,
        issue_codes,
    )
    fingerprint = canonical_sha256(values)
    return CompositeScoreGapAuthority(
        schema_version="1.0.0",
        authority_id=(
            f"composite-score-gap:{composite_valuation.issuer_id}:{lens}:"
            f"{fingerprint[:24]}"
        ),
        lens=lens,
        composite_valuation=composite_valuation,
        planned_review=planned_review,
        issue_codes=issue_codes,
        authority_fingerprint=fingerprint,
    )


def resolve_score_review_authority(
    *,
    composite_valuation: CompositeValuationResult,
    planned_review: NamedHumanReviewAuthority,
) -> ScoreReviewAuthority:
    """Use the exact review or a typed all-Unknown authority for an ineligible composite."""

    if (
        type(composite_valuation) is not CompositeValuationResult
        or type(planned_review) is not NamedHumanReviewAuthority
    ):
        raise OwnerScorecardError("score authority resolution requires exact retained inputs")
    reviewed = to_json_value(planned_review.reviewed_payload)
    if not isinstance(reviewed, dict) or set(reviewed) != {
        "components",
        "composite_valuation_fingerprint",
    }:
        raise OwnerScorecardError("score reviewed payload fields are not closed")
    if (
        composite_valuation.status in {"blocked", "contested"}
        and not composite_valuation.recommendation_eligible
    ):
        return build_composite_score_gap_authority(
            composite_valuation=composite_valuation,
            planned_review=planned_review,
        )
    if reviewed["composite_valuation_fingerprint"] == composite_valuation.fingerprint:
        return planned_review
    raise OwnerScorecardError("score review is bound to another composite valuation")


def _decimal(value: object, label: str) -> Decimal:
    if isinstance(value, bool):
        raise OwnerScorecardError(f"{label} must be a finite decimal")
    try:
        parsed = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise OwnerScorecardError(f"{label} must be a finite decimal") from exc
    if not parsed.is_finite():
        raise OwnerScorecardError(f"{label} must be a finite decimal")
    if not extension_decimal_in_domain(parsed):
        raise OwnerScorecardError(f"{label} exceeds the bounded decimal domain")
    return parsed


def _decimal_text(value: Decimal) -> str:
    if value == 0:
        return "0"
    rendered = format(value, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return rendered


def _materially_overvalued(market: Decimal, intrinsic: Decimal) -> bool:
    """Compare market >= 115% of intrinsic without Decimal-context rounding."""

    market_numerator, market_denominator = market.as_integer_ratio()
    intrinsic_numerator, intrinsic_denominator = intrinsic.as_integer_ratio()
    return (
        20 * market_numerator * intrinsic_denominator
        >= 23 * intrinsic_numerator * market_denominator
    )


def _date(value: str, label: str) -> str:
    try:
        return date.fromisoformat(value).isoformat()
    except (TypeError, ValueError) as exc:
        raise OwnerScorecardError(f"{label} must be an ISO date") from exc


def _strings(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise OwnerScorecardError(f"{label} must be a sequence")
    supplied = tuple(value)
    if any(type(item) is not str or not item for item in supplied):
        raise OwnerScorecardError(f"{label} must contain nonempty strings")
    normalized = tuple(sorted(set(supplied)))
    return normalized


def _evidence_binding(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != _EVIDENCE_FIELDS:
        raise OwnerScorecardError("evidence binding fields are not closed")
    normalized = {field: value[field] for field in sorted(_EVIDENCE_FIELDS)}
    if (
        not isinstance(normalized["object_type"], str)
        or not normalized["object_type"]
        or not isinstance(normalized["object_id"], str)
        or not normalized["object_id"]
        or not isinstance(normalized["fingerprint"], str)
        or _SHA256.fullmatch(normalized["fingerprint"]) is None
    ):
        raise OwnerScorecardError("evidence binding identity is invalid")
    return normalized


def _evidence_bindings(value: object, *, required: bool) -> tuple[dict[str, str], ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise OwnerScorecardError("evidence bindings must be a sequence")
    normalized = tuple(_evidence_binding(item) for item in value)
    if required and not normalized:
        raise OwnerScorecardError("a complete score component requires evidence")
    identities = {
        (item["object_type"], item["object_id"], item["fingerprint"]) for item in normalized
    }
    if len(identities) != len(normalized):
        raise OwnerScorecardError("evidence binding is duplicated")
    return tuple(
        sorted(
            normalized,
            key=lambda item: (
                item["object_type"],
                item["object_id"],
                item["fingerprint"],
            ),
        )
    )


def _red_flag(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _RED_FLAG_FIELDS:
        raise OwnerScorecardError("red-flag fields are not closed")
    code = value["code"]
    severity = value["severity"]
    rationale = value["rationale"]
    if not isinstance(code, str) or not code:
        raise OwnerScorecardError("red-flag code is invalid")
    if severity not in {"warning", "critical", "permanent_loss"}:
        raise OwnerScorecardError("red-flag severity is invalid")
    if not isinstance(rationale, str) or not rationale.strip():
        raise OwnerScorecardError("red-flag rationale is required")
    return {
        "code": code,
        "severity": severity,
        "rationale": rationale,
        "evidence_bindings": _evidence_bindings(
            value["evidence_bindings"],
            required=True,
        ),
    }


def _red_flags(value: object) -> tuple[dict[str, Any], ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise OwnerScorecardError("red flags must be a sequence")
    normalized = tuple(_red_flag(item) for item in value)
    identities = {(item["code"], item["severity"]) for item in normalized}
    if len(identities) != len(normalized):
        raise OwnerScorecardError("red-flag identity is duplicated")
    return tuple(sorted(normalized, key=lambda item: (item["code"], item["severity"])))


def _component(value: object, expected_id: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _COMPONENT_FIELDS:
        raise OwnerScorecardError("score component fields are not closed")
    if value["component_id"] != expected_id:
        raise OwnerScorecardError("score component rubric identity drifted")
    status = value["status"]
    if status not in {"complete", "partial", "unknown", "blocked"}:
        raise OwnerScorecardError("score component status is invalid")
    rationale = value["rationale"]
    if not isinstance(rationale, str) or not rationale.strip():
        raise OwnerScorecardError("score component rationale is required")
    missing = _strings(value["missing_evidence"], "component missing evidence")
    bindings = _evidence_bindings(
        value["evidence_bindings"],
        required=status == "complete",
    )
    flags = _red_flags(value["red_flags"])
    score: str | None
    confidence: str | None
    if status == "complete":
        if missing:
            raise OwnerScorecardError("complete score component cannot omit evidence")
        score_value = _decimal(value["score"], "component score")
        confidence_value = _decimal(
            value["confidence_percent"],
            "component confidence",
        )
        if not 0 <= score_value <= _MAX_COMPONENT_SCORE:
            raise OwnerScorecardError("component score must be between zero and twenty")
        if not 0 <= confidence_value <= _MAX_CONFIDENCE:
            raise OwnerScorecardError("component confidence must be between zero and 100")
        score = _decimal_text(score_value)
        confidence = _decimal_text(confidence_value)
    else:
        if value["score"] is not None or value["confidence_percent"] is not None:
            raise OwnerScorecardError("incomplete evidence must not be converted to zero")
        if not missing:
            raise OwnerScorecardError("incomplete score component must identify missing evidence")
        score = None
        confidence = None
    return {
        "component_id": expected_id,
        "status": status,
        "score": score,
        "max_score": "20",
        "confidence_percent": confidence,
        "rationale": rationale,
        "evidence_bindings": bindings,
        "missing_evidence": missing,
        "red_flags": flags,
    }


def _graph_registry(graph: object) -> dict[str, tuple[str, object]]:
    registry: dict[str, tuple[str, object]] = {}
    for graph_field, object_type in GRAPH_DOMAIN_TYPES.items():
        for item in getattr(graph, graph_field):
            identifier = _graph_object_id(graph_field, item)
            if identifier in registry:
                raise OwnerScorecardError("score graph object identity is invalid")
            registry[identifier] = (object_type, item)
    return registry


ScoreReviewAuthority = NamedHumanReviewAuthority | CompositeScoreGapAuthority


def _score_gap_components(
    authority: CompositeScoreGapAuthority,
) -> tuple[dict[str, Any], ...]:
    issue = authority.issue_codes[0]
    rationale = (
        "The current composite valuation is recommendation-ineligible; "
        "this component remains Unknown even though the frozen review targets it."
        if issue.startswith("composite_valuation_ineligible:")
        else (
            "The frozen human review targets another composite valuation; "
            "this component remains Unknown for the current incomplete conclusion."
        )
    )
    return tuple(
        {
            "component_id": component_id,
            "status": "unknown",
            "score": None,
            "confidence_percent": None,
            "rationale": rationale,
            "evidence_bindings": [],
            "missing_evidence": [f"{issue}:{component_id}"],
            "red_flags": [],
        }
        for component_id in LENS_COMPONENTS[authority.lens]
    )


def _score_authority(
    composite: CompositeValuationResult,
    authority: object,
) -> tuple[ScoreReviewAuthority, str, Sequence[Mapping[str, Any]]]:
    if type(composite) is not CompositeValuationResult:
        raise OwnerScorecardError("Score 2.0 requires an exact composite valuation")
    try:
        composite.__post_init__()
    except (OSError, TypeError, ValueError) as exc:
        raise OwnerScorecardError("composite valuation does not replay") from exc
    if type(authority) is CompositeScoreGapAuthority:
        try:
            authority.__post_init__()
        except (OSError, TypeError, ValueError) as exc:
            raise OwnerScorecardError("score gap authority does not replay") from exc
        if authority.composite_valuation is not composite:
            raise OwnerScorecardError("score gap authority rebound its exact composite")
        return authority, authority.lens, _score_gap_components(authority)
    if type(authority) is not NamedHumanReviewAuthority:
        raise OwnerScorecardError("Score 2.0 requires exact named-human review authority")
    try:
        authority.__post_init__()
    except (OSError, TypeError, ValueError) as exc:
        raise OwnerScorecardError("score review authority does not replay") from exc
    if not authority.scope.startswith("score:"):
        raise OwnerScorecardError("score review authority has the wrong scope")
    lens = authority.scope.removeprefix("score:")
    run_result = composite._run_result
    if (
        lens not in LENS_COMPONENTS
        or authority.issuer_id != composite.issuer_id
        or authority.data_cutoff_date != composite.basis_receipt["valuation_date"]
        or authority.graph != run_result.input_receipt.graph
        or authority.research_bundle not in run_result.input_receipt.graph.research_bundles
        or _graph_fingerprint(authority.graph) != run_result.input_receipt.graph_fingerprint
    ):
        raise OwnerScorecardError("score review is bound to another valuation or graph")
    reviewed = to_json_value(authority.reviewed_payload)
    if not isinstance(reviewed, dict) or set(reviewed) != {
        "components",
        "composite_valuation_fingerprint",
    }:
        raise OwnerScorecardError("score reviewed payload fields are not closed")
    if reviewed["composite_valuation_fingerprint"] != composite.fingerprint:
        raise OwnerScorecardError("score review is bound to another composite valuation")
    if (
        composite.status in {"blocked", "contested"}
        and not composite.recommendation_eligible
    ):
        raise OwnerScorecardError("ineligible composite requires typed score gap authority")
    components = reviewed["components"]
    if not isinstance(components, Sequence) or isinstance(components, (str, bytes)):
        raise OwnerScorecardError("score components must be a sequence")
    return authority, lens, components


def _replay_component_bindings(
    normalized: Sequence[Mapping[str, Any]],
    authority: ScoreReviewAuthority,
) -> None:
    registry = _graph_registry(authority.graph)
    allowed = {
        (item["object_type"], item["object_id"], item["fingerprint"])
        for item in authority.evidence_bindings
    }
    used: set[tuple[str, str, str]] = set()
    for component in normalized:
        bindings = [
            *component["evidence_bindings"],
            *(
                binding
                for flag in component["red_flags"]
                for binding in flag["evidence_bindings"]
            ),
        ]
        for binding in bindings:
            identity = (
                binding["object_type"],
                binding["object_id"],
                binding["fingerprint"],
            )
            resolved = registry.get(binding["object_id"])
            if (
                identity not in allowed
                or resolved is None
                or resolved[0] != binding["object_type"]
                or _object_fingerprint(resolved[1]) != binding["fingerprint"]
            ):
                raise OwnerScorecardError("score evidence binding does not replay")
            used.add(identity)
    if used != allowed:
        raise OwnerScorecardError("score review contains unused or omitted evidence bindings")


def _score_payload(
    composite_valuation: CompositeValuationResult,
    review_authority: ScoreReviewAuthority,
) -> dict[str, Any]:
    review_authority, lens, components = _score_authority(
        composite_valuation, review_authority
    )
    if len(components) != 5:
        raise OwnerScorecardError("each owner lens requires exactly five components")
    supplied: dict[str, Mapping[str, Any]] = {}
    for raw_component in components:
        if not isinstance(raw_component, Mapping):
            raise OwnerScorecardError("score component must be an object")
        component_id = raw_component.get("component_id")
        if type(component_id) is not str or component_id in supplied:
            raise OwnerScorecardError("score component identity is duplicated or invalid")
        supplied[component_id] = raw_component
    expected = LENS_COMPONENTS[lens]
    if set(supplied) != set(expected):
        raise OwnerScorecardError("score component set differs from the fixed rubric")
    normalized = tuple(_component(supplied[item], item) for item in expected)
    _replay_component_bindings(normalized, review_authority)
    if any(item["status"] == "blocked" for item in normalized):
        status = "blocked"
    elif any(item["status"] != "complete" for item in normalized):
        status = "partial"
    else:
        status = "complete"
    if status == "complete":
        with localcontext(score_calculation_context()):
            total = sum(
                (_decimal(item["score"], "component score") for item in normalized),
                Decimal(0),
            )
            confidence = sum(
                (
                    _decimal(item["confidence_percent"], "component confidence")
                    for item in normalized
                ),
                Decimal(0),
            ) / Decimal(5)
        total_text: str | None = _decimal_text(total)
        confidence_text: str | None = _decimal_text(confidence)
    else:
        total_text = None
        confidence_text = None
    flags = tuple(flag for item in normalized for flag in item["red_flags"])
    if len({(item["code"], item["severity"]) for item in flags}) != len(flags):
        raise OwnerScorecardError("red-flag identity is duplicated across score components")
    missing = tuple(
        sorted({item for component in normalized for item in component["missing_evidence"]})
    )
    payload: dict[str, Any] = {
        "schema_version": "2.0.0",
        "extension_label": "PROJECT_EXTENSION_OWNER_SCORE_V2",
        "issuer_id": composite_valuation.issuer_id,
        "as_of_date": composite_valuation.basis_receipt["valuation_date"],
        "lens": lens,
        "status": status,
        "research_bundle_fingerprint": review_authority.research_bundle.fingerprint,
        "contract_graph_fingerprint": _graph_fingerprint(review_authority.graph),
        "review_authority_fingerprint": review_authority.fingerprint,
        "composite_valuation_fingerprint": composite_valuation.fingerprint,
        "components": normalized,
        "total_score": total_text,
        "confidence_percent": confidence_text,
        "red_flags": flags,
        "missing_evidence": missing,
    }
    payload["score_id"] = (
        f"score-v2:{composite_valuation.issuer_id}:{lens}:{canonical_sha256(payload)[:24]}"
    )
    return payload


@retained_authority_replay_scope
def build_score_v2(
    *,
    composite_valuation: CompositeValuationResult,
    review_authority: ScoreReviewAuthority,
) -> ScoreV2:
    """Build one fixed five-component lens from exact graph-bound review authority."""

    # Replay of the retained graph is part of this public operation and can perform
    # exact Decimal unit conversions before the score arithmetic is reached.  Bound
    # the whole operation so caller-owned Decimal state cannot change validation.
    with localcontext(score_calculation_context()):
        return ScoreV2(
            **_score_payload(composite_valuation, review_authority),
            _composite_authority=composite_valuation,
            _review_authority=review_authority,
        )


def _scorecard_status(
    composite: CompositeValuationResult,
    scores: Sequence[ScoreV2],
) -> tuple[str, tuple[str, ...]]:
    issues: list[str] = []
    if composite.status == "contested" or composite.contested:
        issues.append("composite_valuation_contested")
    elif composite.status == "blocked" or not composite.recommendation_eligible:
        issues.append("composite_valuation_blocked")
    for score in scores:
        if score.status != "complete":
            issues.append(f"{score.lens}_score_{score.status}")
    if (
        composite.status in {"blocked", "contested"}
        or composite.contested
        or not composite.recommendation_eligible
        or any(score.status == "blocked" for score in scores)
    ):
        return "blocked", tuple(sorted(set(issues)))
    if any(score.status != "complete" for score in scores):
        return "partial", tuple(sorted(set(issues)))
    return "complete", tuple(sorted(set(issues)))


def _recommendation(
    *,
    status: str,
    composite: CompositeValuationResult,
    overall: Decimal | None,
    confidence: Decimal | None,
    critical_flags: Sequence[Mapping[str, Any]],
) -> str:
    if (
        status != "complete"
        or composite.status != "complete"
        or not composite.recommendation_eligible
        or composite.contested
        or overall is None
        or confidence is None
        or composite.current_intrinsic_value is None
        or composite.margin_of_safety is None
        or composite.twelve_month_upside is None
    ):
        return "无法评级"
    intrinsic = _decimal(composite.current_intrinsic_value, "current intrinsic value")
    market = _decimal(composite.market_price, "market price")
    margin = _decimal(composite.margin_of_safety, "margin of safety")
    upside = _decimal(composite.twelve_month_upside, "twelve-month upside")
    permanent_loss = any(item["severity"] == "permanent_loss" for item in critical_flags)
    materially_overvalued = _materially_overvalued(market, intrinsic)
    if overall < 50 or materially_overvalued or permanent_loss:
        return "回避"
    if (
        overall >= 80
        and confidence >= 80
        and margin >= Decimal("0.25")
        and upside >= Decimal("0.20")
        and not critical_flags
    ):
        return "重点关注"
    if (
        overall >= 70
        and confidence >= 70
        and margin >= Decimal("0.15")
        and upside >= Decimal("0.10")
        and not critical_flags
    ):
        return "关注"
    return "观察"


def _score_replays(
    composite: CompositeValuationResult,
    score: ScoreV2,
) -> bool:
    try:
        score.__post_init__()
    except (KeyError, TypeError, OwnerScorecardError, ValueError):
        return False
    return score._composite_authority == composite


def _owner_scorecard_payload(
    *,
    composite_valuation: CompositeValuationResult,
    lens_scores: Sequence[ScoreV2],
) -> dict[str, Any]:

    if type(composite_valuation) is not CompositeValuationResult:
        raise OwnerScorecardError("OwnerScorecard requires an exact composite valuation")
    if not isinstance(lens_scores, Sequence) or isinstance(lens_scores, (str, bytes)):
        raise OwnerScorecardError("lens scores must be a sequence")
    if len(lens_scores) != 4 or any(type(item) is not ScoreV2 for item in lens_scores):
        raise OwnerScorecardError("OwnerScorecard requires exactly four typed lens scores")
    supplied: dict[str, ScoreV2] = {}
    for score in lens_scores:
        if score.lens in supplied:
            raise OwnerScorecardError("OwnerScorecard lens is duplicated")
        supplied[score.lens] = score
    if set(supplied) != set(_LENS_ORDER):
        raise OwnerScorecardError("OwnerScorecard requires all four registered lenses")
    scores = tuple(supplied[lens] for lens in _LENS_ORDER)
    research_fingerprints = {score.research_bundle_fingerprint for score in scores}
    if len(research_fingerprints) != 1:
        raise OwnerScorecardError("lens scores use different research bundles")
    first_bundle = scores[0]._review_authority.research_bundle
    if any(score._review_authority.research_bundle != first_bundle for score in scores[1:]):
        raise OwnerScorecardError("lens scores do not retain one exact ResearchBundle")
    expected_valuation_fingerprint = composite_valuation.fingerprint
    for score in scores:
        if (
            score.issuer_id != composite_valuation.issuer_id
            or score.as_of_date != composite_valuation.basis_receipt["valuation_date"]
            or score.composite_valuation_fingerprint != expected_valuation_fingerprint
            or not _score_replays(composite_valuation, score)
        ):
            raise OwnerScorecardError("lens score is rebound to another valuation basis")
    status, issue_codes = _scorecard_status(composite_valuation, scores)
    if status == "complete":
        totals = [_decimal(score.total_score, "lens total") for score in scores]
        confidences = [_decimal(score.confidence_percent, "lens confidence") for score in scores]
        if any(not 0 <= item <= 100 for item in totals):
            raise OwnerScorecardError("lens total is outside zero to 100")
        if any(not 0 <= item <= 100 for item in confidences):
            raise OwnerScorecardError("lens confidence is outside zero to 100")
        with localcontext(score_calculation_context()):
            overall: Decimal | None = sum(totals, Decimal(0)) / Decimal(4)
            confidence: Decimal | None = sum(confidences, Decimal(0)) / Decimal(4)
    else:
        overall = None
        confidence = None
    all_flags = [to_json_value(flag) for score in scores for flag in score.red_flags]
    critical_flags: list[dict[str, Any]] = []
    seen_flags: set[tuple[str, str, str]] = set()
    for flag in all_flags:
        if flag["severity"] not in {"critical", "permanent_loss"}:
            continue
        identity = (flag["code"], flag["severity"], canonical_sha256(flag))
        if identity not in seen_flags:
            critical_flags.append(flag)
            seen_flags.add(identity)
    critical_flags.sort(key=lambda item: (item["severity"], item["code"]))
    recommendation = _recommendation(
        status=status,
        composite=composite_valuation,
        overall=overall,
        confidence=confidence,
        critical_flags=critical_flags,
    )
    lens_rows = tuple(
        {
            "lens": score.lens,
            "score_id": score.score_id,
            "score_fingerprint": score.fingerprint,
            "status": score.status,
            "total_score": score.total_score,
            "confidence_percent": score.confidence_percent,
        }
        for score in scores
    )
    payload: dict[str, Any] = {
        "schema_version": "1.0.0",
        "extension_label": "PROJECT_EXTENSION_OWNER_SCORECARD_V1",
        "issuer_id": composite_valuation.issuer_id,
        "as_of_date": composite_valuation.basis_receipt["valuation_date"],
        "status": status,
        "research_bundle_fingerprint": next(iter(research_fingerprints)),
        "composite_valuation_fingerprint": expected_valuation_fingerprint,
        "lens_scores": lens_rows,
        "overall_score": _decimal_text(overall) if overall is not None else None,
        "confidence_percent": (_decimal_text(confidence) if confidence is not None else None),
        "recommendation": recommendation,
        "current_intrinsic_value": composite_valuation.current_intrinsic_value,
        "market_price": composite_valuation.market_price,
        "margin_of_safety": composite_valuation.margin_of_safety,
        "twelve_month_upside": composite_valuation.twelve_month_upside,
        "critical_red_flags": tuple(critical_flags),
        "issue_codes": issue_codes,
    }
    payload["scorecard_id"] = (
        f"owner-scorecard:{composite_valuation.issuer_id}:{canonical_sha256(payload)[:24]}"
    )
    return payload


@retained_authority_replay_scope
def build_owner_scorecard(
    *,
    composite_valuation: CompositeValuationResult,
    lens_scores: Sequence[ScoreV2],
) -> OwnerScorecard:
    """Aggregate four exact retained lens scores and apply fixed thresholds."""

    with localcontext(score_calculation_context()):
        scores = tuple(lens_scores)
        return OwnerScorecard(
            **_owner_scorecard_payload(
                composite_valuation=composite_valuation,
                lens_scores=scores,
            ),
            _composite_authority=composite_valuation,
            _score_authorities=scores,
        )


def _replay_extension_contract(contract: ExtensionContract) -> None:
    if type(contract) is ScoreV2:
        expected = _score_payload(
            contract._composite_authority,
            contract._review_authority,
        )
    elif type(contract) is OwnerScorecard:
        expected = _owner_scorecard_payload(
            composite_valuation=contract._composite_authority,
            lens_scores=contract._score_authorities,
        )
    else:
        raise OwnerScorecardError(
            f"{type(contract).__name__} score replay is unavailable"
        )
    if contract.to_dict() != to_json_value(expected):
        raise OwnerScorecardError(
            f"{type(contract).__name__} public projection does not replay"
        )


__all__ = (
    "CompositeScoreGapAuthority",
    "LENS_COMPONENTS",
    "OwnerScorecardError",
    "build_composite_score_gap_authority",
    "build_owner_scorecard",
    "build_score_v2",
    "resolve_score_review_authority",
)
