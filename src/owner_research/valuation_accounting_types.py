"""Immutable internal Phase 5C policy and compilation result types.

These types are intentionally not public contracts and are not exported from the
package root.  Phase 5C-0 defines their fail-closed shape without implementing any
compiler.
"""

from __future__ import annotations

import math
from dataclasses import InitVar, dataclass
from datetime import date, datetime, timedelta
from decimal import Decimal
from typing import Any

from .calculation_integrity import (
    expected_input_fingerprint,
    expected_output_fingerprint,
)
from .contracts import (
    AccountingQualityFinding,
    AccountingQualityReview,
    AnalyticalClaimCandidate,
    AnalyticalClaimReviewDecision,
    CapitalAllocationReview,
    Claim,
    FootnoteReview,
)
from .fingerprints import FrozenMap, canonical_sha256, freeze, to_json_value
from .valuation_accounting_policies import (
    ACCOUNT_AGGREGATION_LEVELS,
    ACCOUNT_CLASSIFICATION_BASES,
    ACCOUNT_CLASSIFICATION_STATUSES,
    ACCOUNT_CONCEPT_POLICIES,
    ACCOUNT_ROLES,
    ACCOUNTING_FACT_DISPOSITIONS,
    ACCOUNTING_FACT_PURPOSES,
    ACCOUNTING_FORMULA_DERIVATIONS,
    ACCOUNTING_QUALITY_CATEGORIES,
    ACCOUNTING_QUALITY_METHOD_APPLICABILITY,
    ACCOUNTING_RECONCILIATION_RELATIVE_TOLERANCE,
    BRIDGE_AGGREGATE_DERIVATIONS,
    BRIDGE_COMPILATION_STATUSES,
    BRIDGE_ROLES,
    BRIDGE_STATES,
    BRIDGE_UNRESOLVED_REASON_SEVERITY,
    COMMON_EQUITY_ALIAS_DERIVATIONS,
    COMPILATION_STATUSES,
    CROSS_CHANNEL_POLICIES,
    DILUTED_SHARE_TREATMENTS,
    ECONOMIC_CLAIM_BINDING_STATUSES,
    ECONOMIC_CLAIM_IDENTITY_KINDS,
    FORMULA_POLICIES,
    FORMULA_TERM_INCLUSION_STATUSES,
    LINEAGE_STATUSES,
    METHOD_ADJUSTMENT_CALCULATOR_POLICY,
    METHOD_ADJUSTMENT_CATEGORIES,
    METHOD_ADJUSTMENT_DISPOSITIONS,
    METHOD_SUCCESSOR_REQUIRED_ROLES,
    METHODS,
    OWNER_TRANSACTION_CONCEPTS,
    OWNER_TRANSACTION_COVERAGE_STATES,
    PERIOD_ALIGNMENT_POLICIES,
    PHASE5C_POLICY_ID,
    PHASE5C_POLICY_VERSION,
    PHASE5C_REASON_CODES,
    QUALITY_MAPPING_POLICIES,
    RECONCILIATION_STATUSES,
    ROUTING_ASSESSMENT_IDS,
    ROUTING_ASSESSMENT_REQUIRED_EVIDENCE,
    ROUTING_ASSESSMENT_STATUSES,
    SPECIALIST_ROUTES,
    SUCCESSOR_READINESS_STATUSES,
    bridge_role_policy,
    method_adjustment_category_policy,
    method_target_policy,
    phase5c_policy_sha256,
)
from .valuation_fact_mapping_policies import (
    CONCEPT_POLICIES as PHASE5B_CONCEPT_POLICIES,
)
from .valuation_fact_mapping_policies import (
    MAPPING_POLICY_ID,
    MAPPING_POLICY_VERSION,
    PINNED_FACT_LEDGER_SCHEMA_SHA256,
    calculation_policy,
    mapping_policy_sha256,
)
from .valuation_fact_mapping_policies import SOURCE_POLICIES as PHASE5B_SOURCE_POLICIES
from .valuation_fact_mapping_policies import UNIT_POLICIES as PHASE5B_UNIT_POLICIES
from .valuation_fact_mapping_types import (
    FactLedgerMappingResult,
    ValuationReadinessResult,
)
from .valuation_readiness import assess_method_readiness


def _unique(values: tuple[str, ...], label: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} must be unique")


def _sort_unique(instance: object, field_name: str, label: str) -> None:
    values = tuple(getattr(instance, field_name))
    _unique(values, label)
    object.__setattr__(instance, field_name, tuple(sorted(values)))


def _reason_codes(instance: object) -> None:
    _sort_unique(instance, "reason_codes", "reason codes")
    if not set(instance.__getattribute__("reason_codes")).issubset(PHASE5C_REASON_CODES):
        raise ValueError("unregistered Phase 5C reason code")


def _freeze_with_sorted_sequences(
    raw: Any, *, label: str, sequence_fields: tuple[str, ...]
) -> FrozenMap:
    payload = to_json_value(freeze(raw))
    if not isinstance(payload, dict):
        raise ValueError(f"{label} must be an object")
    for field_name in sequence_fields:
        values = tuple(payload[field_name])
        _unique(values, f"{label} {field_name}")
        payload[field_name] = sorted(values)
    return freeze(payload)


def _policy_identity(policy_id: str, policy_version: str, policy_sha256: str) -> None:
    if (policy_id, policy_version) != (PHASE5C_POLICY_ID, PHASE5C_POLICY_VERSION):
        raise ValueError("Phase 5C policy identity is not registered")
    if policy_sha256 != phase5c_policy_sha256():
        raise ValueError("Phase 5C policy SHA is invalid")


def _fingerprint(instance: object) -> str:
    return canonical_sha256(to_json_value(instance))


def _issuer_scope_payload(issuer_id: str) -> dict[str, Any]:
    return {
        "scope_type": "issuer_wide",
        "segment_definition_ids": [],
        "business_unit": None,
        "product_service": None,
        "geography": None,
        "customer_group": None,
        "channel": None,
    }


def _require_sha256(value: str, label: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{label} must be a lowercase SHA-256")


def _canonical_ledger_payload(raw: Any) -> FrozenMap:
    payload = to_json_value(freeze(raw))
    required = {
        "schema_version",
        "entity_id",
        "valuation_date",
        "reporting_currency",
        "sources",
        "facts",
    }
    if not isinstance(payload, dict) or set(payload) != required:
        raise ValueError("FactLedger payload does not have the fixed kernel shape")
    if payload["schema_version"] != "1.0.0":
        raise ValueError("FactLedger payload does not match the pinned Schema version")
    if not all(
        isinstance(payload[field], str) and payload[field]
        for field in ("entity_id", "valuation_date", "reporting_currency")
    ):
        raise ValueError("FactLedger identity and reporting currency are required")
    _parse_iso_date(payload["valuation_date"], "FactLedger valuation_date")
    if not _is_iso_currency(payload["reporting_currency"]):
        raise ValueError("FactLedger reporting currency is invalid")
    sources: list[dict[str, Any]] = []
    for raw_source in payload["sources"]:
        required_source_fields = {
            "source_id",
            "title",
            "publisher",
            "published_date",
            "retrieved_at",
            "locator",
            "primary",
        }
        permitted_source_fields = required_source_fields | {"url", "local_path"}
        if (
            not isinstance(raw_source, dict)
            or not required_source_fields.issubset(raw_source)
            or not set(raw_source).issubset(permitted_source_fields)
            or not all(
                isinstance(raw_source.get(field), str) and raw_source[field]
                for field in (
                    "source_id",
                    "title",
                    "publisher",
                    "published_date",
                    "retrieved_at",
                    "locator",
                )
            )
            or not isinstance(raw_source.get("primary"), bool)
        ):
            raise ValueError("FactLedger source identity is required")
        _parse_iso_date(raw_source["published_date"], "FactLedger source published_date")
        try:
            retrieved = datetime.fromisoformat(raw_source["retrieved_at"].replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("FactLedger source retrieved_at is invalid") from exc
        if retrieved.tzinfo is None:
            raise ValueError("FactLedger source retrieved_at requires a timezone")
        for locator_field in ("url", "local_path"):
            value = raw_source.get(locator_field)
            if value is not None and (not isinstance(value, str) or not value):
                raise ValueError("FactLedger source locator field is invalid")
        if not any(raw_source.get(field) for field in ("url", "local_path")):
            raise ValueError("FactLedger source requires URL or local path")
        sources.append(raw_source)
    _unique(tuple(item["source_id"] for item in sources), "FactLedger source IDs")
    facts: list[dict[str, Any]] = []
    for raw_fact in payload["facts"]:
        required_fact_fields = {
            "fact_id",
            "concept",
            "value",
            "unit",
            "category",
            "source_id",
            "source_location",
            "as_of_date",
            "confidence",
            "raw",
            "parent_fact_ids",
            "derivation",
            "equity_bridge_role",
        }
        permitted_fact_fields = required_fact_fields | {
            "currency",
            "period_start",
            "period_end",
        }
        if (
            not isinstance(raw_fact, dict)
            or not required_fact_fields.issubset(raw_fact)
            or not set(raw_fact).issubset(permitted_fact_fields)
            or not all(
                isinstance(raw_fact.get(field), str) and raw_fact[field]
                for field in (
                    "fact_id",
                    "concept",
                    "unit",
                    "source_id",
                    "source_location",
                    "as_of_date",
                )
            )
            or isinstance(raw_fact.get("value"), bool)
            or not isinstance(raw_fact.get("value"), (int, float))
            or not math.isfinite(float(raw_fact["value"]))
        ):
            raise ValueError("FactLedger Fact identity is required")
        item = dict(raw_fact)
        if item["category"] not in {
            "operating",
            "financing",
            "nonoperating",
            "market_price",
            "market_reference",
            "share_count",
            "accounting",
            "evidence",
        }:
            raise ValueError("FactLedger Fact category is invalid")
        _parse_iso_date(item["as_of_date"], "FactLedger Fact as_of_date")
        for field in ("period_start", "period_end"):
            value = item.get(field)
            if value is not None:
                if not isinstance(value, str):
                    raise ValueError("FactLedger Fact period is invalid")
                _parse_iso_date(value, f"FactLedger Fact {field}")
        if (
            item.get("period_start") is not None
            and item.get("period_end") is not None
            and _parse_iso_date(item["period_start"], "FactLedger Fact period_start")
            > _parse_iso_date(item["period_end"], "FactLedger Fact period_end")
        ):
            raise ValueError("FactLedger Fact period is inverted")
        if item.get("period_end") is not None and _parse_iso_date(
            item["period_end"], "FactLedger Fact period_end"
        ) > _parse_iso_date(item["as_of_date"], "FactLedger Fact as_of_date"):
            raise ValueError("FactLedger Fact period ends after its as-of date")
        currency = item.get("currency")
        if currency is not None and not _is_iso_currency(currency):
            raise ValueError("FactLedger Fact currency is invalid")
        if currency is not None and currency != payload["reporting_currency"]:
            raise ValueError("FactLedger Fact currency conflicts with reporting currency")
        if item["confidence"] not in {"high", "medium"}:
            raise ValueError("Phase 5C requires high- or medium-confidence Facts")
        if not isinstance(item["raw"], bool):
            raise ValueError("FactLedger Fact raw flag is invalid")
        if not isinstance(item["parent_fact_ids"], list):
            raise ValueError("FactLedger Fact parents must be an array")
        parents = tuple(item["parent_fact_ids"])
        if any(not isinstance(parent, str) or not parent for parent in parents):
            raise ValueError("FactLedger Fact parent identity is invalid")
        _unique(parents, f"FactLedger parents for {item['fact_id']}")
        item["parent_fact_ids"] = sorted(parents)
        derivation = item["derivation"]
        if derivation is not None and (not isinstance(derivation, str) or not derivation):
            raise ValueError("FactLedger Fact derivation is invalid")
        if item["raw"] and (parents or derivation is not None):
            raise ValueError("raw FactLedger Fact cannot have derivation lineage")
        if not item["raw"] and (not parents or derivation is None):
            raise ValueError("derived FactLedger Fact requires derivation lineage")
        if item["equity_bridge_role"] not in {None, *BRIDGE_ROLES}:
            raise ValueError("FactLedger Fact bridge role is invalid")
        if item["equity_bridge_role"] is not None:
            concept_policy = ACCOUNT_CONCEPT_POLICIES.get(item["concept"])
            if (
                item["category"] not in {"financing", "nonoperating"}
                or concept_policy is None
                or concept_policy.bridge_role != item["equity_bridge_role"]
            ):
                raise ValueError(
                    "FactLedger equity-bridge role conflicts with category or concept policy"
                )
        facts.append(item)
    _unique(tuple(item["fact_id"] for item in facts), "FactLedger Fact IDs")
    if not sources or not facts:
        raise ValueError("FactLedger payload requires a nonempty ledger with sources and facts")
    source_ids = {item["source_id"] for item in sources}
    if any(item["primary"] is not True for item in sources):
        raise ValueError("Phase 5C FactLedger sources must be formal primary evidence")
    if any(item.get("source_id") not in source_ids for item in facts):
        raise ValueError("FactLedger Fact source is absent from the source registry")
    if any(item.get("category") in {"market_price", "market_reference"} for item in facts):
        raise ValueError("Phase 5C FactLedger payload must remain price-blind")
    for item in facts:
        _validate_registered_fact_semantics(item, payload["reporting_currency"])
    fact_map = {item["fact_id"]: item for item in facts}
    for fact_id in fact_map:
        _ultimate_raw_roots(fact_id, fact_map)
    payload["sources"] = sorted(sources, key=lambda item: item["source_id"])
    payload["facts"] = sorted(facts, key=lambda item: item["fact_id"])
    return freeze(payload)


def _parse_iso_date(value: str, label: str) -> date:
    try:
        parsed = date.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} is invalid") from exc
    if parsed.isoformat() != value:
        raise ValueError(f"{label} is invalid")
    return parsed


def _is_iso_currency(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 3
        and value.isascii()
        and value.isalpha()
        and value.isupper()
    )


def _validate_registered_fact_semantics(fact: dict[str, Any], reporting_currency: str) -> None:
    policy = ACCOUNT_CONCEPT_POLICIES.get(fact.get("concept"))
    if policy is None:
        phase5b_policy = PHASE5B_CONCEPT_POLICIES.get(fact.get("concept"))
        if phase5b_policy is None:
            raise ValueError("Phase 5C FactLedger concept is not registered")
        origin = "raw" if fact["raw"] else "derived"
        if (
            fact["category"] != phase5b_policy.category
            or origin not in phase5b_policy.permitted_origins
        ):
            raise ValueError("FactLedger Fact does not match its Phase 5B concept semantics")
        start = fact.get("period_start")
        end = fact.get("period_end")
        as_of = fact.get("as_of_date")
        if (
            phase5b_policy.period_kind == "stock"
            and not (start is None and end == as_of and end is not None)
        ) or (
            phase5b_policy.period_kind == "flow"
            and not (start is not None and end == as_of and end is not None and start <= end)
        ):
            raise ValueError("FactLedger Fact period does not match its Phase 5B concept")
        if phase5b_policy.unit_family == "currency":
            if (
                fact.get("currency") != reporting_currency
                or fact.get("unit") != f"{reporting_currency} millions"
            ):
                raise ValueError("FactLedger monetary Fact unit semantics are invalid")
        elif phase5b_policy.unit_family == "shares":
            if fact.get("currency") is not None or fact.get("unit") != "millions shares":
                raise ValueError("FactLedger share Fact unit semantics are invalid")
        elif phase5b_policy.unit_family == "ratio" and (
            fact.get("currency") is not None or fact.get("unit") != "decimal"
        ):
            raise ValueError("FactLedger ratio Fact unit semantics are invalid")
        return
    origin = "raw" if fact["raw"] else "derived"
    if fact["category"] != policy.kernel_category or origin not in policy.permitted_origins:
        raise ValueError("FactLedger Fact does not match its registered concept semantics")
    start = fact.get("period_start")
    end = fact.get("period_end")
    as_of = fact.get("as_of_date")
    stock_shape = start is None and end == as_of and end is not None
    flow_shape = start is not None and end == as_of and end is not None and start <= end
    if (
        (policy.period_kind == "stock" and not stock_shape)
        or (policy.period_kind == "flow" and not flow_shape)
        or (policy.period_kind == "stock_or_flow" and not (stock_shape or flow_shape))
    ):
        raise ValueError("FactLedger Fact period does not match its registered concept")
    if policy.kernel_category == "share_count":
        if fact.get("currency") is not None or fact.get("unit") != "millions shares":
            raise ValueError("FactLedger share Fact unit semantics are invalid")
    elif (
        fact.get("currency") != reporting_currency
        or fact.get("unit") != f"{reporting_currency} millions"
    ):
        raise ValueError("FactLedger monetary Fact unit semantics are invalid")


def _ledger_fact_map(ledger_payload: FrozenMap) -> dict[str, FrozenMap]:
    return {item["fact_id"]: item for item in ledger_payload["facts"]}


def _validate_ledger_identity(
    ledger_payload: FrozenMap, *, issuer_id: str, data_cutoff_date: str
) -> None:
    if ledger_payload["entity_id"] != issuer_id:
        raise ValueError("FactLedger issuer conflicts with the compilation result")
    if ledger_payload["valuation_date"] != data_cutoff_date:
        raise ValueError("FactLedger valuation date conflicts with the compilation cutoff")
    cutoff = _parse_iso_date(data_cutoff_date, "compilation cutoff")
    if any(
        _parse_iso_date(item["published_date"], "FactLedger source published_date") > cutoff
        for item in ledger_payload["sources"]
    ):
        raise ValueError("FactLedger source was published after the compilation cutoff")
    if any(
        _parse_iso_date(item["as_of_date"], "FactLedger Fact as_of_date") > cutoff
        or (
            item.get("period_end") is not None
            and _parse_iso_date(item["period_end"], "FactLedger Fact period_end") > cutoff
        )
        for item in ledger_payload["facts"]
    ):
        raise ValueError("FactLedger contains future measurement evidence")


def _require_ledger_facts(
    fact_ids: tuple[str, ...] | list[str] | set[str],
    ledger_facts: dict[str, FrozenMap],
    label: str,
) -> None:
    missing = set(fact_ids).difference(ledger_facts)
    if missing:
        raise ValueError(f"{label} references Facts absent from the FactLedger")


def _ultimate_raw_roots(
    fact_id: str,
    ledger_facts: dict[str, FrozenMap],
    *,
    stack: tuple[str, ...] = (),
) -> frozenset[str]:
    if fact_id in stack:
        raise ValueError("FactLedger lineage contains a cycle")
    fact = ledger_facts.get(fact_id)
    if fact is None:
        raise ValueError("FactLedger lineage references an absent parent")
    parents = tuple(fact.get("parent_fact_ids", ()))
    if fact.get("raw") is True:
        if parents or fact.get("derivation") is not None:
            raise ValueError("raw Fact cannot retain derived lineage")
        return frozenset({fact_id})
    if fact.get("raw") is not False or not parents or not fact.get("derivation"):
        raise ValueError("derived Fact requires complete replayable lineage")
    roots: set[str] = set()
    for parent_id in parents:
        roots.update(
            _ultimate_raw_roots(
                parent_id,
                ledger_facts,
                stack=(*stack, fact_id),
            )
        )
    return frozenset(roots)


def _replayed_raw_roots(
    fact_ids: tuple[str, ...] | list[str] | set[str],
    ledger_facts: dict[str, FrozenMap],
) -> frozenset[str]:
    roots: set[str] = set()
    for fact_id in fact_ids:
        roots.update(_ultimate_raw_roots(fact_id, ledger_facts))
    return frozenset(roots)


def _closed_formula_term_bindings(
    purpose: str,
    disposition: str,
    raw: Any,
) -> tuple[FrozenMap, ...]:
    policy = FORMULA_POLICIES[purpose]
    required = {
        "input_role",
        "fact_ids",
        "inclusion_status",
        "claim_id",
        "review_decision_id",
        "missing_evidence",
        "reason_codes",
    }
    by_role: dict[str, FrozenMap] = {}
    for raw_binding in raw:
        item = _freeze_with_sorted_sequences(
            raw_binding,
            label="formula term binding",
            sequence_fields=("fact_ids", "missing_evidence", "reason_codes"),
        )
        if set(item) != required or not item["input_role"]:
            raise ValueError("formula term binding has invalid fields")
        if item["input_role"] in by_role:
            raise ValueError("formula term bindings must have unique roles")
        if item["inclusion_status"] not in FORMULA_TERM_INCLUSION_STATUSES:
            raise ValueError("formula term inclusion status is not registered")
        if not set(item["reason_codes"]).issubset(PHASE5C_REASON_CODES):
            raise ValueError("formula term binding uses an unregistered reason")
        by_role[item["input_role"]] = item
    term_by_role = {term.input_role: term for term in policy.terms}
    if set(by_role) != set(term_by_role):
        raise ValueError("formula term bindings must cover every registered term")
    all_fact_ids: list[str] = []
    normalized: list[FrozenMap] = []
    for term in policy.terms:
        item = by_role[term.input_role]
        fact_ids = tuple(item["fact_ids"])
        all_fact_ids.extend(fact_ids)
        if item["inclusion_status"] == "unresolved":
            if (
                disposition != "blocked"
                or item["claim_id"] is not None
                or item["review_decision_id"] is not None
                or not item["missing_evidence"]
                or not item["reason_codes"]
            ):
                raise ValueError("unresolved formula term requires a blocked evidence gap")
            normalized.append(item)
            continue
        if item["missing_evidence"] or item["reason_codes"]:
            raise ValueError("resolved formula term cannot retain evidence gaps")
        if term.required_inclusion_status == "not_required":
            if (
                item["inclusion_status"] != "not_required"
                or item["claim_id"] is not None
                or item["review_decision_id"] is not None
            ):
                raise ValueError("ordinary formula term cannot claim inclusion review")
        else:
            expected_status = (
                term.required_inclusion_status if fact_ids else "none_identified_after_review"
            )
            if item["inclusion_status"] != expected_status or not all(
                (item["claim_id"], item["review_decision_id"])
            ):
                raise ValueError("non-common formula term requires reviewed inclusion proof")
        normalized.append(item)
    _unique(tuple(all_fact_ids), "formula term Facts")
    return tuple(normalized)


@dataclass(frozen=True, slots=True)
class AccountClassificationDecision:
    fact_id: str
    concept: str
    status: str
    account_role: str
    classification_basis: str
    classification_claim_id: str | None
    review_decision_id: str | None
    aggregation_set_id: str | None
    aggregation_level: str | None
    root_fact_ids: tuple[str, ...]
    reason_codes: tuple[str, ...]
    rationale: str
    perimeter_disposition: FrozenMap | None = None

    def __post_init__(self) -> None:
        if not self.fact_id or not self.concept or not self.rationale.strip():
            raise ValueError("account classification identity and rationale are required")
        if self.status not in ACCOUNT_CLASSIFICATION_STATUSES:
            raise ValueError("account classification status is not registered")
        if self.account_role not in ACCOUNT_ROLES:
            raise ValueError("account role is not registered")
        if self.classification_basis not in ACCOUNT_CLASSIFICATION_BASES:
            raise ValueError("account classification basis is not registered")
        if self.aggregation_level not in {None, *ACCOUNT_AGGREGATION_LEVELS}:
            raise ValueError("account aggregation level is not registered")
        policy = ACCOUNT_CONCEPT_POLICIES.get(self.concept)
        if policy is None:
            raise ValueError("account classification concept is not registered")
        _sort_unique(self, "root_fact_ids", "account classification roots")
        _reason_codes(self)
        perimeter_concepts = {
            "noncontrolling_interest",
            "preferred_stock",
            "other_non_common_equity_claim",
        }
        if self.concept in perimeter_concepts:
            perimeter = freeze(self.perimeter_disposition)
            if set(perimeter) != {
                "total_equity",
                "reported_liabilities",
                "financial_obligations",
            } or not set(perimeter.values()).issubset({"included", "excluded", "unresolved"}):
                raise ValueError("non-common claim perimeter disposition is invalid")
            if self.status == "classified" and "unresolved" in set(perimeter.values()):
                raise ValueError("classified non-common claim requires resolved perimeter")
            if self.status == "blocked" and set(perimeter.values()) != {"unresolved"}:
                raise ValueError("blocked non-common claim perimeter must remain unresolved")
            object.__setattr__(self, "perimeter_disposition", perimeter)
        elif self.perimeter_disposition is not None:
            raise ValueError("ordinary account classification cannot carry perimeter disposition")
        if self.status == "classified":
            if self.account_role == "unresolved" or self.classification_basis == "unresolved":
                raise ValueError("classified account cannot retain unresolved semantics")
            if not self.root_fact_ids:
                raise ValueError("classified account requires root Facts")
            if self.reason_codes:
                raise ValueError("classified account cannot retain blocking reasons")
            if self.account_role not in policy.classification_roles:
                raise ValueError("account role does not match its registered concept policy")
            required_basis = (
                "reviewed_claim" if policy.classification_requires_review else "registered_concept"
            )
            if self.classification_basis != required_basis:
                raise ValueError("account classification basis does not match concept policy")
            aggregating_roles = {
                "operating_asset",
                "operating_liability",
                "financial_asset",
                "financial_obligation",
            }
            if self.account_role in aggregating_roles:
                aggregate_concepts = {
                    "operating_asset": "operating_assets",
                    "operating_liability": "operating_liabilities",
                    "financial_asset": "financial_assets",
                    "financial_obligation": "financial_obligations",
                }
                expected_level = (
                    "aggregate"
                    if self.concept == aggregate_concepts[self.account_role]
                    else "component"
                )
                if self.aggregation_level != expected_level or not self.aggregation_set_id:
                    raise ValueError("classified account aggregation semantics are incomplete")
            elif self.aggregation_level != "not_applicable" or self.aggregation_set_id is not None:
                raise ValueError("non-aggregating account classification must be not-applicable")
        else:
            if self.account_role != "unresolved" or self.classification_basis != "unresolved":
                raise ValueError("blocked account must remain unresolved")
            if not self.reason_codes:
                raise ValueError("blocked account requires a reason")
            if self.aggregation_level is not None or self.aggregation_set_id is not None:
                raise ValueError("blocked account cannot assert aggregation semantics")
        if self.classification_basis == "reviewed_claim":
            if not self.classification_claim_id or not self.review_decision_id:
                raise ValueError("reviewed account classification requires Claim and Decision")
        elif self.classification_claim_id is not None or self.review_decision_id is not None:
            raise ValueError("non-reviewed classification cannot cite Claim or Decision")

    @property
    def fingerprint(self) -> str:
        return _fingerprint(self)


@dataclass(frozen=True, slots=True)
class AccountingFactDecision:
    purpose: str
    disposition: str
    output_fact_id: str | None
    calculation_id: str | None
    input_fact_ids: tuple[str, ...]
    root_fact_ids: tuple[str, ...]
    term_bindings: tuple[FrozenMap, ...]
    lineage_status: str
    reason_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.purpose not in ACCOUNTING_FACT_PURPOSES:
            raise ValueError("accounting Fact purpose is not registered")
        if self.disposition not in ACCOUNTING_FACT_DISPOSITIONS:
            raise ValueError("accounting Fact disposition is not registered")
        if self.lineage_status not in LINEAGE_STATUSES:
            raise ValueError("accounting Fact lineage status is not registered")
        for field_name in ("input_fact_ids", "root_fact_ids"):
            _sort_unique(self, field_name, f"accounting Fact {field_name}")
        term_bindings = _closed_formula_term_bindings(
            self.purpose,
            self.disposition,
            self.term_bindings,
        )
        object.__setattr__(self, "term_bindings", term_bindings)
        bound_fact_ids = {fact_id for item in term_bindings for fact_id in item["fact_ids"]}
        if bound_fact_ids != set(self.input_fact_ids):
            raise ValueError("formula term bindings do not match accounting inputs")
        _reason_codes(self)
        if self.disposition == "emitted":
            if not all(
                (
                    self.output_fact_id,
                    self.calculation_id,
                    self.input_fact_ids,
                    self.root_fact_ids,
                )
            ):
                raise ValueError(
                    "emitted accounting Fact requires output, calculation, and lineage"
                )
            if self.lineage_status == "not_applicable":
                raise ValueError("emitted accounting Fact requires lineage")
            if self.reason_codes:
                raise ValueError("emitted accounting Fact cannot retain blocking reasons")
        else:
            if self.output_fact_id is not None or self.calculation_id is not None:
                raise ValueError("non-emitted accounting Fact cannot expose output identity")
            if self.disposition == "blocked" and not self.reason_codes:
                raise ValueError("blocked accounting Fact requires a reason")

    @property
    def fingerprint(self) -> str:
        return _fingerprint(self)


def _closed_owner_transaction_coverage(raw: Any) -> FrozenMap:
    coverage = freeze(raw)
    if set(coverage) != set(OWNER_TRANSACTION_CONCEPTS):
        raise ValueError("owner-transaction coverage must contain every registered component")
    normalized: dict[str, FrozenMap] = {}
    fact_ids: list[str] = []
    required = {
        "status",
        "fact_id",
        "claim_id",
        "review_decision_id",
        "missing_evidence",
        "reason_codes",
    }
    for concept in OWNER_TRANSACTION_CONCEPTS:
        item = _freeze_with_sorted_sequences(
            coverage[concept],
            label=f"owner transaction {concept}",
            sequence_fields=("missing_evidence", "reason_codes"),
        )
        if set(item) != required or item["status"] not in OWNER_TRANSACTION_COVERAGE_STATES:
            raise ValueError(f"owner transaction {concept} coverage is invalid")
        if not set(item["reason_codes"]).issubset(PHASE5C_REASON_CODES):
            raise ValueError("owner transaction coverage uses an unregistered reason")
        if item["status"] in {"observed", "official_zero"}:
            if not item["fact_id"] or item["claim_id"] or item["review_decision_id"]:
                raise ValueError("observed owner transaction coverage requires only numeric Fact")
            if item["missing_evidence"] or item["reason_codes"]:
                raise ValueError("closed owner transaction coverage cannot retain gaps")
        elif item["status"] == "not_applicable":
            if not all((item["fact_id"], item["claim_id"], item["review_decision_id"])):
                raise ValueError(
                    "not-applicable owner transaction requires Fact, Claim, and Decision"
                )
            if item["missing_evidence"] or item["reason_codes"]:
                raise ValueError("not-applicable owner transaction cannot retain gaps")
        else:
            if (
                item["fact_id"] is not None
                or not item["missing_evidence"]
                or not item["reason_codes"]
            ):
                raise ValueError("blocked owner transaction requires missing evidence and reason")
        if item["fact_id"]:
            fact_ids.append(item["fact_id"])
        normalized[concept] = item
    _unique(tuple(fact_ids), "owner transaction Facts")
    return freeze(normalized)


def _closed_check(raw: Any, label: str) -> FrozenMap:
    required = {
        "status",
        "role_fact_ids",
        "fact_ids",
        "root_fact_ids",
        "measurement_period",
        "stock_measurement_dates",
        "stock_root_fact_ids",
        "currency",
        "unit",
        "common_equity_perimeter_id",
        "difference",
        "tolerance",
        "reason_codes",
    }
    item = _freeze_with_sorted_sequences(
        raw,
        label=label,
        sequence_fields=("fact_ids", "root_fact_ids", "reason_codes"),
    )
    if set(item) != required:
        raise ValueError(f"{label} has invalid fields")
    if item["status"] not in RECONCILIATION_STATUSES:
        raise ValueError(f"{label} has an invalid status")
    if not set(item["reason_codes"]).issubset(PHASE5C_REASON_CODES):
        raise ValueError(f"{label} uses an unregistered reason code")
    if not item["fact_ids"] or not item["root_fact_ids"]:
        raise ValueError(f"{label} requires Facts and root lineage")
    period = item["measurement_period"]
    if set(period) != {"start", "end"} or not period["end"]:
        raise ValueError(f"{label} measurement period is invalid")
    try:
        period_end = date.fromisoformat(period["end"])
        period_start = date.fromisoformat(period["start"]) if period["start"] else None
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} measurement period is invalid") from exc
    if period_start is not None and period_start > period_end:
        raise ValueError(f"{label} measurement period is reversed")
    policy = PERIOD_ALIGNMENT_POLICIES[label]
    role_fact_ids = item["role_fact_ids"]
    required_roles = {*policy.stock_roles, *policy.flow_roles}
    if set(role_fact_ids) != required_roles or any(
        value is not None and (not isinstance(value, str) or not value)
        for value in role_fact_ids.values()
    ):
        raise ValueError(f"{label} role-Fact coverage is invalid")
    present_role_fact_ids = tuple(value for value in role_fact_ids.values() if value is not None)
    _unique(present_role_fact_ids, f"{label} role Facts")
    if set(item["fact_ids"]) != set(present_role_fact_ids):
        raise ValueError(f"{label} fact_ids do not replay role bindings")
    stock_dates = item["stock_measurement_dates"]
    if set(stock_dates) != set(policy.stock_roles):
        raise ValueError(f"{label} stock-date coverage is incomplete")
    stock_roots = item["stock_root_fact_ids"]
    if set(stock_roots) != set(policy.stock_roles):
        raise ValueError(f"{label} stock-root coverage is incomplete")
    normalized_stock_roots: dict[str, list[str]] = {}
    for role in sorted(stock_roots):
        values = tuple(stock_roots[role])
        _unique(values, f"{label} stock roots for {role}")
        if not values or not set(values).issubset(item["root_fact_ids"]):
            raise ValueError(f"{label} stock roots must be present in check lineage")
        normalized_stock_roots[role] = sorted(values)
    payload = to_json_value(item)
    payload["stock_root_fact_ids"] = normalized_stock_roots
    item = freeze(payload)
    try:
        parsed_stock_dates = {
            role: date.fromisoformat(value) for role, value in stock_dates.items()
        }
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} stock measurement date is invalid") from exc
    if policy.date_relationship == "all_stock_ends_equal":
        if period_start is not None or set(parsed_stock_dates.values()) != {period_end}:
            raise ValueError(f"{label} stock dates must equal the measurement end")
    elif policy.date_relationship == (
        "beginning_plus_one_day_equals_flow_start_and_ending_equals_flow_end"
    ):
        if period_start is None:
            raise ValueError("clean_surplus requires a complete flow period")
        if parsed_stock_dates["beginning_common_equity"] + timedelta(days=1) != period_start:
            raise ValueError("clean_surplus beginning stock must immediately precede flow start")
        if parsed_stock_dates["ending_common_equity"] != period_end:
            raise ValueError("clean_surplus ending stock must equal flow end")
    else:
        raise ValueError(f"{label} date relationship is not registered")
    if not all(
        str(item[field]).strip() for field in ("currency", "unit", "common_equity_perimeter_id")
    ):
        raise ValueError(f"{label} currency, unit, and common-equity perimeter are required")
    if item["difference"] is None:
        if item["status"] != "blocked":
            raise ValueError(f"{label} missing difference requires blocked status")
    elif (
        isinstance(item["difference"], bool)
        or not isinstance(item["difference"], (int, float))
        or not math.isfinite(float(item["difference"]))
    ):
        raise ValueError(f"{label} difference must be finite")
    if (
        isinstance(item["tolerance"], bool)
        or not isinstance(item["tolerance"], (int, float))
        or not math.isfinite(float(item["tolerance"]))
        or float(item["tolerance"]) < 0
    ):
        raise ValueError(f"{label} tolerance is invalid")
    if (
        item["status"] == "reconciles_independently"
        and item["difference"] is not None
        and abs(float(item["difference"])) > float(item["tolerance"])
    ):
        raise ValueError(f"{label} independent reconciliation exceeds tolerance")
    if item["status"] == "reconciles_independently" and item["reason_codes"]:
        raise ValueError(f"{label} independent reconciliation cannot retain reasons")
    if item["status"] != "reconciles_independently" and not item["reason_codes"]:
        raise ValueError(f"{label} non-independent status requires a reason")
    return item


def _current_accounting_measurement_end(
    ledger_facts: dict[str, FrozenMap],
) -> str:
    anchor_dates = {
        fact.get("as_of_date")
        for fact in ledger_facts.values()
        if fact.get("raw") is True
        and fact.get("concept") in {"total_assets", "total_liabilities", "total_equity"}
    }
    if not anchor_dates or None in anchor_dates:
        raise ValueError("current accounting measurement date cannot be determined")
    return max(anchor_dates)


def _classification_candidate_ids(
    ledger_facts: dict[str, FrozenMap], measurement_end: str
) -> set[str]:
    candidates: set[str] = set()
    for fact_id, fact in ledger_facts.items():
        policy = ACCOUNT_CONCEPT_POLICIES.get(fact.get("concept"))
        if (
            policy is not None
            and fact.get("raw") is True
            and policy.period_kind == "stock"
            and fact.get("as_of_date") == measurement_end
            and (policy.account_role != "unresolved" or policy.classification_requires_review)
        ):
            candidates.add(fact_id)
    return candidates


def _validate_formula_decision(
    decision: AccountingFactDecision,
    ledger_facts: dict[str, FrozenMap],
    reporting_currency: str,
    registered_formula_outputs: set[str],
) -> None:
    if decision.disposition != "emitted":
        return
    policy = FORMULA_POLICIES[decision.purpose]
    inputs = [ledger_facts[fact_id] for fact_id in decision.input_fact_ids]
    if any(
        item.get("raw") is False and item["fact_id"] not in registered_formula_outputs
        for item in inputs
    ):
        raise ValueError("accounting formula input uses an unregistered derived Fact")
    replayed_roots = _replayed_raw_roots(decision.input_fact_ids, ledger_facts)
    if replayed_roots != set(decision.root_fact_ids):
        raise ValueError("accounting formula root lineage does not replay its inputs")
    roots_by_input = [
        _ultimate_raw_roots(fact_id, ledger_facts) for fact_id in decision.input_fact_ids
    ]
    seen_roots: set[str] = set()
    for roots in roots_by_input:
        if seen_roots.intersection(roots):
            raise ValueError("accounting formula inputs reuse an ultimate raw root")
        seen_roots.update(roots)
    period_keys = {
        (item.get("period_start"), item.get("period_end"), item.get("as_of_date"))
        for item in inputs
    }
    if policy.requires_same_period and len(period_keys) != 1:
        raise ValueError("accounting formula input periods are inconsistent")
    source_ids = {item.get("source_id") for item in inputs}
    if None in source_ids or len(source_ids) != 1:
        raise ValueError("accounting formula inputs require one formal source")
    if policy.requires_same_currency and any(
        item.get("currency") != reporting_currency
        or item.get("unit") != f"{reporting_currency} millions"
        for item in inputs
    ):
        raise ValueError("accounting formula currency or unit is inconsistent")
    for item in inputs:
        value = item.get("value")
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
        ):
            raise ValueError("accounting formula input must be finite numeric evidence")
    binding_by_role = {item["input_role"]: item for item in decision.term_bindings}
    expected_value = 0.0
    for term in policy.terms:
        binding = binding_by_role[term.input_role]
        facts = [ledger_facts[fact_id] for fact_id in binding["fact_ids"]]
        if any(item.get("concept") not in term.permitted_concepts for item in facts):
            raise ValueError("formula term Fact concept is not registered for its role")
        if term.cardinality == "exactly_one" and len(facts) != 1:
            raise ValueError("formula term requires exactly one Fact")
        if term.cardinality == "classified_role_set" and not facts:
            raise ValueError("formula term requires a classified account role set")
        if term.cardinality == "all_concepts_require_coverage":
            concepts = tuple(item.get("concept") for item in facts)
            if len(concepts) != len(set(concepts)) or set(concepts) != set(term.permitted_concepts):
                raise ValueError("formula term does not cover every registered concept")
        if term.cardinality.startswith("zero_or_more"):
            if facts and binding["inclusion_status"] != term.required_inclusion_status:
                raise ValueError("formula term inclusion proof does not match its policy")
            if not facts and binding["inclusion_status"] != "none_identified_after_review":
                raise ValueError("empty formula term lacks reviewed absence evidence")
        expected_value += term.sign * sum(float(item["value"]) for item in facts)
    output = ledger_facts[decision.output_fact_id]
    output_policy = ACCOUNT_CONCEPT_POLICIES[policy.output_concept]
    output_value = output.get("value")
    if (
        output.get("concept") != policy.output_concept
        or output.get("category") != output_policy.kernel_category
        or output.get("raw") is not False
        or set(output.get("parent_fact_ids", ())) != set(decision.input_fact_ids)
        or output.get("derivation") != ACCOUNTING_FORMULA_DERIVATIONS[decision.purpose]
        or output.get("currency") != reporting_currency
        or output.get("unit") != f"{reporting_currency} millions"
        or (output.get("period_start"), output.get("period_end"), output.get("as_of_date"))
        not in period_keys
        or output.get("source_id") not in source_ids
        or isinstance(output_value, bool)
        or not isinstance(output_value, (int, float))
        or not math.isfinite(float(output_value))
        or not math.isclose(
            float(output_value),
            expected_value,
            rel_tol=0.0,
            abs_tol=1e-12,
        )
    ):
        raise ValueError("accounting derived Fact does not replay its formula decision")
    expected_lineage_status = (
        "dependent_inputs"
        if any(item.get("raw") is False for item in inputs)
        else "independent_inputs"
    )
    if decision.lineage_status != expected_lineage_status:
        raise ValueError("accounting formula lineage status does not replay its inputs")


def _validate_common_equity_alias(
    *,
    role: str,
    fact: FrozenMap,
    ledger_facts: dict[str, FrozenMap],
    registered_formula_outputs: set[str],
) -> None:
    if role not in COMMON_EQUITY_ALIAS_DERIVATIONS:
        raise ValueError("accounting check uses an unregistered derived role Fact")
    parents = tuple(fact.get("parent_fact_ids", ()))
    if len(parents) != 1:
        raise ValueError("common-equity alias requires one official parent")
    parent = ledger_facts[parents[0]]
    if (
        fact.get("concept") != role
        or fact.get("derivation") != COMMON_EQUITY_ALIAS_DERIVATIONS[role]
        or parent.get("concept") != "common_equity"
        or not (parent.get("raw") is True or parent["fact_id"] in registered_formula_outputs)
        or parent.get("value") != fact.get("value")
        or parent.get("currency") != fact.get("currency")
        or parent.get("unit") != fact.get("unit")
        or parent.get("period_start") != fact.get("period_start")
        or parent.get("period_end") != fact.get("period_end")
        or parent.get("as_of_date") != fact.get("as_of_date")
        or parent.get("source_id") != fact.get("source_id")
    ):
        raise ValueError("common-equity alias does not replay its official parent")


def _validate_check_replay(
    check_id: str,
    item: FrozenMap,
    ledger_facts: dict[str, FrozenMap],
    reporting_currency: str,
    registered_formula_outputs: set[str],
) -> None:
    policy = PERIOD_ALIGNMENT_POLICIES[check_id]
    role_fact_ids = dict(item["role_fact_ids"])
    present_fact_ids = tuple(fact_id for fact_id in role_fact_ids.values() if fact_id is not None)
    _require_ledger_facts(present_fact_ids, ledger_facts, f"{check_id} role bindings")
    if any(fact_id is None for fact_id in role_fact_ids.values()):
        if item["status"] != "blocked" or item["difference"] is not None:
            raise ValueError(f"{check_id} missing role requires blocked status")
        return
    role_facts = {
        role: ledger_facts[fact_id]
        for role, fact_id in role_fact_ids.items()
        if fact_id is not None
    }
    for role, fact in role_facts.items():
        if fact.get("raw") is False and fact["fact_id"] not in registered_formula_outputs:
            _validate_common_equity_alias(
                role=role,
                fact=fact,
                ledger_facts=ledger_facts,
                registered_formula_outputs=registered_formula_outputs,
            )
    if any(fact.get("concept") != role for role, fact in role_facts.items()):
        raise ValueError(f"{check_id} role Fact concept is invalid")
    if any(
        fact.get("currency") != reporting_currency
        or fact.get("unit") != f"{reporting_currency} millions"
        or isinstance(fact.get("value"), bool)
        or not isinstance(fact.get("value"), (int, float))
        or not math.isfinite(float(fact["value"]))
        for fact in role_facts.values()
    ):
        raise ValueError(f"{check_id} role Fact amount semantics are invalid")
    if item["currency"] != reporting_currency or item["unit"] != (f"{reporting_currency} millions"):
        raise ValueError(f"{check_id} currency or unit does not replay the ledger")
    stock_dates: dict[str, str] = {}
    for role in policy.stock_roles:
        fact = role_facts[role]
        if (
            fact.get("period_start") is not None
            or fact.get("period_end") != fact.get("as_of_date")
            or not fact.get("period_end")
        ):
            raise ValueError(f"{check_id} stock Fact period is invalid")
        stock_dates[role] = fact["period_end"]
    flow_periods: set[tuple[str, str]] = set()
    for role in policy.flow_roles:
        fact = role_facts[role]
        if (
            not fact.get("period_start")
            or not fact.get("period_end")
            or fact.get("as_of_date") != fact.get("period_end")
        ):
            raise ValueError(f"{check_id} flow Fact period is invalid")
        flow_periods.add((fact["period_start"], fact["period_end"]))
    if len(flow_periods) > 1:
        raise ValueError(f"{check_id} flow Facts do not share one period")
    if policy.date_relationship == "all_stock_ends_equal":
        if len(set(stock_dates.values())) != 1:
            raise ValueError(f"{check_id} stock Facts do not share one measurement date")
        expected_period = {"start": None, "end": next(iter(stock_dates.values()))}
    else:
        flow_start, flow_end = next(iter(flow_periods))
        if (
            date.fromisoformat(stock_dates["beginning_common_equity"]) + timedelta(days=1)
            != date.fromisoformat(flow_start)
            or stock_dates["ending_common_equity"] != flow_end
        ):
            raise ValueError("clean_surplus ledger periods are not consecutive")
        expected_period = {"start": flow_start, "end": flow_end}
    if to_json_value(item["measurement_period"]) != expected_period:
        raise ValueError(f"{check_id} measurement period does not replay role Facts")
    if dict(item["stock_measurement_dates"]) != stock_dates:
        raise ValueError(f"{check_id} stock dates do not replay role Facts")
    roots_by_role = {
        role: _ultimate_raw_roots(fact_id, ledger_facts)
        for role, fact_id in role_fact_ids.items()
        if fact_id is not None
    }
    expected_stock_roots = {role: sorted(roots_by_role[role]) for role in policy.stock_roles}
    if to_json_value(item["stock_root_fact_ids"]) != expected_stock_roots:
        raise ValueError(f"{check_id} stock roots do not replay role Facts")
    expected_roots = set().union(*roots_by_role.values())
    if set(item["root_fact_ids"]) != expected_roots:
        raise ValueError(f"{check_id} roots do not replay role Facts")
    expected_difference = sum(
        sign * float(role_facts[role]["value"]) for role, sign in policy.equation_terms
    )
    if item["difference"] is None or not math.isclose(
        float(item["difference"]),
        expected_difference,
        rel_tol=0.0,
        abs_tol=1e-12,
    ):
        raise ValueError(f"{check_id} difference does not replay registered arithmetic")
    expected_tolerance = ACCOUNTING_RECONCILIATION_RELATIVE_TOLERANCE * max(
        1.0, *(abs(float(fact["value"])) for fact in role_facts.values())
    )
    if not math.isclose(
        float(item["tolerance"]),
        expected_tolerance,
        rel_tol=0.0,
        abs_tol=1e-15,
    ):
        raise ValueError(f"{check_id} tolerance does not replay registered policy")
    seen_roots: set[str] = set()
    overlapping = False
    for roots in roots_by_role.values():
        if seen_roots.intersection(roots):
            overlapping = True
        seen_roots.update(roots)
    expected_status = (
        "blocked"
        if abs(expected_difference) > expected_tolerance
        else "reconciles_by_construction"
        if overlapping
        else "reconciles_independently"
    )
    if item["status"] != expected_status:
        raise ValueError(f"{check_id} status does not replay arithmetic and lineage")


def _economic_claim_key(
    *,
    issuer_id: str,
    identity_kind: str,
    identity_value: str,
    scope_id: str,
    measurement_end: str,
    security_class: str | None,
) -> str:
    return canonical_sha256(
        {
            "policy_id": PHASE5C_POLICY_ID,
            "policy_version": PHASE5C_POLICY_VERSION,
            "issuer_id": issuer_id,
            "identity_kind": identity_kind,
            "identity_value": identity_value,
            "scope_id": scope_id,
            "measurement_end": measurement_end,
            "security_class": security_class,
        }
    )


def _economic_claim_review_statement(binding: FrozenMap) -> str:
    semantic_sha = canonical_sha256(
        {
            "economic_identity": binding["economic_identity"],
            "identity_kind": binding["identity_kind"],
            "identity_value": binding["identity_value"],
            "scope_id": binding["scope_id"],
            "measurement_end": binding["measurement_end"],
            "security_class": binding["security_class"],
            "root_fact_ids": binding["root_fact_ids"],
            "identity_evidence_fact_ids": binding["identity_evidence_fact_ids"],
            "diluted_share_treatment": binding["diluted_share_treatment"],
            "diluted_share_fact_ids": binding["diluted_share_fact_ids"],
        }
    )
    return f"Reviewed Phase 5C economic-claim identity {semantic_sha}."


def _closed_economic_claim_binding(raw: Any, *, issuer_id: str) -> FrozenMap:
    item = _freeze_with_sorted_sequences(
        raw,
        label="economic claim binding",
        sequence_fields=(
            "root_fact_ids",
            "identity_evidence_fact_ids",
            "diluted_share_fact_ids",
            "missing_evidence",
            "reason_codes",
        ),
    )
    required = {
        "binding_id",
        "economic_identity",
        "identity_kind",
        "identity_value",
        "scope_id",
        "measurement_end",
        "security_class",
        "economic_claim_key",
        "status",
        "root_fact_ids",
        "identity_evidence_fact_ids",
        "diluted_share_treatment",
        "diluted_share_fact_ids",
        "candidate_id",
        "review_decision_id",
        "claim_id",
        "missing_evidence",
        "reason_codes",
    }
    if set(item) != required or not all(
        item[field]
        for field in (
            "binding_id",
            "economic_identity",
            "identity_kind",
            "identity_value",
            "scope_id",
            "measurement_end",
            "status",
        )
    ):
        raise ValueError("economic claim binding fields are invalid")
    if item["economic_identity"] not in CROSS_CHANNEL_POLICIES:
        raise ValueError("economic claim identity is not registered")
    if item["identity_kind"] not in ECONOMIC_CLAIM_IDENTITY_KINDS:
        raise ValueError("economic claim identity kind is not registered")
    if item["status"] not in ECONOMIC_CLAIM_BINDING_STATUSES:
        raise ValueError("economic claim binding status is not registered")
    if item["diluted_share_treatment"] not in DILUTED_SHARE_TREATMENTS:
        raise ValueError("diluted-share treatment is not registered")
    _parse_iso_date(item["measurement_end"], "economic claim measurement end")
    if not set(item["reason_codes"]).issubset(PHASE5C_REASON_CODES):
        raise ValueError("economic claim binding uses an unregistered reason")
    if not item["root_fact_ids"]:
        raise ValueError("economic claim binding requires raw roots")
    if not item["identity_evidence_fact_ids"]:
        raise ValueError("economic claim identity requires reviewed evidence")
    if item["scope_id"] != f"scope:{issuer_id}:issuer-wide":
        raise ValueError("economic claim scope is not the reviewed issuer perimeter")
    if item["economic_identity"] == "option_or_dilution_claim":
        if not item["security_class"]:
            raise ValueError("option claim requires one reviewed security class")
        if item["diluted_share_treatment"] in {"included", "excluded"}:
            if len(item["diluted_share_fact_ids"]) != 1:
                raise ValueError("option claim requires reviewed diluted-share evidence")
        elif item["diluted_share_treatment"] == "not_applicable":
            if item["diluted_share_fact_ids"]:
                raise ValueError("not-applicable dilution treatment cannot cite share Facts")
        elif item["diluted_share_treatment"] == "blocked" and not item["missing_evidence"]:
            raise ValueError("blocked dilution treatment requires missing evidence")
    else:
        if item["diluted_share_treatment"] != "not_applicable" or item["diluted_share_fact_ids"]:
            raise ValueError("ordinary economic claims cannot carry dilution treatment")
        if (item["identity_kind"] == "security_class") != bool(item["security_class"]):
            raise ValueError(
                "ordinary security-class identity must bind exactly one reviewed class"
            )
    if item["status"] == "confirmed":
        expected_key = _economic_claim_key(
            issuer_id=issuer_id,
            identity_kind=item["identity_kind"],
            identity_value=item["identity_value"],
            scope_id=item["scope_id"],
            measurement_end=item["measurement_end"],
            security_class=item["security_class"],
        )
        if (
            item["economic_claim_key"] != expected_key
            or not all(item[field] for field in ("candidate_id", "review_decision_id", "claim_id"))
            or item["missing_evidence"]
            or item["reason_codes"]
            or item["diluted_share_treatment"] == "blocked"
        ):
            raise ValueError("confirmed economic claim binding does not replay identity")
    elif (
        item["economic_claim_key"] is not None
        or item["claim_id"] is not None
        or not item["candidate_id"]
        or not item["review_decision_id"]
        or not item["missing_evidence"]
        or "economic_claim_identity_unresolved" not in item["reason_codes"]
    ):
        raise ValueError("blocked economic claim binding must preserve its review gap")
    return item


def _validate_economic_claim_review_chain(
    *,
    binding: FrozenMap,
    issuer_id: str,
    data_cutoff_date: str,
    candidates: dict[str, AnalyticalClaimCandidate],
    decisions: dict[str, AnalyticalClaimReviewDecision],
    claims: dict[str, Claim],
    ledger_facts: dict[str, FrozenMap],
) -> None:
    candidate = candidates[binding["candidate_id"]]
    decision = decisions[binding["review_decision_id"]]
    expected_support = {
        *binding["root_fact_ids"],
        *binding["identity_evidence_fact_ids"],
        *binding["diluted_share_fact_ids"],
    }
    _require_ledger_facts(expected_support, ledger_facts, "economic claim evidence")
    candidate_support = {
        item["fact_id"]
        for item in candidate.supporting_evidence_bindings
        if item["fact_id"] is not None
    }
    root_facts = [ledger_facts[fact_id] for fact_id in binding["root_fact_ids"]]
    expected_identities = {
        ACCOUNT_CONCEPT_POLICIES[item["concept"]].bridge_role or "method_base"
        for item in root_facts
    }
    permitted_identity_kinds = {
        "method_base": {"aggregate_perimeter"},
        "nonoperating_asset": {"aggregate_perimeter", "instrument"},
        "debt": {"instrument"},
        "debt_equivalent": {"instrument"},
        "lease_liability": {"instrument"},
        "unfunded_pension": {"instrument", "plan"},
        "preferred_stock": {"security_class"},
        "noncontrolling_interest": {"security_class", "aggregate_perimeter"},
        "option_or_dilution_claim": {"plan", "program", "aggregate_perimeter"},
        "other_senior_claim": {"instrument", "security_class"},
    }
    if (
        expected_identities != {binding["economic_identity"]}
        or binding["identity_kind"] not in permitted_identity_kinds[binding["economic_identity"]]
        or {item["period_end"] for item in root_facts} != {binding["measurement_end"]}
    ):
        raise ValueError("economic claim structured identity conflicts with its root Facts")
    if (
        candidate.issuer_id != issuer_id
        or candidate.scope != freeze(_issuer_scope_payload(issuer_id))
        or candidate.claim_role != "support"
        or candidate.proposed_statement != _economic_claim_review_statement(binding)
        or candidate.business_attribute_role is not None
        or candidate.business_component_type is not None
        or candidate.validation_status != "ready"
        or candidate.validation_issues
        or candidate_support != expected_support
        or any(
            item["calculation_result_id"] is not None or item["context_observation_id"] is not None
            for item in candidate.supporting_evidence_bindings
        )
        or _parse_iso_date(candidate.as_of_date, "economic claim Candidate as-of")
        > _parse_iso_date(data_cutoff_date, "Phase 5C cutoff")
        or not candidate.counterevidence_search_note
        or not candidate.falsification_condition
    ):
        raise ValueError("economic claim Candidate does not replay reviewed evidence")
    if (
        decision.issuer_id != issuer_id
        or decision.candidate_id != candidate.candidate_id
        or decision.candidate_fingerprint != candidate.fingerprint
        or decision.evidence_graph_sha256 != candidate.evidence_graph_sha256
        or not decision.reviewer_id.startswith("human:")
        or datetime.fromisoformat(decision.reviewed_at.replace("Z", "+00:00")).date()
        > _parse_iso_date(data_cutoff_date, "Phase 5C cutoff")
    ):
        raise ValueError("economic claim ReviewDecision does not replay Candidate")
    if binding["status"] == "confirmed":
        claim = claims[binding["claim_id"]]
        if (
            decision.decision != "confirmed"
            or decision.output_claim_id != claim.claim_id
            or claim.issuer_id != issuer_id
            or claim.statement != candidate.proposed_statement
            or claim.as_of_date != candidate.as_of_date
            or set(claim.supporting_fact_ids) != expected_support
            or set(claim.counterevidence_fact_ids)
            != {
                item["fact_id"]
                for item in candidate.counterevidence_bindings
                if item["fact_id"] is not None
            }
            or claim.counterevidence_search_note != candidate.counterevidence_search_note
            or claim.confidence != candidate.proposed_confidence
            or claim.falsification_condition != candidate.falsification_condition
        ):
            raise ValueError("economic claim review chain does not replay Claim")
    elif decision.decision != "blocked" or decision.output_claim_id is not None:
        raise ValueError("blocked economic claim requires a blocked human Decision")


@dataclass(frozen=True, slots=True)
class AccountingReconciliationResult:
    issuer_id: str
    data_cutoff_date: str
    research_bundle_id: str
    research_bundle_fingerprint: str
    dependency_closure_sha256: str
    component_lock_sha256: str
    phase5b_mapping_fingerprint: str
    phase5b_mapping_result: FactLedgerMappingResult
    phase5b_readiness_fingerprint: str
    phase5b_readiness_result: ValuationReadinessResult
    policy_id: str
    policy_version: str
    policy_sha256: str
    base_ledger_fingerprint: str
    selected_input_fact_ids: tuple[str, ...]
    selected_input_source_ids: tuple[str, ...]
    ledger_payload: FrozenMap
    account_decisions: tuple[AccountClassificationDecision, ...]
    fact_decisions: tuple[AccountingFactDecision, ...]
    economic_claim_bindings: tuple[FrozenMap, ...]
    economic_claim_candidates: tuple[AnalyticalClaimCandidate, ...]
    economic_claim_review_decisions: tuple[AnalyticalClaimReviewDecision, ...]
    economic_claims: tuple[Claim, ...]
    owner_transaction_coverage: FrozenMap
    checks: FrozenMap
    status: str
    reason_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.issuer_id or not self.research_bundle_id:
            raise ValueError("accounting reconciliation identity is required")
        _policy_identity(self.policy_id, self.policy_version, self.policy_sha256)
        if self.status not in COMPILATION_STATUSES:
            raise ValueError("accounting reconciliation status is not registered")
        if not isinstance(self.phase5b_mapping_result, FactLedgerMappingResult):
            raise ValueError("accounting reconciliation requires the replayed Phase 5B mapping")
        if not isinstance(self.phase5b_readiness_result, ValuationReadinessResult):
            raise ValueError("accounting reconciliation requires the replayed Phase 5B readiness")
        mapping = self.phase5b_mapping_result
        readiness = self.phase5b_readiness_result
        if (
            mapping.fingerprint != self.phase5b_mapping_fingerprint
            or readiness.fingerprint != self.phase5b_readiness_fingerprint
            or readiness.mapping_result_fingerprint != mapping.fingerprint
            or mapping.issuer_id != self.issuer_id
            or readiness.issuer_id != self.issuer_id
            or mapping.data_cutoff_date != self.data_cutoff_date
            or readiness.data_cutoff_date != self.data_cutoff_date
            or mapping.research_bundle_id != self.research_bundle_id
            or mapping.research_bundle_fingerprint != self.research_bundle_fingerprint
            or mapping.dependency_closure_sha256 != self.dependency_closure_sha256
            or mapping.component_lock_sha256 != self.component_lock_sha256
            or mapping.mapping_policy_id != MAPPING_POLICY_ID
            or mapping.mapping_policy_version != MAPPING_POLICY_VERSION
            or mapping.mapping_policy_sha256 != mapping_policy_sha256()
            or mapping.kernel_fact_ledger_schema_sha256 != PINNED_FACT_LEDGER_SCHEMA_SHA256
        ):
            raise ValueError("Phase 5B mapping/readiness binding does not replay")
        base_ledger = _canonical_ledger_payload(mapping.ledger_payload)
        _validate_ledger_identity(
            base_ledger,
            issuer_id=self.issuer_id,
            data_cutoff_date=self.data_cutoff_date,
        )
        if self.base_ledger_fingerprint != canonical_sha256(base_ledger):
            raise ValueError("base ledger fingerprint does not replay Phase 5B mapping")
        ledger_payload = _canonical_ledger_payload(self.ledger_payload)
        object.__setattr__(self, "ledger_payload", ledger_payload)
        _validate_ledger_identity(
            ledger_payload,
            issuer_id=self.issuer_id,
            data_cutoff_date=self.data_cutoff_date,
        )
        base_sources = {item["source_id"]: item for item in base_ledger["sources"]}
        enriched_sources = {item["source_id"]: item for item in ledger_payload["sources"]}
        base_facts = {item["fact_id"]: item for item in base_ledger["facts"]}
        enriched_facts = {item["fact_id"]: item for item in ledger_payload["facts"]}
        if any(item.get("equity_bridge_role") is not None for item in base_facts.values()):
            raise ValueError("Phase 5B base ledger cannot pre-tag equity-bridge Facts")
        if any(enriched_sources.get(key) != value for key, value in base_sources.items()) or any(
            enriched_facts.get(key) != value for key, value in base_facts.items()
        ):
            raise ValueError("Phase 5C ledger does not preserve the Phase 5B base ledger")
        _sort_unique(self, "selected_input_fact_ids", "selected Phase 5C input Facts")
        _sort_unique(self, "selected_input_source_ids", "selected Phase 5C input sources")
        selected_fact_ids = set(self.selected_input_fact_ids)
        if selected_fact_ids.intersection(base_facts):
            raise ValueError("selected Phase 5C inputs must be new relative to Phase 5B")
        _require_ledger_facts(
            selected_fact_ids,
            enriched_facts,
            "selected Phase 5C input Facts",
        )
        selected_facts = [enriched_facts[fact_id] for fact_id in selected_fact_ids]
        if any(
            item.get("raw") is not True or item.get("equity_bridge_role") is not None
            for item in selected_facts
        ):
            raise ValueError("selected Phase 5C input Facts must be official raw evidence")
        selected_source_ids = {item["source_id"] for item in selected_facts}
        if selected_source_ids != set(self.selected_input_source_ids):
            raise ValueError("selected Phase 5C input source coverage is inconsistent")
        if set(enriched_sources).difference(base_sources) != selected_source_ids.difference(
            base_sources
        ):
            raise ValueError("Phase 5C ledger contains unrelated added sources")
        ledger_facts = _ledger_fact_map(ledger_payload)
        account_keys = tuple(item.fact_id for item in self.account_decisions)
        _unique(account_keys, "account decisions")
        account_roots = tuple(
            root for item in self.account_decisions for root in item.root_fact_ids
        )
        _unique(account_roots, "account classification roots")
        current_measurement_end = _current_accounting_measurement_end(ledger_facts)
        candidates = _classification_candidate_ids(ledger_facts, current_measurement_end)
        if set(account_keys) != candidates:
            raise ValueError("account decisions do not cover every ledger classification candidate")
        for decision in self.account_decisions:
            fact = ledger_facts[decision.fact_id]
            if fact.get("concept") != decision.concept:
                raise ValueError("account decision concept does not replay the ledger Fact")
            if decision.status == "classified" and set(decision.root_fact_ids) != {
                decision.fact_id
            }:
                raise ValueError("raw account classification roots must equal its ledger Fact")
        fact_keys = tuple(item.purpose for item in self.fact_decisions)
        _unique(fact_keys, "accounting Fact decisions")
        if set(fact_keys) != set(ACCOUNTING_FACT_PURPOSES):
            raise ValueError("accounting result must decide every registered Fact purpose")
        object.__setattr__(
            self,
            "account_decisions",
            tuple(sorted(self.account_decisions, key=lambda item: item.fact_id)),
        )
        object.__setattr__(
            self,
            "fact_decisions",
            tuple(sorted(self.fact_decisions, key=lambda item: item.purpose)),
        )
        emitted_fact_ids = tuple(
            item.output_fact_id
            for item in self.fact_decisions
            if item.disposition == "emitted" and item.output_fact_id is not None
        )
        emitted_calculation_ids = tuple(
            item.calculation_id
            for item in self.fact_decisions
            if item.disposition == "emitted" and item.calculation_id is not None
        )
        _unique(emitted_fact_ids, "emitted accounting Fact IDs")
        _unique(emitted_calculation_ids, "accounting calculation IDs")
        alias_fact_ids = {
            fact_id
            for fact_id, fact in enriched_facts.items()
            if fact_id not in base_facts and fact.get("concept") in COMMON_EQUITY_ALIAS_DERIVATIONS
        }
        if set(enriched_facts).difference(base_facts) != (
            selected_fact_ids | set(emitted_fact_ids) | alias_fact_ids
        ):
            raise ValueError("Phase 5C reconciliation contains unrelated added Facts")
        _require_ledger_facts(emitted_fact_ids, ledger_facts, "accounting Fact decisions")
        registered_formula_outputs = set(emitted_fact_ids)
        for decision in self.fact_decisions:
            _require_ledger_facts(
                {*decision.input_fact_ids, *decision.root_fact_ids},
                ledger_facts,
                f"accounting {decision.purpose}",
            )
            _validate_formula_decision(
                decision,
                ledger_facts,
                ledger_payload["reporting_currency"],
                registered_formula_outputs,
            )
        bindings = tuple(
            sorted(
                (
                    _closed_economic_claim_binding(item, issuer_id=self.issuer_id)
                    for item in self.economic_claim_bindings
                ),
                key=lambda item: item["binding_id"],
            )
        )
        _unique(tuple(item["binding_id"] for item in bindings), "economic claim binding IDs")
        candidates = {
            item.candidate_id: item
            for item in sorted(
                self.economic_claim_candidates,
                key=lambda item: item.candidate_id,
            )
        }
        review_decisions = {
            item.decision_id: item
            for item in sorted(
                self.economic_claim_review_decisions,
                key=lambda item: item.decision_id,
            )
        }
        claims = {
            item.claim_id: item
            for item in sorted(self.economic_claims, key=lambda item: item.claim_id)
        }
        if (
            len(candidates) != len(self.economic_claim_candidates)
            or len(review_decisions) != len(self.economic_claim_review_decisions)
            or len(claims) != len(self.economic_claims)
        ):
            raise ValueError("economic claim review identities must be unique")
        referenced_candidate_ids = {item["candidate_id"] for item in bindings}
        referenced_decision_ids = {item["review_decision_id"] for item in bindings}
        referenced_claim_ids = {
            item["claim_id"] for item in bindings if item["claim_id"] is not None
        }
        if (
            set(candidates) != referenced_candidate_ids
            or set(review_decisions) != referenced_decision_ids
            or set(claims) != referenced_claim_ids
        ):
            raise ValueError("economic claim review objects do not match bindings")
        required_claim_roots = {
            root_id
            for decision in self.fact_decisions
            if decision.purpose
            in {"invested_capital", "net_operating_assets", "net_financial_obligations"}
            for root_id in decision.root_fact_ids
        }
        option_account_roots = {
            item.fact_id
            for item in self.account_decisions
            if item.concept == "option_or_dilution_claim"
        }
        bound_roots = [root_id for item in bindings for root_id in item["root_fact_ids"]]
        _unique(tuple(bound_roots), "economic claim roots")
        if set(bound_roots) != required_claim_roots | option_account_roots:
            raise ValueError("economic claim bindings do not cover method-base roots")
        seen_claim_keys: set[str] = set()
        phase5b_facts = {
            item["fact_id"]: item for item in self.phase5b_mapping_result.ledger_payload["facts"]
        }
        for binding in bindings:
            if any(
                ledger_facts[root_id].get("raw") is not True
                or _ultimate_raw_roots(root_id, ledger_facts) != {root_id}
                for root_id in binding["root_fact_ids"]
            ):
                raise ValueError("economic claim binding roots must be ultimate raw Facts")
            _validate_economic_claim_review_chain(
                binding=binding,
                issuer_id=self.issuer_id,
                data_cutoff_date=self.data_cutoff_date,
                candidates=candidates,
                decisions=review_decisions,
                claims=claims,
                ledger_facts=ledger_facts,
            )
            key = binding["economic_claim_key"]
            if key is not None:
                if key in seen_claim_keys:
                    raise ValueError("one reviewed economic claim cannot have multiple bindings")
                seen_claim_keys.add(key)
            if binding["economic_identity"] == "option_or_dilution_claim":
                diluted_facts = [
                    ledger_facts[fact_id] for fact_id in binding["diluted_share_fact_ids"]
                ]
                if any(
                    item.get("concept") != "diluted_shares"
                    or item.get("category") != "share_count"
                    or item.get("currency") is not None
                    or item.get("unit") != "millions shares"
                    for item in diluted_facts
                ):
                    raise ValueError("diluted-share plan evidence semantics are invalid")
                option_value = sum(
                    float(ledger_facts[root_id]["value"]) for root_id in binding["root_fact_ids"]
                )
                if binding["diluted_share_treatment"] in {"included", "excluded"}:
                    diluted_id = binding["diluted_share_fact_ids"][0]
                    diluted_fact = ledger_facts[diluted_id]
                    if (
                        phase5b_facts.get(diluted_id) != diluted_fact
                        or diluted_fact["period_end"] != binding["measurement_end"]
                    ):
                        raise ValueError(
                            "option treatment does not bind the current Phase 5B diluted shares"
                        )
                elif binding["diluted_share_treatment"] == "not_applicable" and option_value != 0:
                    raise ValueError(
                        "a positive option claim requires an included or excluded treatment"
                    )
                nfo_roots = set(
                    next(
                        item
                        for item in self.fact_decisions
                        if item.purpose == "net_financial_obligations"
                    ).root_fact_ids
                )
                if (
                    binding["diluted_share_treatment"] == "included"
                    and option_value != 0
                    and nfo_roots.intersection(binding["root_fact_ids"])
                ):
                    raise ValueError(
                        "diluted-share included option claim cannot remain in Penman NFO"
                    )
        included_option_roots = {
            root_id
            for binding in bindings
            if binding["economic_identity"] == "option_or_dilution_claim"
            and binding["diluted_share_treatment"] == "included"
            for root_id in binding["root_fact_ids"]
        }
        object.__setattr__(self, "economic_claim_bindings", bindings)
        object.__setattr__(
            self,
            "economic_claim_candidates",
            tuple(candidates[key] for key in sorted(candidates)),
        )
        object.__setattr__(
            self,
            "economic_claim_review_decisions",
            tuple(review_decisions[key] for key in sorted(review_decisions)),
        )
        object.__setattr__(
            self,
            "economic_claims",
            tuple(claims[key] for key in sorted(claims)),
        )
        classified_non_common_claims = {
            item.fact_id: item
            for item in self.account_decisions
            if item.status == "classified" and item.perimeter_disposition is not None
        }
        non_common_formula_roles = {
            "common_equity": (
                "included_non_common_equity_claims",
                "total_equity",
                "included",
            ),
            "adjusted_total_liabilities": (
                "equity_classified_non_common_claims",
                "reported_liabilities",
                "excluded",
            ),
            "net_financial_obligations": (
                "nfo_non_common_equity_claims",
                "financial_obligations",
                "excluded",
            ),
        }
        decisions_by_purpose = {item.purpose: item for item in self.fact_decisions}
        for purpose, (role, perimeter_field, selected_state) in non_common_formula_roles.items():
            decision = decisions_by_purpose[purpose]
            if decision.disposition != "emitted":
                continue
            binding = next(item for item in decision.term_bindings if item["input_role"] == role)
            expected_fact_ids = {
                fact_id
                for fact_id, account_decision in classified_non_common_claims.items()
                if account_decision.perimeter_disposition[perimeter_field] == selected_state
            }
            if set(binding["fact_ids"]) != expected_fact_ids:
                raise ValueError(
                    "non-common claim formula does not replay reviewed perimeter dispositions"
                )
        aggregation_formula_roles = {
            ("net_operating_assets", "operating_asset_components"): "operating_asset",
            ("net_operating_assets", "operating_liability_components"): ("operating_liability"),
            ("net_financial_obligations", "financial_asset_components"): "financial_asset",
            ("net_financial_obligations", "financial_obligation_components"): (
                "financial_obligation"
            ),
        }
        for (purpose, input_role), account_role in aggregation_formula_roles.items():
            formula_decision = decisions_by_purpose[purpose]
            account_rows = tuple(
                item
                for item in self.account_decisions
                if item.status == "classified" and item.account_role == account_role
            )
            binding = next(
                item for item in formula_decision.term_bindings if item["input_role"] == input_role
            )
            expected_account_fact_ids = {item.fact_id for item in account_rows}
            if account_role == "financial_obligation":
                expected_account_fact_ids.difference_update(included_option_roots)
            if set(binding["fact_ids"]) != expected_account_fact_ids:
                raise ValueError("accounting formula does not consume its classified role set")
            if formula_decision.disposition == "blocked":
                if expected_account_fact_ids:
                    if (
                        binding["inclusion_status"] == "unresolved"
                        or binding["missing_evidence"]
                        or binding["reason_codes"]
                    ):
                        raise ValueError(
                            "confirmed account role cannot inherit another role's evidence gap"
                        )
                elif (
                    binding["inclusion_status"] != "unresolved"
                    or not binding["missing_evidence"]
                    or not set(binding["reason_codes"]).intersection(
                        {"account_role_evidence_missing", "account_root_role_conflict"}
                    )
                ):
                    raise ValueError(
                        "blocked account role requires a registered unresolved evidence gap"
                    )
                continue
            if formula_decision.disposition != "emitted" or not account_rows:
                raise ValueError("accounting role cannot emit without classified evidence")
            aggregation_levels = {item.aggregation_level for item in account_rows}
            aggregation_sets = {item.aggregation_set_id for item in account_rows}
            if aggregation_levels == {"aggregate"}:
                if len(account_rows) != 1:
                    raise ValueError("accounting role cannot contain multiple aggregates")
            elif aggregation_levels != {"component"} or len(aggregation_sets) != 1:
                raise ValueError("accounting role components require one aggregation set")
        owner_coverage = _closed_owner_transaction_coverage(self.owner_transaction_coverage)
        object.__setattr__(self, "owner_transaction_coverage", owner_coverage)
        coverage_fact_ids = tuple(
            item["fact_id"] for item in owner_coverage.values() if item["fact_id"]
        )
        _require_ledger_facts(coverage_fact_ids, ledger_facts, "owner-transaction coverage")
        owner_decision = next(
            item for item in self.fact_decisions if item.purpose == "net_distributions_to_owners"
        )
        if owner_decision.disposition == "emitted" and set(owner_decision.input_fact_ids) != set(
            coverage_fact_ids
        ):
            raise ValueError("owner-transaction coverage does not match net-distribution inputs")
        for concept, coverage_item in owner_coverage.items():
            fact_id = coverage_item["fact_id"]
            if fact_id is None:
                continue
            fact = ledger_facts[fact_id]
            if fact.get("concept") != concept:
                raise ValueError("owner-transaction Fact concept does not match coverage")
            value = fact.get("value")
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
                or float(value) < 0
            ):
                raise ValueError("owner-transaction Fact must be a nonnegative magnitude")
            if coverage_item["status"] in {"official_zero", "not_applicable"} and value != 0:
                raise ValueError("official-zero or not-applicable owner transaction must be zero")
            if coverage_item["status"] in {"official_zero", "not_applicable"} and (
                fact.get("raw") is not True
                or fact.get("parent_fact_ids")
                or fact.get("derivation") is not None
                or _ultimate_raw_roots(fact_id, ledger_facts) != {fact_id}
            ):
                raise ValueError(
                    "official-zero or not-applicable owner transaction must be an official raw Fact"
                )
            if coverage_item["status"] == "observed" and fact.get("raw") is not True:
                raise ValueError("observed owner transaction must be an official raw Fact")
        checks = freeze(self.checks)
        expected = {"balance_sheet", "clean_surplus", "noa_nfo_common_equity"}
        if set(checks) != expected:
            raise ValueError("accounting reconciliation must contain exactly three checks")
        normalized = {key: _closed_check(checks[key], key) for key in sorted(checks)}
        object.__setattr__(self, "checks", freeze(normalized))
        check_fact_ids = {fact_id for item in self.checks.values() for fact_id in item["fact_ids"]}
        check_root_ids = {
            fact_id for item in self.checks.values() for fact_id in item["root_fact_ids"]
        }
        _require_ledger_facts(
            check_fact_ids | check_root_ids, ledger_facts, "accounting reconciliation checks"
        )
        consumed_fact_ids = (
            {
                fact_id
                for decision in self.account_decisions
                for fact_id in (decision.fact_id, *decision.root_fact_ids)
            }
            | {
                fact_id
                for decision in self.fact_decisions
                for fact_id in (
                    *decision.input_fact_ids,
                    *decision.root_fact_ids,
                    *((decision.output_fact_id,) if decision.output_fact_id else ()),
                )
            }
            | set(coverage_fact_ids)
            | check_fact_ids
            | check_root_ids
        )
        if not selected_fact_ids.issubset(consumed_fact_ids):
            raise ValueError("selected Phase 5C input Facts are not consumed by reconciliation")
        for check_id, item in self.checks.items():
            _validate_check_replay(
                check_id,
                item,
                ledger_facts,
                ledger_payload["reporting_currency"],
                registered_formula_outputs,
            )
        if (
            len(
                {
                    (
                        item["measurement_period"]["end"],
                        item["currency"],
                        item["unit"],
                        item["common_equity_perimeter_id"],
                    )
                    for item in self.checks.values()
                }
            )
            != 1
        ):
            raise ValueError(
                "accounting checks must share measurement end, currency, unit, and perimeter"
            )
        common_equity_roots = {
            tuple(self.checks["balance_sheet"]["stock_root_fact_ids"]["common_equity"]),
            tuple(self.checks["clean_surplus"]["stock_root_fact_ids"]["ending_common_equity"]),
            tuple(self.checks["noa_nfo_common_equity"]["stock_root_fact_ids"]["common_equity"]),
        }
        if len(common_equity_roots) != 1:
            raise ValueError("accounting checks must share ending common-equity lineage")
        _reason_codes(self)
        statuses = {item["status"] for item in self.checks.values()}
        if self.status == "pass" and statuses != {"reconciles_independently"}:
            raise ValueError("pass cannot include by-construction or blocked checks")
        if "blocked" in statuses and self.status != "blocked":
            raise ValueError("blocked accounting check requires blocked result")
        if "reconciles_by_construction" in statuses and self.status == "pass":
            raise ValueError("by-construction check cannot produce pass")
        has_blocked_evidence = (
            "blocked" in statuses
            or any(item.status == "blocked" for item in self.account_decisions)
            or any(item.disposition == "blocked" for item in self.fact_decisions)
            or any(item["status"] == "blocked" for item in self.owner_transaction_coverage.values())
            or any(
                item["status"] == "blocked" or item["diluted_share_treatment"] == "blocked"
                for item in self.economic_claim_bindings
            )
        )
        has_partial_evidence = "reconciles_by_construction" in statuses or any(
            item.disposition == "excluded" for item in self.fact_decisions
        )
        expected_status = (
            "blocked" if has_blocked_evidence else "partial" if has_partial_evidence else "pass"
        )
        if self.status != expected_status:
            raise ValueError("accounting reconciliation status is not deterministic")
        if self.status == "pass":
            if self.reason_codes:
                raise ValueError("passing accounting result cannot retain blocking reasons")
            if not self.account_decisions or any(
                item.status != "classified" for item in self.account_decisions
            ):
                raise ValueError("passing accounting result requires classified accounts")
            if any(item.disposition != "emitted" for item in self.fact_decisions):
                raise ValueError("passing accounting result requires every accounting Fact")
            if any(
                item["status"] == "blocked" for item in self.owner_transaction_coverage.values()
            ):
                raise ValueError("passing accounting result requires owner-transaction coverage")
        elif not self.reason_codes:
            raise ValueError("partial or blocked accounting result requires a reason")

    @property
    def fingerprint(self) -> str:
        return _fingerprint(self)

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)


def _closed_quality_decision(raw: Any) -> FrozenMap:
    item = _freeze_with_sorted_sequences(
        raw,
        label="accounting quality decision",
        sequence_fields=("evidence_fact_ids", "reason_codes"),
    )
    required = {
        "finding_id",
        "finding_fingerprint",
        "finding_status",
        "final_severity",
        "evidence_state",
        "category",
        "disposition",
        "material",
        "resolved",
        "evidence_fact_ids",
        "claim_id",
        "review_decision_id",
        "reason_codes",
    }
    if set(item) != required:
        raise ValueError("accounting quality issue decision has invalid fields")
    if not isinstance(item["finding_fingerprint"], str) or len(item["finding_fingerprint"]) != 64:
        raise ValueError("accounting quality Finding fingerprint is required")
    if item["finding_status"] not in {"provisional", "confirmed", "cleared", "blocked"}:
        raise ValueError("accounting quality Finding status is invalid")
    if item["final_severity"] not in {"informational", "watch", "red_flag"}:
        raise ValueError("accounting quality Finding severity is invalid")
    if item["finding_status"] == "confirmed":
        expected_evidence_state = (
            "confirmed_red_flag" if item["final_severity"] == "red_flag" else item["final_severity"]
        )
    else:
        expected_evidence_state = item["finding_status"]
    if item["evidence_state"] != expected_evidence_state:
        raise ValueError("accounting quality evidence state does not replay the Finding")
    mapping = QUALITY_MAPPING_POLICIES.get(item["evidence_state"])
    if mapping is None:
        raise ValueError("accounting quality evidence state is not registered")
    expected_disposition = {
        "confirmed_red_flag": "material_unresolved",
        "cleared": "resolved",
        "watch": "nonmaterial",
        "informational": "nonmaterial",
        "provisional": "provisional",
        "blocked": "blocked",
    }[item["evidence_state"]]
    expected_material = (
        item["final_severity"] == "red_flag"
        if mapping.material_source == "reviewed_final_severity"
        else mapping.material
    )
    if (
        item["disposition"] != expected_disposition
        or item["material"] is not expected_material
        or item["resolved"] is not mapping.resolved
    ):
        raise ValueError("accounting quality disposition does not replay the Finding")
    if item["finding_status"] == "blocked" and item["final_severity"] != "informational":
        raise ValueError("blocked AccountingQualityFinding cannot assert severity")
    if item["disposition"] not in {
        "material_unresolved",
        "resolved",
        "nonmaterial",
        "provisional",
        "blocked",
    }:
        raise ValueError("accounting quality disposition is not registered")
    if not item["finding_id"] or item["category"] not in ACCOUNTING_QUALITY_CATEGORIES:
        raise ValueError("accounting quality issue identity is required")
    if not set(item["reason_codes"]).issubset(PHASE5C_REASON_CODES):
        raise ValueError("accounting quality issue uses an unregistered reason code")
    if item["disposition"] in {"material_unresolved", "resolved", "nonmaterial"} and (
        not item["claim_id"] or not item["review_decision_id"]
    ):
        raise ValueError("resolved accounting quality semantics require reviewed Claim evidence")
    if item["disposition"] == "material_unresolved" and (
        item["material"] is not True or item["resolved"] is not False
    ):
        raise ValueError("material unresolved issue flags are inconsistent")
    if item["disposition"] == "resolved" and (
        item["resolved"] is not True or not isinstance(item["material"], bool)
    ):
        raise ValueError("resolved issue must preserve reviewed materiality")
    if item["disposition"] == "nonmaterial" and (
        item["material"] is not False or item["resolved"] is not False
    ):
        raise ValueError("nonmaterial watch/informational issue must remain unresolved")
    if item["disposition"] in {"provisional", "blocked"} and (
        item["material"] is not None or item["resolved"] is not None
    ):
        raise ValueError("provisional or blocked issue cannot assert materiality or resolution")
    if item["disposition"] in {"provisional", "blocked"} and not item["reason_codes"]:
        raise ValueError("provisional or blocked issue requires a reason")
    if (
        item["disposition"] in {"material_unresolved", "resolved", "nonmaterial"}
        and item["reason_codes"]
    ):
        raise ValueError("reviewed accounting quality decision cannot retain blocking reasons")
    return item


def _closed_kernel_issue(raw: Any) -> FrozenMap:
    item = _freeze_with_sorted_sequences(
        raw,
        label="kernel accounting quality issue",
        sequence_fields=("evidence_fact_ids",),
    )
    required = {"issue_id", "category", "material", "resolved", "evidence_fact_ids"}
    if set(item) != required:
        raise ValueError("kernel accounting quality issue has invalid fields")
    if not item["issue_id"] or item["category"] not in ACCOUNTING_QUALITY_CATEGORIES:
        raise ValueError("kernel accounting quality issue identity is required")
    return item


@dataclass(frozen=True, slots=True)
class AccountingQualityCompilationResult:
    issuer_id: str
    data_cutoff_date: str
    reconciliation_fingerprint: str
    reconciliation_result: AccountingReconciliationResult
    policy_id: str
    policy_version: str
    policy_sha256: str
    accounting_quality_review_id: str
    accounting_quality_review_fingerprint: str
    accounting_quality_review_status: str
    accounting_quality_review: AccountingQualityReview
    accounting_quality_findings: tuple[AccountingQualityFinding, ...]
    ledger_payload: FrozenMap
    adjustment_decisions: tuple[MethodAdjustmentDecision, ...]
    expected_finding_ids: tuple[str, ...]
    issue_decisions: tuple[FrozenMap, ...]
    kernel_quality_issues: tuple[FrozenMap, ...]
    kernel_gate_status: str
    kernel_gate_scope: str
    kernel_route_effect_by_method: FrozenMap
    kernel_execution_compatibility_by_method: FrozenMap
    kernel_incompatibility_reason_codes: FrozenMap
    unresolved_material_issue_ids: tuple[str, ...]
    status: str
    status_by_method: FrozenMap
    missing_evidence: tuple[str, ...]
    reason_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        _policy_identity(self.policy_id, self.policy_version, self.policy_sha256)
        if (
            not isinstance(self.reconciliation_result, AccountingReconciliationResult)
            or self.reconciliation_result.fingerprint != self.reconciliation_fingerprint
            or self.reconciliation_result.issuer_id != self.issuer_id
            or self.reconciliation_result.data_cutoff_date != self.data_cutoff_date
        ):
            raise ValueError("accounting quality reconciliation binding does not replay")
        reconciliation_facts = _ledger_fact_map(self.reconciliation_result.ledger_payload)
        ledger_payload = _canonical_ledger_payload(self.ledger_payload)
        object.__setattr__(self, "ledger_payload", ledger_payload)
        _validate_ledger_identity(
            ledger_payload,
            issuer_id=self.issuer_id,
            data_cutoff_date=self.data_cutoff_date,
        )
        quality_facts = _ledger_fact_map(ledger_payload)
        reconciliation_sources = {
            item["source_id"]: item for item in self.reconciliation_result.ledger_payload["sources"]
        }
        quality_sources = {item["source_id"]: item for item in ledger_payload["sources"]}
        if quality_sources != reconciliation_sources or any(
            quality_facts.get(key) != value for key, value in reconciliation_facts.items()
        ):
            raise ValueError("accounting quality ledger does not preserve reconciliation evidence")
        adjustments = tuple(
            sorted(self.adjustment_decisions, key=lambda item: (item.method, item.adjustment_id))
        )
        if any(not isinstance(item, MethodAdjustmentDecision) for item in adjustments):
            raise ValueError("accounting quality compilation requires adjustment decisions")
        _unique(tuple(item.adjustment_id for item in adjustments), "quality adjustment IDs")
        compiled_adjustments = tuple(item for item in adjustments if item.disposition == "compiled")
        if any(item.target_bridge_role is not None for item in compiled_adjustments):
            raise ValueError("Phase 5C-2 adjustments cannot pre-empt equity-bridge review")
        added_fact_ids = set(quality_facts).difference(reconciliation_facts)
        expected_added_fact_ids = {
            item.amount_fact_id for item in compiled_adjustments if item.amount_fact_id is not None
        }
        if added_fact_ids != expected_added_fact_ids:
            raise ValueError("accounting quality ledger additions do not match adjustment outputs")
        reconciliation_outputs = {
            FORMULA_POLICIES[item.purpose].output_concept: item.output_fact_id
            for item in self.reconciliation_result.fact_decisions
            if item.disposition == "emitted" and item.output_fact_id is not None
        }
        trusted_derived_fact_ids = {
            item["fact_id"]
            for item in self.reconciliation_result.phase5b_mapping_result.ledger_payload["facts"]
        } | {
            item.output_fact_id
            for item in self.reconciliation_result.fact_decisions
            if item.disposition == "emitted" and item.output_fact_id is not None
        }
        for decision in compiled_adjustments:
            _validate_compiled_adjustment(
                decision,
                ledger_facts=quality_facts,
                predecessor_fact_ids=set(reconciliation_facts),
                trusted_derived_fact_ids=trusted_derived_fact_ids,
                reconciliation_outputs=reconciliation_outputs,
                reporting_currency=ledger_payload["reporting_currency"],
            )
        object.__setattr__(self, "adjustment_decisions", adjustments)
        if not isinstance(self.accounting_quality_review, AccountingQualityReview):
            raise ValueError("accounting quality compilation requires the current Review object")
        findings = tuple(sorted(self.accounting_quality_findings, key=lambda item: item.finding_id))
        if any(not isinstance(item, AccountingQualityFinding) for item in findings):
            raise ValueError("accounting quality compilation requires Finding objects")
        _unique(tuple(item.finding_id for item in findings), "accounting quality Findings")
        review = self.accounting_quality_review
        if (
            review.review_id != self.accounting_quality_review_id
            or review.fingerprint != self.accounting_quality_review_fingerprint
            or review.status != self.accounting_quality_review_status
            or review.issuer_id != self.issuer_id
            or any(item.issuer_id != self.issuer_id for item in findings)
            or set(review.finding_ids) != {item.finding_id for item in findings}
            or set(self.expected_finding_ids) != set(review.finding_ids)
        ):
            raise ValueError("accounting quality Review/Finding binding does not replay")
        object.__setattr__(self, "accounting_quality_findings", findings)
        if (
            not self.issuer_id
            or not self.accounting_quality_review_id
            or not self.accounting_quality_review_fingerprint
        ):
            raise ValueError("accounting quality compilation identity is required")
        if self.accounting_quality_review_status not in {"complete", "partial", "blocked"}:
            raise ValueError("accounting quality Review status is invalid")
        if self.kernel_gate_status not in {"pass", "blocked"}:
            raise ValueError("kernel accounting quality gate status is invalid")
        if self.kernel_gate_scope != "global":
            raise ValueError("pinned kernel accounting quality gate scope must be global")
        if self.status not in COMPILATION_STATUSES:
            raise ValueError("accounting quality compilation status is invalid")
        decisions = tuple(_closed_quality_decision(item) for item in self.issue_decisions)
        issues = tuple(_closed_kernel_issue(item) for item in self.kernel_quality_issues)
        _sort_unique(self, "expected_finding_ids", "expected accounting quality Findings")
        _unique(tuple(item["finding_id"] for item in decisions), "quality Finding decisions")
        _unique(tuple(item["issue_id"] for item in issues), "kernel quality issues")
        object.__setattr__(
            self, "issue_decisions", tuple(sorted(decisions, key=lambda item: item["finding_id"]))
        )
        object.__setattr__(
            self, "kernel_quality_issues", tuple(sorted(issues, key=lambda item: item["issue_id"]))
        )
        if {item["finding_id"] for item in decisions} != set(self.expected_finding_ids):
            raise ValueError("accounting quality decisions do not cover the current Review")
        finding_by_id = {item.finding_id: item for item in findings}
        for decision in decisions:
            finding = finding_by_id[decision["finding_id"]]
            if (
                decision["finding_fingerprint"] != finding.fingerprint
                or decision["finding_status"] != finding.status
                or decision["final_severity"] != finding.final_severity
                or decision["category"] != finding.category
                or set(decision["evidence_fact_ids"]) != set(finding.fact_ids)
                or (
                    decision["claim_id"] is not None
                    and decision["claim_id"] not in set(finding.claim_ids)
                )
            ):
                raise ValueError("accounting quality decision does not replay its Finding")
        quality_evidence_fact_ids = {
            fact_id for item in decisions for fact_id in item["evidence_fact_ids"]
        }
        _require_ledger_facts(
            quality_evidence_fact_ids,
            reconciliation_facts,
            "accounting quality evidence",
        )
        for field_name in ("unresolved_material_issue_ids", "missing_evidence"):
            _sort_unique(self, field_name, f"accounting quality {field_name}")
        _reason_codes(self)
        unresolved = {
            item["finding_id"]
            for item in self.issue_decisions
            if item["disposition"] == "material_unresolved"
        }
        if unresolved != set(self.unresolved_material_issue_ids):
            raise ValueError("unresolved material issue coverage is inconsistent")
        eligible = {
            item["finding_id"]: item
            for item in self.issue_decisions
            if item["disposition"] in {"material_unresolved", "resolved", "nonmaterial"}
        }
        kernel_by_id = {item["issue_id"]: item for item in self.kernel_quality_issues}
        if set(kernel_by_id) != set(eligible):
            raise ValueError("kernel accounting-quality issues do not round-trip decisions")
        for issue_id, decision in eligible.items():
            issue = kernel_by_id[issue_id]
            if (
                issue["category"] != decision["category"]
                or issue["material"] is not decision["material"]
                or issue["resolved"] is not decision["resolved"]
                or tuple(issue["evidence_fact_ids"]) != tuple(decision["evidence_fact_ids"])
            ):
                raise ValueError("kernel accounting-quality issue payload drifted")
        expected_gate = (
            "blocked"
            if any(item["material"] and not item["resolved"] for item in kernel_by_id.values())
            else "pass"
        )
        if self.kernel_gate_status != expected_gate:
            raise ValueError("kernel accounting-quality gate status is inconsistent")
        incomplete = any(
            item["disposition"] in {"provisional", "blocked"} for item in self.issue_decisions
        )
        if self.accounting_quality_review_status != "complete":
            incomplete = True
        if self.status == "pass" and (unresolved or incomplete or self.missing_evidence):
            raise ValueError("accounting quality pass cannot omit unresolved evidence")
        if self.kernel_gate_status == "blocked" and self.status != "blocked":
            raise ValueError("blocked kernel quality gate requires blocked result")
        expected_status = (
            "blocked"
            if self.kernel_gate_status == "blocked"
            or self.accounting_quality_review_status == "blocked"
            or any(item["disposition"] == "blocked" for item in self.issue_decisions)
            else "partial"
            if incomplete or self.missing_evidence
            else "pass"
        )
        if self.status != expected_status:
            raise ValueError("accounting quality compilation status is not deterministic")
        statuses = freeze(self.status_by_method)
        if set(statuses) != set(METHODS) or not set(statuses.values()).issubset(
            COMPILATION_STATUSES
        ):
            raise ValueError("accounting quality method status coverage is invalid")
        for method in METHODS:
            applicable = tuple(
                item
                for item in self.issue_decisions
                if method in ACCOUNTING_QUALITY_METHOD_APPLICABILITY[item["category"]]
            )
            expected_method_status = (
                "blocked"
                if self.accounting_quality_review_status == "blocked"
                or any(
                    item["disposition"] in {"material_unresolved", "blocked"} for item in applicable
                )
                else "partial"
                if self.accounting_quality_review_status == "partial"
                or self.missing_evidence
                or any(item["disposition"] == "provisional" for item in applicable)
                else "pass"
            )
            if statuses[method] != expected_method_status:
                raise ValueError("accounting quality method status is not deterministic")
        object.__setattr__(self, "status_by_method", statuses)
        route_effect = freeze(self.kernel_route_effect_by_method)
        expected_route_effect = {
            "mckinsey": "not_blocked_by_quality_gate",
            "penman": (
                "blocked_by_quality_gate"
                if self.kernel_gate_status == "blocked"
                else "not_blocked_by_quality_gate"
            ),
        }
        if dict(route_effect) != expected_route_effect:
            raise ValueError("pinned kernel accounting-quality route effect drifted")
        object.__setattr__(self, "kernel_route_effect_by_method", route_effect)
        compatibility = freeze(self.kernel_execution_compatibility_by_method)
        expected_compatibility = {
            method: (
                (statuses[method] == "blocked")
                == (expected_route_effect[method] == "blocked_by_quality_gate")
            )
            for method in METHODS
        }
        if dict(compatibility) != expected_compatibility:
            raise ValueError("kernel execution compatibility is not deterministic")
        object.__setattr__(self, "kernel_execution_compatibility_by_method", compatibility)
        raw_reasons = freeze(self.kernel_incompatibility_reason_codes)
        if set(raw_reasons) != set(METHODS):
            raise ValueError("kernel incompatibility reason coverage is incomplete")
        normalized_reasons: dict[str, tuple[str, ...]] = {}
        for method in METHODS:
            reasons = tuple(sorted(raw_reasons[method]))
            _unique(reasons, f"kernel incompatibility reasons for {method}")
            expected_reasons: tuple[str, ...] = ()
            if not expected_compatibility[method]:
                expected_reasons = (
                    ("pinned_kernel_quality_gate_underblocks_mckinsey",)
                    if method == "mckinsey"
                    else ("pinned_kernel_global_gate_overblocks_penman",)
                )
            if reasons != expected_reasons:
                raise ValueError("kernel incompatibility reasons are not deterministic")
            normalized_reasons[method] = reasons
        object.__setattr__(
            self,
            "kernel_incompatibility_reason_codes",
            freeze(normalized_reasons),
        )
        if self.status == "pass" and self.reason_codes:
            raise ValueError("passing accounting quality result cannot retain blocking reasons")
        if self.status != "pass" and not self.reason_codes:
            raise ValueError("partial or blocked accounting quality result requires a reason")

    @property
    def fingerprint(self) -> str:
        return _fingerprint(self)

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)


@dataclass(frozen=True, slots=True)
class MethodAdjustmentDecision:
    method: str
    adjustment_id: str
    adjustment_group_id: str
    category: str
    disposition: str
    target_fact_id: str | None
    target_concept: str | None
    target_bridge_role: str | None
    amount_fact_id: str | None
    source_fact_ids: tuple[str, ...]
    root_fact_ids: tuple[str, ...]
    evidence_source_ids: tuple[str, ...]
    calculation_id: str | None
    calculator_id: str | None
    calculator_version: str | None
    calculator_code_sha256: str | None
    assumption_ids: tuple[str, ...]
    rationale: str
    reason_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.method not in METHODS:
            raise ValueError("method adjustment method is not registered")
        if self.category not in METHOD_ADJUSTMENT_CATEGORIES:
            raise ValueError("method adjustment category is not registered")
        if self.disposition not in METHOD_ADJUSTMENT_DISPOSITIONS:
            raise ValueError("method adjustment disposition is not registered")
        if not self.adjustment_id or not self.adjustment_group_id or not self.rationale.strip():
            raise ValueError("method adjustment identity and rationale are required")
        for field_name in (
            "source_fact_ids",
            "root_fact_ids",
            "evidence_source_ids",
            "assumption_ids",
        ):
            _sort_unique(self, field_name, f"method adjustment {field_name}")
        _reason_codes(self)
        if self.disposition == "compiled":
            if not all(
                (
                    self.target_fact_id,
                    self.target_concept,
                    self.amount_fact_id,
                    self.source_fact_ids,
                    self.root_fact_ids,
                    self.evidence_source_ids,
                    self.calculation_id,
                    self.calculator_id,
                    self.calculator_version,
                    self.calculator_code_sha256,
                )
            ):
                raise ValueError(
                    "compiled adjustment requires target, calculator, amount Fact, and lineage"
                )
            calculator = METHOD_ADJUSTMENT_CALCULATOR_POLICY
            if (
                self.calculator_id != calculator.calculator_id
                or self.calculator_version != calculator.calculator_version
                or self.calculator_code_sha256 != calculator.calculator_code_sha256
                or self.assumption_ids
            ):
                raise ValueError("compiled adjustment calculator identity is not registered")
            policy = method_target_policy(self.method)
            if self.target_concept in policy.allowed_concepts:
                if self.target_bridge_role is not None:
                    raise ValueError("method base target cannot claim an equity-bridge role")
            else:
                concept_policy = ACCOUNT_CONCEPT_POLICIES.get(self.target_concept)
                if (
                    self.method != "mckinsey"
                    or not policy.allows_modeled_bridge_facts
                    or self.target_bridge_role not in policy.allowed_bridge_roles
                    or concept_policy is None
                    or concept_policy.bridge_role != self.target_bridge_role
                ):
                    raise ValueError("method adjustment target is not allowed")
            if self.reason_codes:
                raise ValueError("compiled adjustment cannot retain blocking reasons")
        else:
            if any(
                item is not None
                for item in (
                    self.target_fact_id,
                    self.target_concept,
                    self.target_bridge_role,
                    self.amount_fact_id,
                    self.calculation_id,
                    self.calculator_id,
                    self.calculator_version,
                    self.calculator_code_sha256,
                )
            ):
                raise ValueError(
                    "non-compiled adjustment cannot expose target, calculator, or amount output"
                )
            if self.assumption_ids:
                raise ValueError("non-compiled adjustment cannot retain Assumption inputs")
            if self.disposition == "blocked" and not self.reason_codes:
                raise ValueError("blocked method adjustment requires a reason")

    @property
    def fingerprint(self) -> str:
        return _fingerprint(self)


def _validate_compiled_adjustment(
    decision: MethodAdjustmentDecision,
    *,
    ledger_facts: dict[str, FrozenMap],
    predecessor_fact_ids: set[str],
    trusted_derived_fact_ids: set[str],
    reconciliation_outputs: dict[str, str | None],
    reporting_currency: str,
) -> None:
    if decision.disposition != "compiled":
        return
    predecessor_ids = {
        decision.target_fact_id,
        *decision.source_fact_ids,
        *decision.root_fact_ids,
    }
    if not predecessor_ids.issubset(predecessor_fact_ids):
        raise ValueError("quality adjustment evidence was not frozen by reconciliation")
    _require_ledger_facts(
        {*predecessor_ids, decision.amount_fact_id},
        ledger_facts,
        "compiled quality adjustment",
    )
    target_fact = ledger_facts[decision.target_fact_id]
    amount_fact = ledger_facts[decision.amount_fact_id]
    target_policy = ACCOUNT_CONCEPT_POLICIES[decision.target_concept]
    if (
        decision.target_bridge_role is None
        and reconciliation_outputs.get(decision.target_concept) != decision.target_fact_id
    ):
        raise ValueError("method-view base target does not replay accounting reconciliation")
    if (
        target_fact.get("concept") != decision.target_concept
        or target_fact.get("category") != target_policy.kernel_category
        or target_fact.get("equity_bridge_role") != decision.target_bridge_role
        or target_fact.get("currency") != reporting_currency
        or target_fact.get("unit") != f"{reporting_currency} millions"
        or target_policy.period_kind != "stock"
        or target_fact.get("period_start") is not None
    ):
        raise ValueError("method-view target Fact semantics are invalid")
    calculator = METHOD_ADJUSTMENT_CALCULATOR_POLICY
    if (
        amount_fact.get("concept") != "method_adjustment_amount"
        or amount_fact.get("category") != "evidence"
        or amount_fact.get("raw") is not False
        or set(amount_fact.get("parent_fact_ids", ())) != set(decision.source_fact_ids)
        or amount_fact.get("derivation") != calculator.derivation_label
        or amount_fact.get("currency") != reporting_currency
        or amount_fact.get("unit") != f"{reporting_currency} millions"
    ):
        raise ValueError("quality adjustment output lineage is not registered")
    source_facts = [ledger_facts[fact_id] for fact_id in decision.source_fact_ids]
    if any(
        item.get("raw") is not True and item["fact_id"] not in trusted_derived_fact_ids
        for item in source_facts
    ):
        raise ValueError("method-view adjustment source derivation is not trusted")
    category_policy = method_adjustment_category_policy(decision.category)
    if category_policy.requires_phase5d_judgment or any(
        item.get("concept") not in category_policy.permitted_source_concepts
        or item.get("category") != ACCOUNT_CONCEPT_POLICIES[item["concept"]].kernel_category
        or item.get("category") not in calculator.permitted_input_categories
        or item.get("currency") != reporting_currency
        or item.get("unit") != f"{reporting_currency} millions"
        for item in source_facts
    ):
        raise ValueError("method-view adjustment sources do not match the registered category")
    values = [amount_fact.get("value"), *(item.get("value") for item in source_facts)]
    if any(
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        for value in values
    ) or not math.isclose(
        float(amount_fact["value"]),
        sum(float(item["value"]) for item in source_facts),
        rel_tol=0.0,
        abs_tol=1e-12,
    ):
        raise ValueError("method-view adjustment amount does not replay its calculator")
    source_roots = _replayed_raw_roots(decision.source_fact_ids, ledger_facts)
    if source_roots != set(decision.root_fact_ids) or any(
        _ultimate_raw_roots(root_id, ledger_facts) != {root_id}
        for root_id in decision.root_fact_ids
    ):
        raise ValueError("method-view adjustment roots do not replay source lineage")
    if _ultimate_raw_roots(decision.target_fact_id, ledger_facts).intersection(
        decision.root_fact_ids
    ):
        raise ValueError("method-view target cannot consume its own adjustment roots")
    period_keys = {
        (
            ledger_facts[fact_id].get("period_start"),
            ledger_facts[fact_id].get("period_end"),
            ledger_facts[fact_id].get("as_of_date"),
        )
        for fact_id in {
            decision.target_fact_id,
            decision.amount_fact_id,
            *decision.source_fact_ids,
            *decision.root_fact_ids,
        }
    }
    if len(period_keys) != 1:
        raise ValueError("method-view adjustment periods are inconsistent")
    source_ids = {
        ledger_facts[fact_id].get("source_id")
        for fact_id in {
            decision.amount_fact_id,
            *decision.source_fact_ids,
            *decision.root_fact_ids,
        }
    }
    if (
        None in source_ids
        or len(source_ids) != 1
        or source_ids != set(decision.evidence_source_ids)
    ):
        raise ValueError("method-view evidence sources do not replay ledger lineage")


def _closed_consumption(raw: Any) -> FrozenMap:
    item = freeze(raw)
    required = {
        "root_fact_id",
        "economic_claim_key",
        "economic_identity",
        "channel",
        "method",
        "group_id",
        "consumption_kind",
    }
    if set(item) != required:
        raise ValueError("root consumption record has invalid fields")
    if item["method"] not in METHODS:
        raise ValueError("root consumption method is invalid")
    if item["consumption_kind"] not in {"validation", "economic_deduction", "method_base"}:
        raise ValueError("root consumption kind is invalid")
    if not all(
        item[field]
        for field in (
            "root_fact_id",
            "economic_claim_key",
            "economic_identity",
            "channel",
            "group_id",
        )
    ):
        raise ValueError("root consumption identity is required")
    policy = CROSS_CHANNEL_POLICIES.get(item["economic_identity"])
    if policy is None:
        raise ValueError("root consumption economic identity is not registered")
    permitted_channels = (
        policy.validation_channels
        if item["consumption_kind"] == "validation"
        else policy.economic_channels
    )
    if item["channel"] not in permitted_channels:
        raise ValueError("root consumption channel is not registered for its identity")
    expected_method = (
        "mckinsey"
        if item["channel"].startswith("mckinsey_")
        else "penman"
        if item["channel"].startswith("penman_")
        else item["method"]
    )
    if item["method"] != expected_method:
        raise ValueError("root consumption channel conflicts with method")
    return item


def _economic_binding_index(
    reconciliation: AccountingReconciliationResult,
) -> dict[str, FrozenMap]:
    result: dict[str, FrozenMap] = {}
    for binding in reconciliation.economic_claim_bindings:
        for root_id in binding["root_fact_ids"]:
            if root_id in result:
                raise ValueError("economic claim root is bound more than once")
            result[root_id] = binding
    return result


def _claim_records_for_roots(
    *,
    root_ids: set[str],
    binding_index: dict[str, FrozenMap],
    channel: str,
    method: str,
    group_id: str,
    consumption_kind: str,
) -> set[tuple[str, str, str, str, str, str, str]]:
    records: set[tuple[str, str, str, str, str, str, str]] = set()
    grouped: dict[str, set[str]] = {}
    for root_id in root_ids:
        binding = binding_index.get(root_id)
        if binding is None or binding["status"] != "confirmed":
            raise ValueError("economic claim identity is unresolved for method consumption")
        grouped.setdefault(binding["binding_id"], set()).add(root_id)
    for binding_id, consumed_roots in grouped.items():
        binding = next(item for item in binding_index.values() if item["binding_id"] == binding_id)
        if (
            consumed_roots != set(binding["root_fact_ids"])
            and binding["economic_identity"] != "method_base"
        ):
            raise ValueError("economic claim treatment consumes only part of its root set")
        for root_id in consumed_roots:
            records.add(
                (
                    root_id,
                    binding["economic_claim_key"],
                    binding["economic_identity"],
                    channel,
                    method,
                    group_id,
                    consumption_kind,
                )
            )
    return records


def _closed_method_view_entry(raw: Any) -> FrozenMap:
    item = freeze(raw)
    required = {
        "adjustment_id",
        "target_fact_id",
        "target_concept",
        "target_bridge_role",
        "amount_fact_id",
    }
    if set(item) != required or not all(
        item[field]
        for field in ("adjustment_id", "target_fact_id", "target_concept", "amount_fact_id")
    ):
        raise ValueError("method-view adjustment entry is invalid")
    return item


@dataclass(frozen=True, slots=True)
class MethodViewCompilationResult:
    issuer_id: str
    data_cutoff_date: str
    reconciliation_fingerprint: str
    reconciliation_result: AccountingReconciliationResult
    quality_fingerprint: str
    quality_result: AccountingQualityCompilationResult
    policy_id: str
    policy_version: str
    policy_sha256: str
    ledger_payload: FrozenMap
    adjustment_decisions: tuple[MethodAdjustmentDecision, ...]
    method_views: FrozenMap
    consumption_records: tuple[FrozenMap, ...]
    status_by_method: FrozenMap
    reason_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        _policy_identity(self.policy_id, self.policy_version, self.policy_sha256)
        if not self.issuer_id:
            raise ValueError("method-view compilation issuer is required")
        normalized_adjustments = tuple(
            sorted(
                self.adjustment_decisions,
                key=lambda item: (item.method, item.adjustment_id),
            )
        )
        if (
            not isinstance(self.reconciliation_result, AccountingReconciliationResult)
            or not isinstance(self.quality_result, AccountingQualityCompilationResult)
            or self.reconciliation_result.fingerprint != self.reconciliation_fingerprint
            or self.quality_result.fingerprint != self.quality_fingerprint
            or self.quality_result.reconciliation_fingerprint != self.reconciliation_fingerprint
            or self.reconciliation_result.issuer_id != self.issuer_id
            or self.quality_result.issuer_id != self.issuer_id
            or self.reconciliation_result.data_cutoff_date != self.data_cutoff_date
            or self.quality_result.data_cutoff_date != self.data_cutoff_date
            or self.quality_result.adjustment_decisions != normalized_adjustments
        ):
            raise ValueError("method-view predecessor binding does not replay")
        ledger_payload = _canonical_ledger_payload(self.ledger_payload)
        object.__setattr__(self, "ledger_payload", ledger_payload)
        if self.quality_result.ledger_payload != ledger_payload:
            raise ValueError("method-view ledger does not replay accounting quality outputs")
        _validate_ledger_identity(
            ledger_payload,
            issuer_id=self.issuer_id,
            data_cutoff_date=self.data_cutoff_date,
        )
        reconciliation_sources = {
            item["source_id"]: item for item in self.reconciliation_result.ledger_payload["sources"]
        }
        method_sources = {item["source_id"]: item for item in ledger_payload["sources"]}
        reconciliation_facts = {
            item["fact_id"]: item for item in self.reconciliation_result.ledger_payload["facts"]
        }
        method_facts = {item["fact_id"]: item for item in ledger_payload["facts"]}
        sources_drifted = any(
            method_sources.get(key) != value for key, value in reconciliation_sources.items()
        )
        facts_drifted = any(
            method_facts.get(key) != value for key, value in reconciliation_facts.items()
        )
        if sources_drifted or facts_drifted:
            raise ValueError("MethodView ledger does not preserve accounting reconciliation")
        ledger_facts = _ledger_fact_map(ledger_payload)
        decisions = normalized_adjustments
        _unique(tuple(item.adjustment_id for item in decisions), "method adjustment IDs")
        compiled_decisions = tuple(item for item in decisions if item.disposition == "compiled")
        _unique(
            tuple(
                f"{item.method}:{item.category}:{item.target_fact_id}"
                for item in compiled_decisions
            ),
            "method category-target pairs",
        )
        _unique(
            tuple(
                f"{item.method}:{item.adjustment_group_id}:{item.target_fact_id}"
                for item in compiled_decisions
            ),
            "method group-target pairs",
        )
        _unique(
            tuple(
                item.calculation_id
                for item in decisions
                if item.disposition == "compiled" and item.calculation_id is not None
            ),
            "method adjustment calculation IDs",
        )
        object.__setattr__(self, "adjustment_decisions", decisions)
        raw_views = freeze(self.method_views)
        if set(raw_views) != set(METHODS):
            raise ValueError("method views must contain exactly McKinsey and Penman")
        views: dict[str, tuple[FrozenMap, ...]] = {}
        for method in METHODS:
            entries = tuple(_closed_method_view_entry(item) for item in raw_views[method])
            entries = tuple(sorted(entries, key=lambda item: item["adjustment_id"]))
            _unique(tuple(item["adjustment_id"] for item in entries), f"{method} view adjustments")
            compiled = {
                item.adjustment_id: item
                for item in decisions
                if item.method == method and item.disposition == "compiled"
            }
            if set(compiled) != {item["adjustment_id"] for item in entries}:
                raise ValueError("method-view payload does not match compiled decisions")
            for entry in entries:
                decision = compiled[entry["adjustment_id"]]
                if (
                    entry["target_fact_id"] != decision.target_fact_id
                    or entry["target_concept"] != decision.target_concept
                    or entry["target_bridge_role"] != decision.target_bridge_role
                    or entry["amount_fact_id"] != decision.amount_fact_id
                ):
                    raise ValueError("method-view entry does not replay its decision")
            views[method] = entries
        object.__setattr__(self, "method_views", freeze(views))
        statuses = freeze(self.status_by_method)
        if set(statuses) != set(METHODS) or not set(statuses.values()).issubset(
            COMPILATION_STATUSES
        ):
            raise ValueError("method-view status coverage is invalid")
        object.__setattr__(self, "status_by_method", statuses)
        records = tuple(_closed_consumption(item) for item in self.consumption_records)
        records = tuple(
            sorted(
                records,
                key=lambda item: (
                    item["root_fact_id"],
                    item["method"],
                    item["economic_claim_key"],
                    item["economic_identity"],
                    item["channel"],
                    item["group_id"],
                    item["consumption_kind"],
                ),
            )
        )
        keys = tuple(
            f"{item['root_fact_id']}:{item['economic_claim_key']}:{item['economic_identity']}:{item['channel']}:{item['method']}:{item['group_id']}"
            for item in records
        )
        _unique(keys, "root consumption records")
        treatments_by_claim: dict[tuple[str, str], set[tuple[str, str, str]]] = {}
        for item in records:
            if item["consumption_kind"] == "validation":
                continue
            treatments_by_claim.setdefault((item["method"], item["economic_claim_key"]), set()).add(
                (item["channel"], item["group_id"], item["consumption_kind"])
            )
        if any(len(treatments) > 1 for treatments in treatments_by_claim.values()):
            raise ValueError("economic claim is consumed more than once by one method")
        _require_ledger_facts(
            {item["root_fact_id"] for item in records},
            ledger_facts,
            "root consumption records",
        )
        expected_economic_records: set[tuple[str, str, str, str, str, str, str]] = set()
        referenced_fact_ids: set[str] = set()
        binding_index = _economic_binding_index(self.reconciliation_result)
        reconciliation_outputs = {
            FORMULA_POLICIES[item.purpose].output_concept: item.output_fact_id
            for item in self.reconciliation_result.fact_decisions
            if item.disposition == "emitted" and item.output_fact_id is not None
        }
        base_groups = (
            (
                "mckinsey",
                "mckinsey_invested_capital",
                "method-base:mckinsey:invested-capital",
                ("invested_capital",),
            ),
            (
                "penman",
                "penman_noa_nfo",
                "method-base:penman:noa-nfo",
                ("net_operating_assets", "net_financial_obligations"),
            ),
        )
        for method, channel, group_id, concepts in base_groups:
            fact_ids = {
                reconciliation_outputs[concept]
                for concept in concepts
                if reconciliation_outputs.get(concept) is not None
            }
            roots = {
                root_id
                for fact_id in fact_ids
                for root_id in _ultimate_raw_roots(fact_id, ledger_facts)
            }
            roots_by_channel: dict[str, set[str]] = {}
            for root_id in roots:
                identity = binding_index[root_id]["economic_identity"]
                effective_channel = (
                    "penman_nfo" if method == "penman" and identity != "method_base" else channel
                )
                roots_by_channel.setdefault(effective_channel, set()).add(root_id)
            for effective_channel, channel_roots in roots_by_channel.items():
                expected_economic_records.update(
                    _claim_records_for_roots(
                        root_ids=channel_roots,
                        binding_index=binding_index,
                        channel=effective_channel,
                        method=method,
                        group_id=group_id,
                        consumption_kind="method_base",
                    )
                )
        for decision in decisions:
            if decision.disposition != "compiled":
                continue
            referenced_fact_ids.update(
                (
                    decision.target_fact_id,
                    decision.amount_fact_id,
                    *decision.source_fact_ids,
                    *decision.root_fact_ids,
                )
            )
            target_fact = ledger_facts.get(decision.target_fact_id)
            amount_fact = ledger_facts.get(decision.amount_fact_id)
            calculator = METHOD_ADJUSTMENT_CALCULATOR_POLICY
            target_policy = ACCOUNT_CONCEPT_POLICIES.get(decision.target_concept)
            if (
                decision.target_bridge_role is None
                and reconciliation_outputs.get(decision.target_concept) != decision.target_fact_id
            ):
                raise ValueError(
                    "method-view base target does not replay accounting reconciliation"
                )
            if (
                target_fact is None
                or target_policy is None
                or target_fact.get("concept") != decision.target_concept
                or target_fact.get("category") != target_policy.kernel_category
                or target_fact.get("equity_bridge_role") != decision.target_bridge_role
                or target_fact.get("currency") != ledger_payload["reporting_currency"]
                or target_fact.get("unit") != f"{ledger_payload['reporting_currency']} millions"
                or target_policy.period_kind != "stock"
                or target_fact.get("period_start") is not None
                or isinstance(target_fact.get("value"), bool)
                or not isinstance(target_fact.get("value"), (int, float))
                or not math.isfinite(float(target_fact["value"]))
            ):
                raise ValueError("method-view target Fact semantics are invalid")
            if (
                amount_fact is None
                or amount_fact.get("concept") != "method_adjustment_amount"
                or amount_fact.get("category") != "evidence"
                or amount_fact.get("raw") is not False
                or set(amount_fact.get("parent_fact_ids", ())) != set(decision.source_fact_ids)
                or amount_fact.get("derivation") != calculator.derivation_label
                or amount_fact.get("currency") != ledger_payload["reporting_currency"]
                or amount_fact.get("unit") != f"{ledger_payload['reporting_currency']} millions"
                or isinstance(amount_fact.get("value"), bool)
                or not isinstance(amount_fact.get("value"), (int, float))
                or not math.isfinite(float(amount_fact["value"]))
            ):
                raise ValueError("method-view adjustment amount lineage is invalid")
            source_facts = [ledger_facts[fact_id] for fact_id in decision.source_fact_ids]
            category_policy = method_adjustment_category_policy(decision.category)
            if any(
                item.get("concept") not in ACCOUNT_CONCEPT_POLICIES
                or item.get("category") != ACCOUNT_CONCEPT_POLICIES[item["concept"]].kernel_category
                or item.get("category") not in calculator.permitted_input_categories
                or item.get("currency") != ledger_payload["reporting_currency"]
                or item.get("unit") != f"{ledger_payload['reporting_currency']} millions"
                or isinstance(item.get("value"), bool)
                or not isinstance(item.get("value"), (int, float))
                or not math.isfinite(float(item["value"]))
                for item in source_facts
            ):
                raise ValueError("method-view adjustment source semantics are invalid")
            if category_policy.requires_phase5d_judgment or any(
                item.get("concept") not in category_policy.permitted_source_concepts
                for item in source_facts
            ):
                raise ValueError(
                    "method-view adjustment sources do not match the registered category"
                )
            if not math.isclose(
                float(amount_fact["value"]),
                sum(float(item["value"]) for item in source_facts),
                rel_tol=0.0,
                abs_tol=1e-12,
            ):
                raise ValueError("method-view adjustment amount does not replay its calculator")
            source_roots = _replayed_raw_roots(decision.source_fact_ids, ledger_facts)
            if source_roots != set(decision.root_fact_ids) or any(
                _ultimate_raw_roots(root_id, ledger_facts) != {root_id}
                for root_id in decision.root_fact_ids
            ):
                raise ValueError("method-view adjustment roots do not replay source lineage")
            method_base_concepts = (
                ("invested_capital",)
                if decision.method == "mckinsey"
                else ("net_operating_assets", "net_financial_obligations")
            )
            base_fact_ids = {
                reconciliation_outputs[concept]
                for concept in method_base_concepts
                if reconciliation_outputs.get(concept) is not None
            }
            base_roots = {
                root
                for fact_id in base_fact_ids
                for root in _ultimate_raw_roots(fact_id, ledger_facts)
            }
            if base_roots.intersection(decision.root_fact_ids):
                raise ValueError(
                    "method-view adjustment cannot consume any root already in its method base"
                )
            identities = {
                binding_index[root_fact_id]["economic_identity"]
                for root_fact_id in decision.root_fact_ids
            }
            channels = {
                (
                    "mckinsey_equity_bridge"
                    if decision.method == "mckinsey" and identity != "method_base"
                    else "mckinsey_invested_capital"
                    if decision.method == "mckinsey"
                    else "penman_nfo"
                    if identity != "method_base"
                    else "penman_noa_nfo"
                )
                for identity in identities
            }
            if len(channels) != 1:
                raise ValueError("method adjustment group mixes economic channels")
            expected_economic_records.update(
                _claim_records_for_roots(
                    root_ids=set(decision.root_fact_ids),
                    binding_index=binding_index,
                    channel=next(iter(channels)),
                    method=decision.method,
                    group_id=decision.adjustment_group_id,
                    consumption_kind="economic_deduction",
                )
            )
            period_keys = {
                (
                    ledger_facts[fact_id].get("period_start"),
                    ledger_facts[fact_id].get("period_end"),
                    ledger_facts[fact_id].get("as_of_date"),
                )
                for fact_id in decision.root_fact_ids
            }
            period_keys.add(
                (
                    target_fact.get("period_start"),
                    target_fact.get("period_end"),
                    target_fact.get("as_of_date"),
                )
            )
            period_keys.update(
                (
                    item.get("period_start"),
                    item.get("period_end"),
                    item.get("as_of_date"),
                )
                for item in source_facts
            )
            period_keys.add(
                (
                    amount_fact.get("period_start"),
                    amount_fact.get("period_end"),
                    amount_fact.get("as_of_date"),
                )
            )
            if len(period_keys) != 1:
                raise ValueError("method-view adjustment periods are inconsistent")
            source_ids = {
                ledger_facts[fact_id].get("source_id")
                for fact_id in (
                    *decision.source_fact_ids,
                    *decision.root_fact_ids,
                    decision.amount_fact_id,
                )
            }
            if (
                None in source_ids
                or len(source_ids) != 1
                or source_ids != set(decision.evidence_source_ids)
            ):
                raise ValueError("method-view evidence sources do not replay ledger lineage")
        _require_ledger_facts(referenced_fact_ids, ledger_facts, "method-view compilation")
        actual_economic_records = {
            (
                item["root_fact_id"],
                item["economic_claim_key"],
                item["economic_identity"],
                item["channel"],
                item["method"],
                item["group_id"],
                item["consumption_kind"],
            )
            for item in records
            if item["consumption_kind"] != "validation"
        }
        if actual_economic_records != expected_economic_records:
            raise ValueError("method-view root consumption does not replay compiled decisions")
        object.__setattr__(self, "consumption_records", records)
        _reason_codes(self)
        for method in METHODS:
            blocked = any(
                item.method == method and item.disposition == "blocked" for item in decisions
            )
            expected_status = (
                "blocked"
                if blocked or self.quality_result.status_by_method[method] == "blocked"
                else "partial"
                if self.quality_result.status_by_method[method] == "partial"
                else "pass"
            )
            if self.status_by_method[method] != expected_status:
                raise ValueError("method-view status is not deterministic")
        if set(self.status_by_method.values()) == {"pass"} and self.reason_codes:
            raise ValueError("passing method views cannot retain blocking reasons")
        if (
            any(status != "pass" for status in self.status_by_method.values())
            and not self.reason_codes
        ):
            raise ValueError("partial or blocked method view requires a reason")

    @property
    def fingerprint(self) -> str:
        return _fingerprint(self)

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)


@dataclass(frozen=True, slots=True)
class EquityBridgeRoleDecision:
    role: str
    status: str
    fact_id: str | None
    evidence_fact_ids: tuple[str, ...]
    root_fact_ids: tuple[str, ...]
    claim_id: str | None
    review_decision_id: str | None
    rationale: str
    missing_evidence: tuple[str, ...]
    reason_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.role not in BRIDGE_ROLES:
            raise ValueError("equity-bridge role is not registered")
        if self.status not in BRIDGE_STATES:
            raise ValueError("equity-bridge state is not registered")
        if not self.rationale.strip():
            raise ValueError("equity-bridge rationale is required")
        for field_name in ("evidence_fact_ids", "root_fact_ids", "missing_evidence"):
            _sort_unique(self, field_name, f"equity-bridge {field_name}")
        _reason_codes(self)
        if self.status == "modeled":
            if (
                not self.fact_id
                or self.fact_id not in self.evidence_fact_ids
                or not self.root_fact_ids
            ):
                raise ValueError("modeled bridge role requires one aggregate Fact and lineage")
            if self.claim_id is not None or self.review_decision_id is not None:
                raise ValueError("modeled bridge role cannot use Claim as numeric evidence")
            if self.missing_evidence or self.reason_codes:
                raise ValueError("modeled bridge role cannot retain unresolved evidence")
        elif self.status == "explicitly_absent":
            if self.fact_id is not None or not self.evidence_fact_ids or not self.root_fact_ids:
                raise ValueError("explicit absence requires official numeric zero evidence")
            if self.claim_id is not None or self.review_decision_id is not None:
                raise ValueError("explicit absence does not use narrative Claim evidence")
            if self.missing_evidence:
                raise ValueError("explicit absence cannot retain missing evidence")
            if self.reason_codes:
                raise ValueError("explicit absence cannot retain blocking reasons")
        elif self.status == "not_applicable":
            if self.fact_id is not None or not self.evidence_fact_ids or not self.root_fact_ids:
                raise ValueError("not-applicable bridge role requires mappable official evidence")
            if not self.claim_id or not self.review_decision_id:
                raise ValueError("not-applicable bridge role requires reviewed Claim evidence")
            if self.missing_evidence:
                raise ValueError("not-applicable bridge role cannot retain missing evidence")
            if self.reason_codes:
                raise ValueError("not-applicable bridge role cannot retain blocking reasons")
        else:
            if self.fact_id is not None:
                raise ValueError("unresolved bridge role cannot expose a modeled Fact")
            if not self.missing_evidence or not self.reason_codes:
                raise ValueError("unresolved bridge role requires missing evidence and reason")
            if not set(self.reason_codes).issubset(BRIDGE_UNRESOLVED_REASON_SEVERITY):
                raise ValueError("unresolved bridge role uses a non-bridge reason")

    @property
    def fingerprint(self) -> str:
        return _fingerprint(self)


def _closed_bridge_item(raw: Any) -> FrozenMap:
    item = freeze(raw)
    if set(item) != {"item_id", "fact_id"} or not item["item_id"] or not item["fact_id"]:
        raise ValueError("equity-bridge item is invalid")
    return item


def _closed_bridge_assertion(raw: Any) -> FrozenMap:
    item = _freeze_with_sorted_sequences(
        raw,
        label="equity-bridge assertion",
        sequence_fields=("source_fact_ids",),
    )
    required = {"role", "status", "fact_id", "source_fact_ids", "rationale"}
    if set(item) != required or item["role"] not in BRIDGE_ROLES:
        raise ValueError("equity-bridge assertion is invalid")
    if item["status"] not in BRIDGE_STATES or not item["rationale"]:
        raise ValueError("equity-bridge assertion state is invalid")
    return item


@dataclass(frozen=True, slots=True)
class EquityBridgeCompilationResult:
    issuer_id: str
    data_cutoff_date: str
    reconciliation_fingerprint: str
    method_view_fingerprint: str
    method_view_result: MethodViewCompilationResult
    policy_id: str
    policy_version: str
    policy_sha256: str
    ledger_payload: FrozenMap
    diluted_shares_fact_id: str
    diluted_share_root_fact_ids: tuple[str, ...]
    role_decisions: tuple[EquityBridgeRoleDecision, ...]
    bridge_items: tuple[FrozenMap, ...]
    role_assertions: tuple[FrozenMap, ...]
    consumption_records: tuple[FrozenMap, ...]
    status: str
    kernel_request_compatible: bool
    reason_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        _policy_identity(self.policy_id, self.policy_version, self.policy_sha256)
        if not self.issuer_id or not self.diluted_shares_fact_id:
            raise ValueError("equity-bridge identity and diluted shares are required")
        if self.status not in BRIDGE_COMPILATION_STATUSES:
            raise ValueError("equity-bridge compilation status is invalid")
        ledger_payload = _canonical_ledger_payload(self.ledger_payload)
        object.__setattr__(self, "ledger_payload", ledger_payload)
        _validate_ledger_identity(
            ledger_payload,
            issuer_id=self.issuer_id,
            data_cutoff_date=self.data_cutoff_date,
        )
        ledger_facts = _ledger_fact_map(ledger_payload)
        if not isinstance(self.method_view_result, MethodViewCompilationResult):
            raise ValueError("equity bridge requires the validated MethodView result")
        if (
            self.method_view_result.fingerprint != self.method_view_fingerprint
            or self.method_view_result.issuer_id != self.issuer_id
            or self.method_view_result.data_cutoff_date != self.data_cutoff_date
            or self.method_view_result.reconciliation_fingerprint != self.reconciliation_fingerprint
        ):
            raise ValueError("equity bridge MethodView binding does not replay")
        method_sources = {
            item["source_id"]: item for item in self.method_view_result.ledger_payload["sources"]
        }
        bridge_sources = {item["source_id"]: item for item in ledger_payload["sources"]}
        method_facts = {
            item["fact_id"]: item for item in self.method_view_result.ledger_payload["facts"]
        }
        if any(bridge_sources.get(key) != value for key, value in method_sources.items()) or any(
            ledger_facts.get(key) != value for key, value in method_facts.items()
        ):
            raise ValueError("equity bridge ledger does not preserve MethodView evidence")
        if set(bridge_sources) != set(method_sources):
            raise ValueError("equity bridge cannot introduce a late evidence source")
        method_consumption_records = self.method_view_result.consumption_records
        _sort_unique(self, "diluted_share_root_fact_ids", "diluted-share roots")
        if not self.diluted_share_root_fact_ids:
            raise ValueError("diluted shares require nonempty root lineage")
        _require_ledger_facts(
            {self.diluted_shares_fact_id, *self.diluted_share_root_fact_ids},
            ledger_facts,
            "diluted-share lineage",
        )
        diluted_fact = ledger_facts[self.diluted_shares_fact_id]
        phase5b_mapping = self.method_view_result.reconciliation_result.phase5b_mapping_result
        phase5b_facts = {item["fact_id"]: item for item in phase5b_mapping.ledger_payload["facts"]}
        if phase5b_facts.get(self.diluted_shares_fact_id) != diluted_fact:
            raise ValueError("diluted shares do not replay the Phase 5B mapped Fact")
        diluted_value = diluted_fact.get("value")
        if (
            diluted_fact.get("concept") != "diluted_shares"
            or diluted_fact.get("category") != "share_count"
            or diluted_fact.get("currency") is not None
            or diluted_fact.get("unit") != "millions shares"
            or isinstance(diluted_value, bool)
            or not isinstance(diluted_value, (int, float))
            or not math.isfinite(float(diluted_value))
            or float(diluted_value) <= 0
        ):
            raise ValueError("diluted-share Fact semantics are invalid")
        if diluted_fact.get("raw") is True and set(self.diluted_share_root_fact_ids) != {
            self.diluted_shares_fact_id
        }:
            raise ValueError("raw diluted-share lineage must root in the diluted-share Fact")
        if diluted_fact.get("raw") is False and set(diluted_fact.get("parent_fact_ids", ())) != set(
            self.diluted_share_root_fact_ids
        ):
            raise ValueError("derived diluted-share lineage is incomplete")
        if _ultimate_raw_roots(self.diluted_shares_fact_id, ledger_facts) != set(
            self.diluted_share_root_fact_ids
        ) or any(
            _ultimate_raw_roots(root_id, ledger_facts) != {root_id}
            for root_id in self.diluted_share_root_fact_ids
        ):
            raise ValueError("diluted-share roots do not replay ultimate raw lineage")
        role_map = {item.role: item for item in self.role_decisions}
        if len(role_map) != len(self.role_decisions) or set(role_map) != set(BRIDGE_ROLES):
            raise ValueError("equity bridge requires exactly nine unique role decisions")
        decisions = tuple(role_map[role] for role in BRIDGE_ROLES)
        object.__setattr__(self, "role_decisions", decisions)
        if not {
            self.diluted_shares_fact_id,
            *self.diluted_share_root_fact_ids,
        }.issubset(method_facts):
            raise ValueError("diluted-share evidence must be frozen before equity-bridge review")
        modeled_fact_ids = tuple(
            item.fact_id for item in decisions if item.status == "modeled" and item.fact_id
        )
        _unique(modeled_fact_ids, "modeled equity-bridge Facts")
        permitted_additions = {
            decision.fact_id
            for decision in decisions
            if decision.status == "modeled" and decision.fact_id is not None
        }
        added_fact_ids = set(ledger_facts).difference(method_facts)
        if added_fact_ids != permitted_additions:
            raise ValueError("equity bridge may add only the reviewed modeled aggregate Facts")
        binding_index = _economic_binding_index(self.method_view_result.reconciliation_result)
        all_roots: set[str] = set()
        all_claim_keys: set[str] = set()
        option_bindings = {
            item["binding_id"]: item
            for item in self.method_view_result.reconciliation_result.economic_claim_bindings
            if item["economic_identity"] == "option_or_dilution_claim"
        }
        included_option_roots = {
            root_id
            for item in option_bindings.values()
            if item["diluted_share_treatment"] == "included"
            for root_id in item["root_fact_ids"]
        }
        excluded_option_roots = {
            root_id
            for item in option_bindings.values()
            if item["diluted_share_treatment"] == "excluded"
            for root_id in item["root_fact_ids"]
        }
        blocked_option_roots = {
            root_id
            for item in option_bindings.values()
            if item["diluted_share_treatment"] == "blocked"
            for root_id in item["root_fact_ids"]
        }
        for decision in decisions:
            if not set(decision.root_fact_ids).issubset(decision.evidence_fact_ids):
                raise ValueError("equity-bridge roots must be included in evidence Facts")
            _require_ledger_facts(
                {*decision.evidence_fact_ids, *decision.root_fact_ids},
                ledger_facts,
                f"equity-bridge {decision.role}",
            )
            predecessor_evidence = set(decision.evidence_fact_ids)
            if decision.fact_id is not None:
                predecessor_evidence.discard(decision.fact_id)
            if not predecessor_evidence.issubset(method_facts) or not set(
                decision.root_fact_ids
            ).issubset(method_facts):
                raise ValueError(
                    "equity-bridge roots and zero evidence must be frozen before bridge review"
                )
            overlap = all_roots.intersection(decision.root_fact_ids)
            if overlap and bridge_role_policy(decision.role).requires_diluted_share_root_separation:
                raise ValueError("equity-bridge roots overlap another role or diluted shares")
            role_bindings = [binding_index[root_id] for root_id in decision.root_fact_ids]
            claim_keys = {
                item["economic_claim_key"]
                for item in role_bindings
                if item["economic_claim_key"] is not None
            }
            if any(item["economic_identity"] != decision.role for item in role_bindings):
                raise ValueError("equity-bridge role conflicts with reviewed economic identity")
            if all_claim_keys.intersection(claim_keys):
                raise ValueError("equity-bridge roles or diluted shares reuse an economic claim")
            all_claim_keys.update(claim_keys)
            all_roots.update(decision.root_fact_ids)
            evidence = [ledger_facts[fact_id] for fact_id in decision.evidence_fact_ids]
            expected_concepts = {
                policy.research_concept
                for policy in ACCOUNT_CONCEPT_POLICIES.values()
                if policy.bridge_role == decision.role
            }
            expected_category = bridge_role_policy(decision.role).kernel_category
            if any(
                item.get("concept") not in expected_concepts
                or item.get("category") != expected_category
                or item.get("currency") != ledger_payload["reporting_currency"]
                or item.get("unit") != f"{ledger_payload['reporting_currency']} millions"
                or item.get("equity_bridge_role")
                != (
                    decision.role
                    if decision.status == "modeled" and item["fact_id"] == decision.fact_id
                    else None
                )
                for item in evidence
            ):
                raise ValueError("equity-bridge evidence semantics are invalid")
            if (
                evidence
                and len(
                    {
                        (
                            item.get("period_start"),
                            item.get("period_end"),
                            item.get("as_of_date"),
                        )
                        for item in evidence
                    }
                )
                != 1
            ):
                raise ValueError("equity-bridge evidence periods are inconsistent")
            evidence_sources = {item.get("source_id") for item in evidence}
            if evidence and (None in evidence_sources or len(evidence_sources) != 1):
                raise ValueError("equity-bridge evidence requires one formal source")
            if decision.status == "modeled":
                modeled_fact = ledger_facts[decision.fact_id]
                modeled_value = modeled_fact.get("value")
                if (
                    modeled_fact.get("equity_bridge_role") != decision.role
                    or modeled_fact.get("category") != expected_category
                    or modeled_fact.get("currency") != ledger_payload["reporting_currency"]
                    or modeled_fact.get("unit")
                    != f"{ledger_payload['reporting_currency']} millions"
                    or isinstance(modeled_value, bool)
                    or not isinstance(modeled_value, (int, float))
                    or not math.isfinite(float(modeled_value))
                    or float(modeled_value) <= 0
                ):
                    raise ValueError("modeled bridge Fact semantics are invalid")
                if modeled_fact.get("raw") is not False:
                    raise ValueError("modeled bridge Fact must be a reviewed derived aggregate")
                if set(modeled_fact.get("parent_fact_ids", ())) != set(decision.root_fact_ids):
                    raise ValueError("modeled bridge aggregate lineage is incomplete")
                if modeled_fact.get("derivation") != BRIDGE_AGGREGATE_DERIVATIONS[decision.role]:
                    raise ValueError("modeled bridge aggregate derivation is not registered")
                if _ultimate_raw_roots(decision.fact_id, ledger_facts) != set(
                    decision.root_fact_ids
                ) or any(
                    _ultimate_raw_roots(root_id, ledger_facts) != {root_id}
                    for root_id in decision.root_fact_ids
                ):
                    raise ValueError("modeled bridge roots do not replay ultimate raw lineage")
                root_values = [
                    ledger_facts[root_id].get("value") for root_id in decision.root_fact_ids
                ]
                if any(
                    isinstance(value, bool)
                    or not isinstance(value, (int, float))
                    or not math.isfinite(float(value))
                    or float(value) < 0
                    for value in root_values
                ) or not math.isclose(
                    float(modeled_value),
                    sum(float(value) for value in root_values),
                    rel_tol=0.0,
                    abs_tol=1e-12,
                ):
                    raise ValueError("modeled bridge aggregate does not replay root magnitudes")
            elif decision.status == "explicitly_absent":
                if any(
                    item.get("value") != 0
                    or item.get("raw") is not True
                    or item.get("parent_fact_ids")
                    or item.get("derivation") is not None
                    for item in evidence
                ):
                    raise ValueError("absent bridge evidence must be an official raw zero")
                if set(decision.root_fact_ids) != set(decision.evidence_fact_ids):
                    raise ValueError("official zero bridge evidence must root in itself")
            elif decision.status == "not_applicable":
                if any(
                    item.get("raw") is not True
                    or item.get("parent_fact_ids")
                    or item.get("derivation") is not None
                    for item in evidence
                ):
                    raise ValueError("not-applicable bridge evidence must be official raw evidence")
                if set(decision.root_fact_ids) != set(decision.evidence_fact_ids):
                    raise ValueError("not-applicable bridge evidence must root in itself")
                reviewed_bindings = {item["binding_id"]: item for item in role_bindings}
                reviewed_pairs = {
                    (item["claim_id"], item["review_decision_id"])
                    for item in reviewed_bindings.values()
                }
                reviewed_roots = {
                    root_id
                    for item in reviewed_bindings.values()
                    for root_id in item["root_fact_ids"]
                }
                if (
                    any(item["status"] != "confirmed" for item in reviewed_bindings.values())
                    or reviewed_roots != set(decision.root_fact_ids)
                    or reviewed_pairs != {(decision.claim_id, decision.review_decision_id)}
                ):
                    raise ValueError(
                        "not-applicable bridge proof must exactly match one reviewed Claim chain"
                    )
        option_decision = next(
            item for item in decisions if item.role == "option_or_dilution_claim"
        )
        if blocked_option_roots and option_decision.status != "unresolved":
            raise ValueError("blocked option coverage requires an unresolved bridge role")
        if included_option_roots.intersection(option_decision.root_fact_ids) and (
            option_decision.status == "modeled"
        ):
            raise ValueError("diluted-share included option claim cannot be modeled again")
        if excluded_option_roots and (
            option_decision.status != "modeled"
            or set(option_decision.root_fact_ids) != excluded_option_roots
        ):
            raise ValueError("diluted-share excluded option claims require one bridge aggregate")
        if included_option_roots and not excluded_option_roots:
            included_bindings = {
                item["binding_id"]: item
                for item in option_bindings.values()
                if item["diluted_share_treatment"] == "included"
            }
            if (
                option_decision.status != "not_applicable"
                or set(option_decision.root_fact_ids) != included_option_roots
                or len(included_bindings) != 1
                or {
                    (item["claim_id"], item["review_decision_id"])
                    for item in included_bindings.values()
                }
                != {(option_decision.claim_id, option_decision.review_decision_id)}
            ):
                raise ValueError(
                    "included option claims require exact reviewed not-applicable proof"
                )
        expected_consumption_records = {
            (
                item["root_fact_id"],
                item["economic_claim_key"],
                item["economic_identity"],
                item["channel"],
                item["method"],
                item["group_id"],
                item["consumption_kind"],
            )
            for item in method_consumption_records
        }
        for decision in decisions:
            if decision.status != "modeled":
                continue
            expected_consumption_records.update(
                _claim_records_for_roots(
                    root_ids=set(decision.root_fact_ids),
                    binding_index=binding_index,
                    channel="mckinsey_equity_bridge",
                    method="mckinsey",
                    group_id=f"equity-bridge:{decision.role}",
                    consumption_kind="economic_deduction",
                )
            )
        for binding in option_bindings.values():
            if binding["diluted_share_treatment"] != "included":
                continue
            for method in METHODS:
                expected_consumption_records.update(
                    _claim_records_for_roots(
                        root_ids=set(binding["root_fact_ids"]),
                        binding_index=binding_index,
                        channel=f"{method}_diluted_shares",
                        method=method,
                        group_id=f"diluted-shares:{binding['binding_id']}",
                        consumption_kind="economic_deduction",
                    )
                )
        consumption_records = tuple(
            sorted(
                (_closed_consumption(item) for item in self.consumption_records),
                key=lambda item: (
                    item["root_fact_id"],
                    item["method"],
                    item["economic_claim_key"],
                    item["channel"],
                    item["group_id"],
                    item["consumption_kind"],
                ),
            )
        )
        actual_consumption_records = {
            (
                item["root_fact_id"],
                item["economic_claim_key"],
                item["economic_identity"],
                item["channel"],
                item["method"],
                item["group_id"],
                item["consumption_kind"],
            )
            for item in consumption_records
        }
        if (
            len(actual_consumption_records) != len(consumption_records)
            or actual_consumption_records != expected_consumption_records
        ):
            raise ValueError("equity-bridge consumption does not replay reviewed claims")
        treatments_by_claim: dict[tuple[str, str], set[tuple[str, str, str]]] = {}
        for item in consumption_records:
            if item["consumption_kind"] == "validation":
                continue
            treatments_by_claim.setdefault((item["method"], item["economic_claim_key"]), set()).add(
                (item["channel"], item["group_id"], item["consumption_kind"])
            )
        if any(len(treatments) > 1 for treatments in treatments_by_claim.values()):
            raise ValueError("economic claim is consumed more than once by one method")
        object.__setattr__(self, "consumption_records", consumption_records)
        items = tuple(_closed_bridge_item(item) for item in self.bridge_items)
        items = tuple(sorted(items, key=lambda item: item["item_id"]))
        _unique(tuple(item["item_id"] for item in items), "equity-bridge item IDs")
        _unique(tuple(item["fact_id"] for item in items), "equity-bridge item Facts")
        modeled = set(modeled_fact_ids)
        role_tagged_fact_ids = {
            fact_id
            for fact_id, fact in ledger_facts.items()
            if fact.get("equity_bridge_role") is not None
        }
        if role_tagged_fact_ids != modeled:
            raise ValueError(
                "kernel equity-bridge role tags must identify only modeled aggregate Facts"
            )
        if len(items) != len(modeled) or {item["fact_id"] for item in items} != modeled:
            raise ValueError("bridge items must equal modeled role Facts")
        object.__setattr__(self, "bridge_items", items)
        assertions = tuple(_closed_bridge_assertion(item) for item in self.role_assertions)
        assertion_map = {item["role"]: item for item in assertions}
        if len(assertion_map) != len(assertions) or set(assertion_map) != set(BRIDGE_ROLES):
            raise ValueError("equity bridge requires exactly nine unique role assertions")
        for decision in decisions:
            assertion = assertion_map[decision.role]
            if (
                assertion["status"] != decision.status
                or assertion["fact_id"] != decision.fact_id
                or tuple(sorted(assertion["source_fact_ids"])) != decision.evidence_fact_ids
                or assertion["rationale"] != decision.rationale
            ):
                raise ValueError("equity-bridge assertion does not replay its role decision")
        object.__setattr__(
            self, "role_assertions", tuple(assertion_map[role] for role in BRIDGE_ROLES)
        )
        _reason_codes(self)
        unresolved = any(item.status == "unresolved" for item in decisions)
        unresolved_reasons = {
            reason
            for decision in decisions
            if decision.status == "unresolved"
            for reason in decision.reason_codes
        }
        expected_reasons = set(unresolved_reasons)
        if not modeled:
            expected_reasons.add("kernel_bridge_item_required")
        expected_compatible = bool(modeled) and not unresolved
        expected_status = (
            "blocked"
            if any(
                BRIDGE_UNRESOLVED_REASON_SEVERITY[reason] == "blocked"
                for reason in unresolved_reasons
            )
            else "partial"
            if unresolved or not modeled
            else "complete"
        )
        if not modeled and "kernel_bridge_item_required" not in self.reason_codes:
            raise ValueError("kernel_bridge_item_required must be recorded")
        if unresolved and self.kernel_request_compatible:
            raise ValueError("unresolved equity bridge cannot be request compatible")
        if (
            self.status != expected_status
            or self.kernel_request_compatible is not expected_compatible
            or set(self.reason_codes) != expected_reasons
        ):
            raise ValueError("equity-bridge status does not replay role decisions")

    @property
    def fingerprint(self) -> str:
        return _fingerprint(self)

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)


def _closed_routing_assessment(raw: Any, assessment_id: str) -> FrozenMap:
    item = _freeze_with_sorted_sequences(
        raw,
        label=f"routing assessment {assessment_id}",
        sequence_fields=("evidence_fact_ids", "research_evidence_ids", "reason_codes"),
    )
    required = {
        "status",
        "value",
        "rationale",
        "evidence_fact_ids",
        "research_evidence_ids",
        "evidence_role_bindings",
        "reason_codes",
    }
    if set(item) != required:
        raise ValueError(f"routing assessment {assessment_id} has invalid fields")
    if item["status"] not in ROUTING_ASSESSMENT_STATUSES or not str(item["rationale"]).strip():
        raise ValueError(f"routing assessment {assessment_id} is invalid")
    if not set(item["reason_codes"]).issubset(PHASE5C_REASON_CODES):
        raise ValueError("routing assessment uses an unregistered reason")
    raw_bindings = item["evidence_role_bindings"]
    expected_roles = set(ROUTING_ASSESSMENT_REQUIRED_EVIDENCE[assessment_id])
    if set(raw_bindings) != expected_roles:
        raise ValueError("routing assessment evidence-role coverage is incomplete")
    bindings: dict[str, list[str]] = {}
    for role in sorted(raw_bindings):
        values = tuple(raw_bindings[role])
        _unique(values, f"routing assessment {assessment_id} evidence role {role}")
        bindings[role] = sorted(values)
    payload = to_json_value(item)
    payload["evidence_role_bindings"] = bindings
    item = freeze(payload)
    if item["status"] in {"pending_phase5d", "blocked"} and item["value"] is not None:
        raise ValueError("pending or blocked routing assessment cannot assert a value")
    if item["status"] == "satisfied" and item["value"] is not True:
        raise ValueError("satisfied routing assessment requires true")
    if item["status"] == "unsatisfied" and item["value"] is not False:
        raise ValueError("unsatisfied routing assessment requires false")
    if item["status"] == "satisfied" and item["reason_codes"]:
        raise ValueError("satisfied routing assessment cannot retain blocking reasons")
    if item["status"] != "satisfied" and not item["reason_codes"]:
        raise ValueError("non-satisfied routing assessment requires a reason")
    if item["status"] == "satisfied" and any(not values for values in bindings.values()):
        raise ValueError("satisfied routing assessment requires every evidence role")
    if assessment_id == "stable_capital_structure" and item["status"] == "satisfied":
        snapshots = bindings["three_comparable_annual_debt_cash_common_equity_snapshots"]
        if len(snapshots) < 3:
            raise ValueError("stable capital structure requires three annual evidence snapshots")
    return item


def _closed_method_panel(raw: Any, method: str) -> FrozenMap:
    item = _freeze_with_sorted_sequences(
        raw,
        label=f"successor readiness {method}",
        sequence_fields=(
            "satisfied_roles",
            "missing_roles",
            "evidence_fact_ids",
            "research_evidence_ids",
            "reason_codes",
        ),
    )
    required = {
        "status",
        "satisfied_roles",
        "missing_roles",
        "evidence_fact_ids",
        "research_evidence_ids",
        "reason_codes",
    }
    if set(item) != required or item["status"] not in SUCCESSOR_READINESS_STATUSES:
        raise ValueError(f"successor readiness panel {method} is invalid")
    if set(item["satisfied_roles"]) & set(item["missing_roles"]):
        raise ValueError("successor readiness roles cannot be both satisfied and missing")
    if set(item["satisfied_roles"]) | set(item["missing_roles"]) != set(
        METHOD_SUCCESSOR_REQUIRED_ROLES[method]
    ):
        raise ValueError("successor readiness role coverage is not the registered closed set")
    if not set(item["reason_codes"]).issubset(PHASE5C_REASON_CODES):
        raise ValueError("successor readiness panel uses an unregistered reason")
    if item["status"] == "ready_for_phase5d" and (item["missing_roles"] or item["reason_codes"]):
        raise ValueError("ready-for-Phase-5D panel cannot retain gaps")
    if item["status"] != "ready_for_phase5d" and not item["reason_codes"]:
        raise ValueError("non-ready successor panel requires a reason")
    return item


def _stable_capital_snapshot_fact_ids(ledger_payload: FrozenMap) -> tuple[str, ...]:
    facts = _ledger_fact_map(ledger_payload)
    concept_roles = {
        "interest_bearing_debt": "debt",
        "cash_and_cash_equivalents": "cash",
        "common_equity": "common_equity",
    }
    by_period: dict[str, dict[str, list[str]]] = {}
    for fact_id, fact in facts.items():
        role = concept_roles.get(fact["concept"])
        if (
            role is None
            or fact.get("period_start") is not None
            or fact.get("equity_bridge_role") is not None
        ):
            continue
        period_end = fact.get("period_end")
        if period_end is None or fact.get("as_of_date") != period_end:
            continue
        by_period.setdefault(period_end, {}).setdefault(role, []).append(fact_id)
    complete_periods = sorted(
        period_end
        for period_end, roles in by_period.items()
        if set(roles) == {"debt", "cash", "common_equity"}
    )
    if len(complete_periods) < 3:
        raise ValueError("stable capital structure requires three complete annual snapshots")
    selected_periods = complete_periods[-3:]
    return tuple(
        sorted(
            fact_id
            for period_end in selected_periods
            for fact_ids in by_period[period_end].values()
            for fact_id in fact_ids
        )
    )


def _closed_annual_capital_binding(raw: Any) -> FrozenMap:
    item = _freeze_with_sorted_sequences(
        raw,
        label="annual capital snapshot binding",
        sequence_fields=(
            "debt_fact_ids",
            "cash_fact_ids",
            "common_equity_fact_ids",
            "raw_root_fact_ids",
            "source_document_ids",
        ),
    )
    if set(item) != {
        "fiscal_period_id",
        "fiscal_period_fingerprint",
        "fiscal_year",
        "calendar_type",
        "period_end",
        "debt_fact_ids",
        "cash_fact_ids",
        "common_equity_fact_ids",
        "raw_root_fact_ids",
        "source_document_ids",
    }:
        raise ValueError("annual capital snapshot binding fields are invalid")
    if (
        not item["fiscal_period_id"]
        or not item["fiscal_period_fingerprint"]
        or not isinstance(item["fiscal_year"], int)
        or item["calendar_type"] not in {"calendar", "non_calendar", "52_53_week"}
        or not item["period_end"]
        or not item["debt_fact_ids"]
        or not item["cash_fact_ids"]
        or not item["common_equity_fact_ids"]
        or not item["raw_root_fact_ids"]
        or not item["source_document_ids"]
    ):
        raise ValueError("annual capital snapshot binding is incomplete")
    _require_sha256(item["fiscal_period_fingerprint"], "FiscalPeriod fingerprint")
    _parse_iso_date(item["period_end"], "annual capital period end")
    return item


def _expected_annual_capital_bindings(
    *,
    graph: Any,
    ledger_payload: FrozenMap,
    issuer_id: str,
    data_cutoff_date: str,
    allowed_fiscal_period_ids: set[str],
    phase5b_mapping_result: FactLedgerMappingResult,
    selected_phase5c_input_fact_ids: set[str],
) -> tuple[FrozenMap, ...]:
    ledger_facts = _ledger_fact_map(ledger_payload)
    snapshot_fact_ids = _stable_capital_snapshot_fact_ids(ledger_payload)
    snapshot_by_end: dict[str, dict[str, list[str]]] = {}
    role_by_concept = {
        "interest_bearing_debt": "debt",
        "cash_and_cash_equivalents": "cash",
        "common_equity": "common_equity",
    }
    for fact_id in snapshot_fact_ids:
        fact = ledger_facts[fact_id]
        snapshot_by_end.setdefault(fact["period_end"], {}).setdefault(
            role_by_concept[fact["concept"]], []
        ).append(fact_id)
    documents = {item.document_id: item for item in graph.documents}
    research_facts = {item.fact_id: item for item in graph.facts}
    mapping_decisions = {
        (item.object_type, item.object_id): item for item in phase5b_mapping_result.decisions
    }
    phase5b_facts = _ledger_fact_map(phase5b_mapping_result.ledger_payload)
    period_candidates: dict[int, list[Any]] = {}
    for period in graph.periods:
        if (
            period.period_id not in allowed_fiscal_period_ids
            or period.issuer_id != issuer_id
            or period.fiscal_quarter != 4
        ):
            continue
        if not period.source_document_ids or any(
            document_id not in documents
            or documents[document_id].issuer_id != issuer_id
            or documents[document_id].published_date > data_cutoff_date
            or documents[document_id].authority_level
            not in {"primary_regulatory", "company_primary"}
            for document_id in period.source_document_ids
        ):
            continue
        period_candidates.setdefault(period.fiscal_year, []).append(period)
    selected_by_year: dict[int, Any] = {}
    for fiscal_year, candidates in period_candidates.items():
        highest = max(item.restatement_version for item in candidates)
        winners = [item for item in candidates if item.restatement_version == highest]
        if len(winners) != 1:
            raise ValueError("annual FiscalPeriod restatement selection is ambiguous")
        selected_by_year[fiscal_year] = winners[0]
    eligible = [
        item for item in selected_by_year.values() if item.cumulative_end in snapshot_by_end
    ]
    if not eligible:
        raise ValueError("stable capital structure lacks a current annual FiscalPeriod")
    latest = max(eligible, key=lambda item: item.fiscal_year)
    selected_periods = [latest]
    for _ in range(2):
        predecessor_id = selected_periods[-1].comparative_period_id
        predecessors = [
            item for item in selected_by_year.values() if item.period_id == predecessor_id
        ]
        if len(predecessors) != 1:
            raise ValueError("stable capital FiscalPeriod comparative chain is incomplete")
        selected_periods.append(predecessors[0])
    selected_periods.reverse()
    if any(
        later.fiscal_year != earlier.fiscal_year + 1
        or later.comparative_period_id != earlier.period_id
        or later.calendar_type != earlier.calendar_type
        or _parse_iso_date(earlier.cumulative_end, "annual period end") + timedelta(days=1)
        != _parse_iso_date(later.cumulative_start, "annual period start")
        for earlier, later in zip(selected_periods, selected_periods[1:], strict=False)
    ):
        raise ValueError("stable capital FiscalPeriod chain is not consecutive")
    for period in selected_periods:
        annual_days = (
            _parse_iso_date(period.cumulative_end, "annual period end")
            - _parse_iso_date(period.cumulative_start, "annual period start")
        ).days + 1
        permitted_days = {364, 371} if period.calendar_type == "52_53_week" else {365, 366}
        if (
            annual_days not in permitted_days
            or period.cumulative_start != period.ttm_start
            or period.cumulative_end != period.quarter_end
            or period.weeks not in {13, 14}
        ):
            raise ValueError("stable capital FiscalPeriod annual window is invalid")
    expected: list[FrozenMap] = []
    for period in selected_periods:
        roles = snapshot_by_end.get(period.cumulative_end)
        if roles is None or set(roles) != {"debt", "cash", "common_equity"}:
            raise ValueError("FiscalPeriod does not have a complete capital snapshot")
        fact_ids = {fact_id for values in roles.values() for fact_id in values}
        raw_roots = {
            root_id
            for fact_id in fact_ids
            for root_id in _ultimate_raw_roots(fact_id, ledger_facts)
        }
        source_ids = {ledger_facts[root_id]["source_id"] for root_id in raw_roots}
        for root_id in raw_roots:
            research_fact = research_facts.get(root_id)
            ledger_fact = ledger_facts[root_id]
            concept_policy = (
                None
                if research_fact is None
                else PHASE5B_CONCEPT_POLICIES.get(research_fact.concept)
            )
            account_policy = (
                None
                if research_fact is None
                else ACCOUNT_CONCEPT_POLICIES.get(research_fact.concept)
            )
            unit_policy = (
                None
                if research_fact is None
                else PHASE5B_UNIT_POLICIES.get(research_fact.unit or "")
            )
            expected_unit = None
            expected_value = None
            if unit_policy is not None:
                expected_unit = unit_policy.target_unit_template
                if expected_unit is not None:
                    expected_unit = expected_unit.format(currency=research_fact.currency or "")
                if unit_policy.multiplier is not None:
                    expected_value = Decimal(str(research_fact.value)) * Decimal(
                        str(unit_policy.multiplier)
                    )
            mapping_decision = mapping_decisions.get(("Fact", root_id))
            is_phase5b_mapped = root_id in phase5b_facts
            expected_concept = (
                concept_policy.kernel_concept
                if is_phase5b_mapped and concept_policy is not None
                else account_policy.research_concept
                if account_policy is not None
                else None
            )
            expected_category = (
                concept_policy.category
                if is_phase5b_mapped and concept_policy is not None
                else account_policy.kernel_category
                if account_policy is not None
                else None
            )
            if (
                research_fact is None
                or research_fact.issuer_id != issuer_id
                or research_fact.source_document_id != ledger_fact["source_id"]
                or research_fact.source_locator != ledger_fact["source_location"]
                or research_fact.period["end"] != period.cumulative_end
                or research_fact.confidence not in {"high", "medium"}
                or (is_phase5b_mapped and concept_policy is None)
                or (
                    not is_phase5b_mapped
                    and (root_id not in selected_phase5c_input_fact_ids or account_policy is None)
                )
                or unit_policy is None
                or unit_policy.unit_family != "currency"
                or expected_concept != ledger_fact["concept"]
                or expected_category != ledger_fact["category"]
                or expected_unit != ledger_fact["unit"]
                or research_fact.currency != ledger_fact["currency"]
                or expected_value is None
                or expected_value != Decimal(str(ledger_fact["value"]))
                or ledger_fact["period_start"] is not None
                or ledger_fact["period_end"] != research_fact.period["end"]
                or ledger_fact["as_of_date"] != research_fact.period["end"]
                or ledger_fact["confidence"] != research_fact.confidence
                or ledger_fact["raw"] is not True
                or ledger_fact["parent_fact_ids"]
                or ledger_fact["derivation"] is not None
                or (
                    is_phase5b_mapped
                    and (
                        mapping_decision is None
                        or mapping_decision.disposition != "mapped"
                        or mapping_decision.output_id != root_id
                        or phase5b_facts[root_id] != ledger_fact
                    )
                )
            ):
                raise ValueError("annual capital raw root does not replay research evidence")
        if any(
            source_id not in documents
            or documents[source_id].issuer_id != issuer_id
            or documents[source_id].published_date > data_cutoff_date
            or documents[source_id].authority_level not in {"primary_regulatory", "company_primary"}
            for source_id in source_ids
        ):
            raise ValueError("annual capital source evidence is not cutoff safe")
        expected.append(
            freeze(
                {
                    "fiscal_period_id": period.period_id,
                    "fiscal_period_fingerprint": period.fingerprint,
                    "fiscal_year": period.fiscal_year,
                    "calendar_type": period.calendar_type,
                    "period_end": period.cumulative_end,
                    "debt_fact_ids": sorted(roles["debt"]),
                    "cash_fact_ids": sorted(roles["cash"]),
                    "common_equity_fact_ids": sorted(roles["common_equity"]),
                    "raw_root_fact_ids": sorted(raw_roots),
                    "source_document_ids": sorted(source_ids),
                }
            )
        )
    return tuple(expected)


def _graph_object_map(items: tuple[Any, ...], identifier: str) -> dict[str, Any]:
    result = {getattr(item, identifier): item for item in items}
    if len(result) != len(items):
        raise ValueError(f"research graph repeats {identifier}")
    return result


def _module_object_ids(bundle: Any, module_type: str) -> set[str]:
    return {
        object_id
        for reference in bundle.module_references
        if reference["module_type"] == module_type
        for object_id in reference["object_ids"]
    }


def _expected_phase5b_derived_fact(
    *,
    calculation: Any,
    research_facts: dict[str, Any],
    calculations: dict[str, Any],
    periods: dict[str, Any],
    ledger_facts: dict[str, FrozenMap],
    reporting_currency: str,
    data_cutoff_date: str,
) -> dict[str, Any]:
    try:
        calculator = calculation_policy(
            calculation.calculator_id,
            calculation.calculator_version,
        )
    except KeyError as exc:
        raise ValueError("Phase 5B derived Fact calculator is not registered") from exc
    if (
        calculation.generator != "deterministic_program"
        or calculation.code_sha256 != calculator.code_sha256
        or calculation.input_assumption_ids
        or not calculator.requires_empty_assumptions
        or not calculator.requires_single_source_lineage
    ):
        raise ValueError("Phase 5B derived Fact calculation policy does not replay")

    outputs = []
    for suffix in calculator.allowed_output_suffixes:
        if not calculation.concept.endswith(suffix):
            continue
        research_concept = calculation.concept.removesuffix(suffix)
        concept = PHASE5B_CONCEPT_POLICIES.get(research_concept)
        if concept is not None and "derived" in concept.permitted_origins:
            outputs.append((concept, suffix))
    if len(outputs) != 1:
        raise ValueError("Phase 5B derived Fact concept does not replay")
    concept, suffix = outputs[0]

    unit = PHASE5B_UNIT_POLICIES.get(calculation.unit or "")
    if (
        unit is None
        or unit.multiplier is None
        or not unit.price_blind_eligible
        or unit.unit_family != concept.unit_family
        or unit.target_unit_template is None
    ):
        raise ValueError("Phase 5B derived Fact unit does not replay")
    target_unit = unit.target_unit_template
    if unit.unit_family == "currency":
        if calculation.currency != reporting_currency:
            raise ValueError("Phase 5B derived Fact currency does not replay")
        target_unit = target_unit.format(currency=calculation.currency)
    else:
        target_unit = target_unit.format(currency="")

    period = dict(calculation.period)
    period_start = period.get("start")
    period_end = period.get("end")
    if period_end is None or period_end > data_cutoff_date:
        raise ValueError("Phase 5B derived Fact period does not replay")
    if concept.period_kind == "stock":
        if period_start is not None:
            raise ValueError("Phase 5B derived stock Fact period does not replay")
    elif period_start is None or period_start > period_end:
        raise ValueError("Phase 5B derived flow Fact period does not replay")
    eligible_periods = [
        periods[period_id] for period_id in calculation.input_period_ids if period_id in periods
    ]
    registered_period = (
        any(
            period == {"start": item.quarter_start, "end": item.quarter_end}
            for item in eligible_periods
        )
        if suffix == ".single_quarter"
        else any(
            period == {"start": item.ttm_start, "end": item.quarter_end}
            for item in eligible_periods
        )
        if suffix == ".ttm"
        else False
    )
    if not registered_period:
        raise ValueError("Phase 5B derived Fact period policy does not replay")

    try:
        fingerprints_replay = calculation.input_fingerprint == expected_input_fingerprint(
            calculation,
            facts=research_facts,
            assumptions={},
            calculations=calculations,
            periods=periods,
        ) and calculation.output_fingerprint == expected_output_fingerprint(calculation)
    except KeyError as exc:
        raise ValueError("Phase 5B derived Fact input lineage is incomplete") from exc
    if not fingerprints_replay:
        raise ValueError("Phase 5B derived Fact fingerprints do not replay")

    parent_fact_ids = tuple(
        sorted(
            (
                *calculation.input_fact_ids,
                *(
                    f"derived:{calculation_id}"
                    for calculation_id in calculation.input_calculation_ids
                ),
            )
        )
    )
    if not parent_fact_ids or any(parent_id not in ledger_facts for parent_id in parent_fact_ids):
        raise ValueError("Phase 5B derived Fact parent lineage does not replay")
    parents = [ledger_facts[parent_id] for parent_id in parent_fact_ids]
    source_ids = {item["source_id"] for item in parents}
    confidences = {item["confidence"] for item in parents}
    if len(source_ids) != 1 or not confidences.issubset({"high", "medium"}):
        raise ValueError("Phase 5B derived Fact source lineage does not replay")

    value = calculation.value
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("Phase 5B derived Fact value is not numeric")
    scaled = Decimal(str(value)) * Decimal(str(unit.multiplier))
    scaled_value: int | float = (
        int(scaled) if scaled == scaled.to_integral_value() else float(scaled)
    )
    return {
        "fact_id": f"derived:{calculation.calculation_id}",
        "concept": concept.kernel_concept,
        "value": scaled_value,
        "unit": target_unit,
        "category": concept.category,
        "source_id": next(iter(source_ids)),
        "source_location": (
            f"calculation_id={calculation.calculation_id};"
            f"output_fingerprint={calculation.output_fingerprint}"
        ),
        "as_of_date": period_end,
        "currency": calculation.currency,
        "period_start": None if concept.period_kind == "stock" else period_start,
        "period_end": period_end,
        "confidence": "medium" if "medium" in confidences else "high",
        "raw": False,
        "parent_fact_ids": parent_fact_ids,
        "derivation": (
            f"{calculation.calculator_id}@{calculation.calculator_version}:"
            f"{suffix.removeprefix('.')}"
        ),
        "equity_bridge_role": None,
    }


def _validate_phase5b_mapping_replay(
    *,
    graph: Any,
    bundle_closure: dict[str, tuple[str, Any]],
    mapping_result: FactLedgerMappingResult,
) -> None:
    from . import valuation_fact_mapping as phase5b_mapping

    documents = {
        object_id: item
        for object_id, (contract_type, item) in bundle_closure.items()
        if contract_type == "SourceDocument"
    }
    research_facts = _graph_object_map(graph.facts, "fact_id")
    calculations = _graph_object_map(graph.calculations, "calculation_id")
    periods = _graph_object_map(graph.periods, "period_id")
    ledger_payload = mapping_result.ledger_payload
    ledger_sources = {item["source_id"]: item for item in ledger_payload["sources"]}
    ledger_facts = _ledger_fact_map(ledger_payload)
    decisions = {(item.object_type, item.object_id): item for item in mapping_result.decisions}
    expected_decision_keys = {
        (contract_type, object_id)
        for object_id, (contract_type, _) in bundle_closure.items()
        if contract_type in {"SourceDocument", "Fact", "CalculationResult"}
    }
    if set(decisions) != expected_decision_keys:
        raise ValueError("Phase 5B mapping decisions do not cover the frozen Bundle closure")

    segment_fact_ids = {
        assignment["fact_id"]
        for _, (contract_type, item) in bundle_closure.items()
        if contract_type == "SegmentSnapshot"
        for assignment in item.metric_assignments
    }
    authoritative_fact_ids = {
        item.authoritative_fact_id
        for _, (contract_type, item) in bundle_closure.items()
        if contract_type == "QuarterlyReconciliation" and item.authoritative_fact_id is not None
    }
    replayed_fact_decisions: dict[str, Any] = {}
    candidates: list[Any] = []
    for object_id, (contract_type, item) in sorted(bundle_closure.items()):
        if contract_type != "Fact":
            continue
        document = documents.get(item.source_document_id)
        if document is None:
            replayed_fact_decisions[object_id] = phase5b_mapping.FactMappingDecision(
                "Fact", object_id, "blocked", ("source_identity_incomplete",)
            )
            continue
        candidate, reasons, disposition = phase5b_mapping._fact_candidate(
            item,
            document=document,
            issuer_id=mapping_result.issuer_id,
            cutoff=mapping_result.data_cutoff_date,
            segment_fact_ids=segment_fact_ids,
        )
        if candidate is None:
            replayed_fact_decisions[object_id] = phase5b_mapping.FactMappingDecision(
                "Fact", object_id, disposition, reasons
            )
        else:
            candidates.append(candidate)
    selected, conflict_decisions = phase5b_mapping._select_current_candidates(
        candidates,
        authoritative_fact_ids=authoritative_fact_ids,
    )
    replayed_fact_decisions.update(conflict_decisions)
    selected = [item for item in selected if item.fact.fact_id not in replayed_fact_decisions]
    currencies = {
        item.fact.currency
        for item in selected
        if item.unit.unit_family == "currency" and item.fact.currency is not None
    }
    if len(currencies) != 1:
        raise ValueError("Phase 5B reporting currency does not replay uniquely")
    reporting_currency = next(iter(currencies))
    if any(item.fact.currency not in {None, reporting_currency} for item in selected):
        raise ValueError("Phase 5B mapping replay found cross-currency raw Facts")
    for item in selected:
        replayed_fact_decisions[item.fact.fact_id] = phase5b_mapping.FactMappingDecision(
            "Fact", item.fact.fact_id, "mapped", (), item.fact.fact_id
        )
    derived_facts, calculation_decisions = phase5b_mapping._map_derived_calculations(
        closure=bundle_closure,
        raw_candidates=selected,
        fact_decisions=replayed_fact_decisions,
        reporting_currency=reporting_currency,
        cutoff=mapping_result.data_cutoff_date,
    )
    used_document_ids = {item.document.document_id for item in selected}
    replayed_decisions = [
        *replayed_fact_decisions.values(),
        *calculation_decisions,
    ]
    for object_id, document in sorted(documents.items()):
        if object_id in used_document_ids:
            replayed_decisions.append(
                phase5b_mapping.FactMappingDecision(
                    "SourceDocument", object_id, "mapped", (), object_id
                )
            )
        elif phase5b_mapping._source_is_registered(document):
            replayed_decisions.append(
                phase5b_mapping.FactMappingDecision(
                    "SourceDocument",
                    object_id,
                    "excluded",
                    ("source_unused_by_mapped_fact",),
                )
            )
        else:
            replayed_decisions.append(
                phase5b_mapping.FactMappingDecision(
                    "SourceDocument",
                    object_id,
                    "excluded",
                    ("source_not_official",),
                )
            )
    if not selected:
        raise ValueError("Phase 5B mapping replay has no eligible raw Fact")
    replayed_payload = {
        "schema_version": "1.0.0",
        "entity_id": mapping_result.issuer_id,
        "valuation_date": mapping_result.data_cutoff_date,
        "reporting_currency": reporting_currency,
        "sources": sorted(
            (phase5b_mapping._source_ref(documents[object_id]) for object_id in used_document_ids),
            key=lambda item: item["source_id"],
        ),
        "facts": sorted(
            (*[item.kernel_fact for item in selected], *derived_facts),
            key=lambda item: item["fact_id"],
        ),
    }
    replayed_decision_tuple = tuple(
        sorted(
            replayed_decisions,
            key=lambda item: (item.object_type, item.object_id),
        )
    )
    if (
        to_json_value(mapping_result.ledger_payload) != replayed_payload
        or mapping_result.decisions != replayed_decision_tuple
    ):
        raise ValueError("Phase 5B FactLedger mapping does not replay deterministically")

    source_sequence = tuple(item["source_id"] for item in ledger_payload["sources"])
    fact_sequence = tuple(item["fact_id"] for item in ledger_payload["facts"])
    if (
        ledger_payload["schema_version"] != "1.0.0"
        or ledger_payload["entity_id"] != mapping_result.issuer_id
        or ledger_payload["valuation_date"] != mapping_result.data_cutoff_date
        or not ledger_payload["reporting_currency"]
        or source_sequence != tuple(sorted(source_sequence))
        or fact_sequence != tuple(sorted(fact_sequence))
    ):
        raise ValueError("Phase 5B FactLedger envelope does not replay")
    raw_fact_ids = {fact_id for fact_id, item in ledger_facts.items() if item["raw"] is True}
    derived_fact_ids = set(ledger_facts).difference(raw_fact_ids)
    mapped_outputs = {
        object_type: tuple(
            item.output_id
            for item in mapping_result.decisions
            if item.object_type == object_type and item.disposition == "mapped"
        )
        for object_type in ("SourceDocument", "Fact", "CalculationResult")
    }
    if (
        any(len(outputs) != len(set(outputs)) for outputs in mapped_outputs.values())
        or set(mapped_outputs["SourceDocument"]) != set(ledger_sources)
        or set(mapped_outputs["Fact"]) != raw_fact_ids
        or set(mapped_outputs["CalculationResult"]) != derived_fact_ids
    ):
        raise ValueError("Phase 5B mapped decisions do not replay FactLedger outputs")
    for source_id, source in ledger_sources.items():
        document = documents.get(source_id)
        policy = None if document is None else PHASE5B_SOURCE_POLICIES.get(document.authority_level)
        decision = decisions.get(("SourceDocument", source_id))
        if document is None or policy is None:
            raise ValueError("Phase 5B SourceRef does not replay official research evidence")
        values = {
            "issuer_id": document.issuer_id,
            "document_type": document.document_type,
            "published_date": document.published_date,
        }
        expected_source = {
            "source_id": document.document_id,
            "title": policy.title_template.format(**values),
            "publisher": policy.publisher_template.format(**values),
            "published_date": document.published_date,
            "retrieved_at": document.retrieved_at,
            "locator": (
                f"document_id={document.document_id};content_sha256={document.content_sha256}"
            ),
            "url": document.source_url,
            "local_path": None,
            "primary": policy.primary,
        }
        if (
            dict(source) != expected_source
            or source_id not in bundle_closure
            or decision is None
            or decision.disposition != "mapped"
            or decision.output_id != source_id
        ):
            raise ValueError("Phase 5B SourceRef does not replay official research evidence")
    for fact_id, ledger_fact in ledger_facts.items():
        if ledger_fact["raw"] is True:
            research_fact = research_facts.get(fact_id)
            concept = (
                None
                if research_fact is None
                else PHASE5B_CONCEPT_POLICIES.get(research_fact.concept)
            )
            unit = (
                None
                if research_fact is None
                else PHASE5B_UNIT_POLICIES.get(research_fact.unit or "")
            )
            decision = decisions.get(("Fact", fact_id))
            if research_fact is None or concept is None or unit is None:
                raise ValueError("Phase 5B raw Fact does not replay ResearchBundle evidence")
            target_unit = unit.target_unit_template
            if target_unit is not None:
                target_unit = target_unit.format(currency=research_fact.currency or "")
            expected_value = (
                None
                if unit.multiplier is None
                else Decimal(str(research_fact.value)) * Decimal(str(unit.multiplier))
            )
            expected_start = (
                None if concept.period_kind == "stock" else research_fact.period["start"]
            )
            if (
                fact_id not in bundle_closure
                or research_fact.issuer_id != mapping_result.issuer_id
                or research_fact.source_document_id != ledger_fact["source_id"]
                or research_fact.source_locator != ledger_fact["source_location"]
                or research_fact.confidence != ledger_fact["confidence"]
                or concept.kernel_concept != ledger_fact["concept"]
                or concept.category != ledger_fact["category"]
                or unit.unit_family != concept.unit_family
                or target_unit != ledger_fact["unit"]
                or research_fact.currency != ledger_fact["currency"]
                or expected_value is None
                or expected_value != Decimal(str(ledger_fact["value"]))
                or expected_start != ledger_fact["period_start"]
                or research_fact.period["end"] != ledger_fact["period_end"]
                or research_fact.period["end"] != ledger_fact["as_of_date"]
                or ledger_fact["parent_fact_ids"]
                or ledger_fact["derivation"] is not None
                or ledger_fact["equity_bridge_role"] is not None
                or decision is None
                or decision.disposition != "mapped"
                or decision.output_id != fact_id
            ):
                raise ValueError("Phase 5B raw Fact does not replay ResearchBundle evidence")
            continue
        calculation_id = fact_id.removeprefix("derived:")
        calculation = calculations.get(calculation_id)
        decision = decisions.get(("CalculationResult", calculation_id))
        if (
            not fact_id.startswith("derived:")
            or calculation is None
            or calculation_id not in bundle_closure
            or decision is None
            or decision.disposition != "mapped"
            or decision.output_id != fact_id
        ):
            raise ValueError("Phase 5B derived Fact does not replay ResearchBundle evidence")
        if not {
            *calculation.input_fact_ids,
            *calculation.input_calculation_ids,
            *calculation.input_period_ids,
        }.issubset(bundle_closure):
            raise ValueError("Phase 5B derived Fact lineage leaves ResearchBundle closure")
        expected = _expected_phase5b_derived_fact(
            calculation=calculation,
            research_facts=research_facts,
            calculations=calculations,
            periods=periods,
            ledger_facts=ledger_facts,
            reporting_currency=ledger_payload["reporting_currency"],
            data_cutoff_date=mapping_result.data_cutoff_date,
        )
        if dict(ledger_fact) != expected:
            raise ValueError("Phase 5B derived Fact does not replay ResearchBundle evidence")


def _validate_phase5b_readiness_replay(
    *,
    graph: Any,
    mapping_result: FactLedgerMappingResult,
    readiness_result: ValuationReadinessResult,
) -> None:
    replayed = assess_method_readiness(
        graph=graph,
        mapping_result=mapping_result,
    )
    if replayed.fingerprint != readiness_result.fingerprint or to_json_value(
        replayed
    ) != to_json_value(readiness_result):
        raise ValueError("Phase 5B method readiness does not replay deterministically")


def _validate_research_context(
    *,
    graph: Any,
    issuer_id: str,
    data_cutoff_date: str,
    reconciliation_result: AccountingReconciliationResult,
    quality_result: AccountingQualityCompilationResult,
    footnote_review: FootnoteReview | None,
    allocation_review: CapitalAllocationReview | None,
    stable_claim: Claim | None,
    stable_candidate: AnalyticalClaimCandidate | None,
    stable_decision: AnalyticalClaimReviewDecision | None,
) -> tuple[str, str | None, tuple[FrozenMap, ...]]:
    from .research_bundle_policies import dependency_closure_sha256
    from .research_bundle_validation import dependency_closure
    from .validation import ContractGraph

    if not isinstance(graph, ContractGraph):
        raise ValueError("Phase 5C readiness requires one validated ContractGraph")
    graph.validate()
    if graph.market_reference_snapshots or any(
        item.authority_level == "market_reference" for item in graph.documents
    ):
        raise ValueError("Phase 5C ContractGraph must remain entirely price blind")
    bundles = [
        item
        for item in graph.research_bundles
        if item.bundle_id == reconciliation_result.research_bundle_id
    ]
    if len(bundles) != 1:
        raise ValueError("Phase 5C readiness requires one exact ResearchBundle")
    bundle = bundles[0]
    if (
        bundle.issuer_id != issuer_id
        or bundle.data_cutoff_date != data_cutoff_date
        or bundle.bundle_fingerprint != reconciliation_result.research_bundle_fingerprint
        or bundle.dependency_closure_sha256 != reconciliation_result.dependency_closure_sha256
        or bundle.component_lock_sha256 != reconciliation_result.component_lock_sha256
    ):
        raise ValueError("Phase 5C ResearchBundle identity does not replay")
    manifests = [item for item in graph.manifests if item.run_id == bundle.run_id]
    if len(manifests) != 1:
        raise ValueError("Phase 5C ResearchBundle RunManifest is unavailable")
    manifest = manifests[0]
    if (
        manifest.issuer_id != issuer_id
        or manifest.data_cutoff_date != data_cutoff_date
        or manifest.component_lock_sha256 != bundle.component_lock_sha256
        or manifest.output_artifact_hashes.get("research-bundle.json") != bundle.bundle_fingerprint
    ):
        raise ValueError("Phase 5C RunManifest does not replay ResearchBundle")
    bundle_roots = tuple(
        object_id for reference in bundle.module_references for object_id in reference["object_ids"]
    )
    bundle_closure = dependency_closure(graph, bundle_roots)
    _validate_phase5b_mapping_replay(
        graph=graph,
        bundle_closure=bundle_closure,
        mapping_result=reconciliation_result.phase5b_mapping_result,
    )
    _validate_phase5b_readiness_replay(
        graph=graph,
        mapping_result=reconciliation_result.phase5b_mapping_result,
        readiness_result=reconciliation_result.phase5b_readiness_result,
    )
    if any(
        contract_type == "SourceDocument" and item.authority_level == "market_reference"
        for contract_type, item in bundle_closure.values()
    ):
        raise ValueError("price-blind ResearchBundle contains market evidence")

    footnotes = _graph_object_map(graph.footnote_reviews, "review_id")
    quality_reviews = _graph_object_map(graph.accounting_quality_reviews, "review_id")
    allocation_reviews = _graph_object_map(graph.capital_allocation_reviews, "review_id")
    claims = _graph_object_map(graph.claims, "claim_id")
    candidates = _graph_object_map(graph.analytical_claim_candidates, "candidate_id")
    decisions = _graph_object_map(graph.analytical_claim_review_decisions, "decision_id")
    selected_footnotes = _module_object_ids(bundle, "footnote_review")
    selected_quality = _module_object_ids(bundle, "accounting_quality_review")
    selected_allocation = _module_object_ids(bundle, "capital_allocation_review")
    quality_review = quality_result.accounting_quality_review
    if (
        selected_quality != {quality_review.review_id}
        or quality_reviews.get(quality_review.review_id) != quality_review
        or any(
            item.review_id not in selected_footnotes or footnotes.get(item.review_id) != item
            for item in (footnotes[review_id] for review_id in quality_review.footnote_review_ids)
        )
    ):
        raise ValueError("Phase 5C accounting-quality evidence is not current Bundle evidence")
    for finding in quality_result.accounting_quality_findings:
        graph_findings = _graph_object_map(graph.accounting_quality_findings, "finding_id")
        if graph_findings.get(finding.finding_id) != finding:
            raise ValueError("Phase 5C accounting-quality Finding does not replay graph")

    for claim in reconciliation_result.economic_claims:
        if claims.get(claim.claim_id) != claim:
            raise ValueError("economic Claim does not replay ContractGraph")
    for candidate in reconciliation_result.economic_claim_candidates:
        if candidates.get(candidate.candidate_id) != candidate:
            raise ValueError("economic Claim Candidate does not replay ContractGraph")
    for decision in reconciliation_result.economic_claim_review_decisions:
        if decisions.get(decision.decision_id) != decision:
            raise ValueError("economic Claim Decision does not replay ContractGraph")

    stable_objects = (
        footnote_review,
        allocation_review,
        stable_claim,
        stable_candidate,
        stable_decision,
    )
    stable_enabled = all(item is not None for item in stable_objects)
    stable_disabled = all(item is None for item in stable_objects)
    if not (stable_enabled or stable_disabled):
        raise ValueError("stable-capital evidence graph is only partially bound")
    stable_hash: str | None = None
    annual_bindings: tuple[FrozenMap, ...] = ()
    if stable_enabled:
        assert footnote_review is not None
        assert allocation_review is not None
        assert stable_claim is not None
        assert stable_candidate is not None
        assert stable_decision is not None
        if (
            footnote_review.review_id not in selected_footnotes
            or footnotes.get(footnote_review.review_id) != footnote_review
            or allocation_review.review_id not in selected_allocation
            or allocation_reviews.get(allocation_review.review_id) != allocation_review
            or claims.get(stable_claim.claim_id) != stable_claim
            or candidates.get(stable_candidate.candidate_id) != stable_candidate
            or decisions.get(stable_decision.decision_id) != stable_decision
        ):
            raise ValueError("stable-capital typed evidence is not current Bundle evidence")
        annual_bindings = _expected_annual_capital_bindings(
            graph=graph,
            ledger_payload=reconciliation_result.ledger_payload,
            issuer_id=issuer_id,
            data_cutoff_date=data_cutoff_date,
            allowed_fiscal_period_ids={
                object_id
                for object_id, (contract_type, _) in bundle_closure.items()
                if contract_type == "FiscalPeriod"
            }.intersection(bundle.fiscal_period_ids),
            phase5b_mapping_result=reconciliation_result.phase5b_mapping_result,
            selected_phase5c_input_fact_ids=set(reconciliation_result.selected_input_fact_ids),
        )
        stable_roots = (
            footnote_review.review_id,
            allocation_review.review_id,
            stable_claim.claim_id,
            stable_candidate.candidate_id,
            stable_decision.decision_id,
            *(item["fiscal_period_id"] for item in annual_bindings),
        )
        closure = dependency_closure(graph, tuple(stable_roots))
        forbidden_types = {"Assumption", "Score"}
        if any(contract_type in forbidden_types for contract_type, _ in closure.values()):
            raise ValueError("stable-capital evidence closure contains a forbidden object")
        for contract_type, item in closure.values():
            if contract_type == "SourceDocument" and item.published_date > data_cutoff_date:
                raise ValueError("stable-capital evidence closure contains a future source")
            if contract_type == "Fact" and item.issuer_id != issuer_id:
                raise ValueError("stable-capital evidence closure contains a foreign Fact")
        stable_hash = dependency_closure_sha256(
            [
                (contract_type, object_id, item.fingerprint)
                for object_id, (contract_type, item) in closure.items()
            ]
        )
    extension_roots = (
        *(item.claim_id for item in reconciliation_result.economic_claims),
        *(item.candidate_id for item in reconciliation_result.economic_claim_candidates),
        *(item.decision_id for item in reconciliation_result.economic_claim_review_decisions),
        *(
            ()
            if stable_claim is None
            else (
                stable_claim.claim_id,
                stable_candidate.candidate_id,
                stable_decision.decision_id,
            )
        ),
        *(item["fiscal_period_id"] for item in annual_bindings),
    )
    extension_closure = dependency_closure(graph, tuple(extension_roots))
    evidence_ids = {
        reference
        for candidate in (
            *reconciliation_result.economic_claim_candidates,
            *((stable_candidate,) if stable_candidate is not None else ()),
        )
        for binding in (
            *candidate.supporting_evidence_bindings,
            *candidate.counterevidence_bindings,
        )
        for reference in (
            binding["fact_id"],
            binding["calculation_result_id"],
            binding["context_observation_id"],
        )
        if reference is not None
    }
    if not evidence_ids.issubset(bundle_closure):
        raise ValueError("Phase 5C reviewed evidence is outside ResearchBundle closure")
    if any(
        contract_type in {"Assumption", "Score"}
        or (contract_type == "SourceDocument" and item.authority_level == "market_reference")
        for contract_type, item in extension_closure.values()
    ):
        raise ValueError("Phase 5C evidence extension contains a forbidden object")
    extension_hash = dependency_closure_sha256(
        [
            (contract_type, object_id, item.fingerprint)
            for object_id, (contract_type, item) in extension_closure.items()
        ]
    )
    context_hash = canonical_sha256(
        {
            "research_bundle_id": bundle.bundle_id,
            "research_bundle_fingerprint": bundle.bundle_fingerprint,
            "dependency_closure_sha256": bundle.dependency_closure_sha256,
            "component_lock_sha256": bundle.component_lock_sha256,
            "phase5b_mapping_fingerprint": reconciliation_result.phase5b_mapping_fingerprint,
            "phase5b_readiness_fingerprint": reconciliation_result.phase5b_readiness_fingerprint,
            "reconciliation_fingerprint": reconciliation_result.fingerprint,
            "quality_fingerprint": quality_result.fingerprint,
            "phase5c_evidence_extension_sha256": extension_hash,
            "stable_capital_evidence_closure_sha256": stable_hash,
        }
    )
    return context_hash, stable_hash, annual_bindings


def _validate_stable_capital_contracts(
    *,
    assessment: FrozenMap,
    issuer_id: str,
    data_cutoff_date: str,
    ledger_payload: FrozenMap,
    quality_result: AccountingQualityCompilationResult,
    footnote_review: FootnoteReview | None,
    allocation_review: CapitalAllocationReview | None,
    claim: Claim | None,
    candidate: AnalyticalClaimCandidate | None,
    review_decision: AnalyticalClaimReviewDecision | None,
) -> None:
    contracts = (
        footnote_review,
        allocation_review,
        claim,
        candidate,
        review_decision,
    )
    if assessment["status"] == "blocked":
        if any(item is not None for item in contracts):
            raise ValueError("blocked stable-capital assessment cannot retain a partial proof")
        if (
            any(assessment["evidence_role_bindings"].values())
            or assessment["evidence_fact_ids"]
            or assessment["research_evidence_ids"]
        ):
            raise ValueError("blocked stable-capital assessment cannot use placeholder evidence")
        return
    if assessment["status"] not in {"satisfied", "unsatisfied"} or any(
        item is None for item in contracts
    ):
        raise ValueError("stable-capital conclusion requires five typed evidence objects")
    if not (
        isinstance(footnote_review, FootnoteReview)
        and isinstance(allocation_review, CapitalAllocationReview)
        and isinstance(claim, Claim)
        and isinstance(candidate, AnalyticalClaimCandidate)
        and isinstance(review_decision, AnalyticalClaimReviewDecision)
    ):
        raise ValueError("stable-capital evidence object types are invalid")
    snapshot_fact_ids = _stable_capital_snapshot_fact_ids(ledger_payload)
    ledger_facts = _ledger_fact_map(ledger_payload)
    snapshot_raw_root_ids = {
        root_id
        for fact_id in snapshot_fact_ids
        for root_id in _ultimate_raw_roots(fact_id, ledger_facts)
    }
    reporting_currency = ledger_payload["reporting_currency"]
    if any(
        ledger_facts[fact_id].get("currency") != reporting_currency
        or ledger_facts[fact_id].get("unit") != f"{reporting_currency} millions"
        for fact_id in snapshot_fact_ids
    ):
        raise ValueError("stable-capital snapshots do not share one currency and unit")
    bindings = assessment["evidence_role_bindings"]
    if tuple(bindings["three_comparable_annual_debt_cash_common_equity_snapshots"]) != tuple(
        sorted(snapshot_fact_ids)
    ):
        raise ValueError("stable-capital snapshot bindings do not replay the ledger")
    if (
        tuple(bindings["current_debt_liquidity_covenants_footnote_review"])
        != (footnote_review.review_id,)
        or tuple(bindings["current_capital_allocation_review"]) != (allocation_review.review_id,)
        or any(
            tuple(bindings[role]) != (claim.claim_id,)
            for role in (
                "named_human_confirmed_analytical_claim",
                "counterevidence_search",
                "falsification_condition",
            )
        )
    ):
        raise ValueError("stable-capital evidence-role bindings do not replay typed objects")
    if (
        footnote_review.issuer_id != issuer_id
        or footnote_review.topic_code != "debt_liquidity_covenants"
        or footnote_review.status != "reviewed"
        or footnote_review.missing_evidence
        or not footnote_review.source_document_ids
        or not footnote_review.fact_ids
        or footnote_review.fiscal_period_id
        != quality_result.accounting_quality_review.fiscal_period_id
        or footnote_review.review_id
        not in quality_result.accounting_quality_review.footnote_review_ids
    ):
        raise ValueError("stable-capital debt and liquidity FootnoteReview is invalid")
    source_statuses = {item["status"] for item in allocation_review.source_coverage}
    event_statuses = {item["status"] for item in allocation_review.event_type_coverage}
    coverage = allocation_review.coverage
    if (
        allocation_review.schema_version != "3.0.0"
        or allocation_review.review_policy_id != "capital-allocation-review"
        or allocation_review.review_policy_version != "2.0.0"
        or allocation_review.issuer_id != issuer_id
        or _parse_iso_date(allocation_review.as_of_date, "capital-allocation review as-of")
        > _parse_iso_date(data_cutoff_date, "Phase 5C cutoff")
        or allocation_review.status != "complete"
        or allocation_review.missing_evidence
        or len(allocation_review.source_coverage) != 8
        or "blocked" in source_statuses
        or len(allocation_review.event_type_coverage) != 13
        or "blocked" in event_statuses
        or any(
            coverage[key] != 0 for key in ("partial_count", "unverifiable_count", "blocked_count")
        )
    ):
        raise ValueError("stable-capital CapitalAllocationReview is not complete")
    if (
        claim.issuer_id != issuer_id
        or candidate.issuer_id != issuer_id
        or review_decision.issuer_id != issuer_id
        or candidate.scope["scope_type"] != "issuer_wide"
        or candidate.scope["segment_definition_ids"]
        or any(
            candidate.scope[field] is not None
            for field in (
                "business_unit",
                "product_service",
                "geography",
                "customer_group",
                "channel",
            )
        )
        or candidate.business_attribute_role is not None
        or candidate.business_component_type is not None
        or candidate.claim_role != ("stable" if assessment["status"] == "satisfied" else "eroding")
        or candidate.validation_status != "ready"
        or candidate.validation_issues
        or review_decision.decision != "confirmed"
        or review_decision.candidate_id != candidate.candidate_id
        or review_decision.candidate_fingerprint != candidate.fingerprint
        or review_decision.evidence_graph_sha256 != candidate.evidence_graph_sha256
        or review_decision.output_claim_id != claim.claim_id
        or claim.statement != candidate.proposed_statement
        or claim.confidence not in {"high", "medium"}
        or not claim.falsification_condition.strip()
        or (not claim.counterevidence_fact_ids and not claim.counterevidence_search_note)
        or set(claim.supporting_fact_ids) != snapshot_raw_root_ids
        or _parse_iso_date(claim.as_of_date, "stable-capital Claim as-of")
        > _parse_iso_date(data_cutoff_date, "Phase 5C cutoff")
        or datetime.fromisoformat(review_decision.reviewed_at.replace("Z", "+00:00")).date()
        > _parse_iso_date(data_cutoff_date, "Phase 5C cutoff")
    ):
        raise ValueError("stable-capital Claim review chain does not replay")
    candidate_fact_ids = {
        item["fact_id"]
        for item in candidate.supporting_evidence_bindings
        if item["fact_id"] is not None
    }
    if candidate_fact_ids != set(claim.supporting_fact_ids) or any(
        item["calculation_result_id"] is not None or item["context_observation_id"] is not None
        for item in candidate.supporting_evidence_bindings
    ):
        raise ValueError("stable-capital Candidate does not replay supporting Facts")
    expected_evidence_fact_ids = {
        *snapshot_fact_ids,
        *footnote_review.fact_ids,
        *claim.supporting_fact_ids,
        *claim.counterevidence_fact_ids,
    }
    expected_research_ids = {
        footnote_review.review_id,
        allocation_review.review_id,
        claim.claim_id,
        candidate.candidate_id,
        review_decision.decision_id,
    }
    if (
        set(assessment["evidence_fact_ids"]) != expected_evidence_fact_ids
        or set(assessment["research_evidence_ids"]) != expected_research_ids
    ):
        raise ValueError("stable-capital evidence unions do not replay typed objects")


@dataclass(frozen=True, slots=True)
class Phase5CReadinessResult:
    issuer_id: str
    data_cutoff_date: str
    phase5b_mapping_fingerprint: str
    phase5b_readiness_fingerprint: str
    reconciliation_fingerprint: str
    reconciliation_result: AccountingReconciliationResult
    quality_fingerprint: str
    quality_result: AccountingQualityCompilationResult
    method_view_fingerprint: str
    method_view_result: MethodViewCompilationResult
    equity_bridge_fingerprint: str
    equity_bridge_result: EquityBridgeCompilationResult
    stable_capital_footnote_review: FootnoteReview | None
    stable_capital_allocation_review: CapitalAllocationReview | None
    stable_capital_claim: Claim | None
    stable_capital_claim_candidate: AnalyticalClaimCandidate | None
    stable_capital_claim_review_decision: AnalyticalClaimReviewDecision | None
    validated_research_context_sha256: str
    stable_capital_evidence_closure_sha256: str | None
    stable_capital_annual_bindings: tuple[FrozenMap, ...]
    policy_id: str
    policy_version: str
    policy_sha256: str
    specialist_route: str
    upstream_statuses: FrozenMap
    routing_assessments: FrozenMap
    method_panels: FrozenMap
    validation_graph: InitVar[Any]

    def __post_init__(self, validation_graph: Any) -> None:
        _policy_identity(self.policy_id, self.policy_version, self.policy_sha256)
        if not self.issuer_id:
            raise ValueError("Phase 5C readiness issuer is required")
        if (
            not isinstance(self.reconciliation_result, AccountingReconciliationResult)
            or not isinstance(self.quality_result, AccountingQualityCompilationResult)
            or not isinstance(self.method_view_result, MethodViewCompilationResult)
            or not isinstance(self.equity_bridge_result, EquityBridgeCompilationResult)
            or self.reconciliation_result.fingerprint != self.reconciliation_fingerprint
            or self.quality_result.fingerprint != self.quality_fingerprint
            or self.method_view_result.fingerprint != self.method_view_fingerprint
            or self.equity_bridge_result.fingerprint != self.equity_bridge_fingerprint
            or self.reconciliation_result.phase5b_mapping_fingerprint
            != self.phase5b_mapping_fingerprint
            or self.reconciliation_result.phase5b_readiness_fingerprint
            != self.phase5b_readiness_fingerprint
            or self.quality_result.reconciliation_fingerprint != self.reconciliation_fingerprint
            or self.method_view_result.reconciliation_fingerprint != self.reconciliation_fingerprint
            or self.method_view_result.quality_fingerprint != self.quality_fingerprint
            or self.equity_bridge_result.method_view_fingerprint != self.method_view_fingerprint
            or any(
                item.issuer_id != self.issuer_id or item.data_cutoff_date != self.data_cutoff_date
                for item in (
                    self.reconciliation_result,
                    self.quality_result,
                    self.method_view_result,
                    self.equity_bridge_result,
                )
            )
        ):
            raise ValueError("Phase 5C readiness predecessor binding does not replay")
        if self.specialist_route not in SPECIALIST_ROUTES:
            raise ValueError("Phase 5C specialist route is not registered")
        if (
            self.specialist_route
            != self.reconciliation_result.phase5b_readiness_result.specialist_route
        ):
            raise ValueError("Phase 5C specialist route does not replay Phase 5B readiness")
        upstream = freeze(self.upstream_statuses)
        expected_upstream = {
            "accounting_reconciliation",
            "mckinsey_accounting_quality",
            "penman_accounting_quality",
            "mckinsey_method_view",
            "penman_method_view",
            "equity_bridge",
        }
        if set(upstream) != expected_upstream:
            raise ValueError("Phase 5C readiness upstream status coverage is incomplete")
        for key in expected_upstream - {"equity_bridge"}:
            if upstream[key] not in {"pass", "partial", "blocked"}:
                raise ValueError("Phase 5C readiness upstream status is invalid")
        if upstream["equity_bridge"] not in {"complete", "partial", "blocked"}:
            raise ValueError("Phase 5C equity-bridge upstream status is invalid")
        expected_upstream_statuses = {
            "accounting_reconciliation": self.reconciliation_result.status,
            "mckinsey_accounting_quality": self.quality_result.status_by_method["mckinsey"],
            "penman_accounting_quality": self.quality_result.status_by_method["penman"],
            "mckinsey_method_view": self.method_view_result.status_by_method["mckinsey"],
            "penman_method_view": self.method_view_result.status_by_method["penman"],
            "equity_bridge": self.equity_bridge_result.status,
        }
        if dict(upstream) != expected_upstream_statuses:
            raise ValueError("Phase 5C readiness upstream statuses do not replay predecessors")
        object.__setattr__(self, "upstream_statuses", upstream)
        raw_assessments = freeze(self.routing_assessments)
        if set(raw_assessments) != set(ROUTING_ASSESSMENT_IDS):
            raise ValueError("Phase 5C readiness must cover six routing assessments")
        assessments = {
            key: _closed_routing_assessment(raw_assessments[key], key)
            for key in ROUTING_ASSESSMENT_IDS
        }
        _validate_stable_capital_contracts(
            assessment=assessments["stable_capital_structure"],
            issuer_id=self.issuer_id,
            data_cutoff_date=self.data_cutoff_date,
            ledger_payload=self.equity_bridge_result.ledger_payload,
            quality_result=self.quality_result,
            footnote_review=self.stable_capital_footnote_review,
            allocation_review=self.stable_capital_allocation_review,
            claim=self.stable_capital_claim,
            candidate=self.stable_capital_claim_candidate,
            review_decision=self.stable_capital_claim_review_decision,
        )
        (
            expected_context_sha256,
            expected_stable_closure_sha256,
            expected_annual_bindings,
        ) = _validate_research_context(
            graph=validation_graph,
            issuer_id=self.issuer_id,
            data_cutoff_date=self.data_cutoff_date,
            reconciliation_result=self.reconciliation_result,
            quality_result=self.quality_result,
            footnote_review=self.stable_capital_footnote_review,
            allocation_review=self.stable_capital_allocation_review,
            stable_claim=self.stable_capital_claim,
            stable_candidate=self.stable_capital_claim_candidate,
            stable_decision=self.stable_capital_claim_review_decision,
        )
        annual_bindings = tuple(
            sorted(
                (
                    _closed_annual_capital_binding(item)
                    for item in self.stable_capital_annual_bindings
                ),
                key=lambda item: (item["fiscal_year"], item["fiscal_period_id"]),
            )
        )
        if (
            self.validated_research_context_sha256 != expected_context_sha256
            or self.stable_capital_evidence_closure_sha256 != expected_stable_closure_sha256
            or annual_bindings != expected_annual_bindings
        ):
            raise ValueError("Phase 5C research-context binding does not replay")
        _require_sha256(
            self.validated_research_context_sha256,
            "validated research-context SHA",
        )
        if self.stable_capital_evidence_closure_sha256 is not None:
            _require_sha256(
                self.stable_capital_evidence_closure_sha256,
                "stable-capital evidence-closure SHA",
            )
        object.__setattr__(self, "stable_capital_annual_bindings", annual_bindings)
        separable = assessments["operating_financing_separable"]
        expected_separable = (
            "satisfied"
            if self.reconciliation_result.account_decisions
            and all(
                item.status == "classified" for item in self.reconciliation_result.account_decisions
            )
            else "blocked"
        )
        if separable["status"] != expected_separable or separable["value"] is not (
            True if expected_separable == "satisfied" else None
        ):
            raise ValueError("operating/financing separability does not replay account decisions")
        credible_noa = assessments["credible_noa"]
        noa_check_status = self.reconciliation_result.checks["noa_nfo_common_equity"]["status"]
        expected_noa_status = (
            "satisfied"
            if noa_check_status == "reconciles_independently"
            else "blocked"
            if noa_check_status == "blocked"
            else "unsatisfied"
        )
        if credible_noa["status"] != expected_noa_status or credible_noa["value"] is not (
            True
            if expected_noa_status == "satisfied"
            else False
            if expected_noa_status == "unsatisfied"
            else None
        ):
            raise ValueError("credible NOA does not replay the accounting reconciliation")
        bridge_assessment = assessments["equity_bridge_complete"]
        expected_bridge_status = (
            "satisfied"
            if self.equity_bridge_result.status == "complete"
            and self.equity_bridge_result.kernel_request_compatible
            else "blocked"
            if self.equity_bridge_result.status == "blocked"
            else "unsatisfied"
        )
        if bridge_assessment["status"] != expected_bridge_status or bridge_assessment[
            "value"
        ] is not (
            True
            if expected_bridge_status == "satisfied"
            else False
            if expected_bridge_status == "unsatisfied"
            else None
        ):
            raise ValueError("equity-bridge readiness does not replay the bridge result")
        required_data = assessments["required_data_complete"]
        if (
            required_data["status"] != "unsatisfied"
            or required_data["value"] is not False
            or "required_data_incomplete_until_phase5e" not in required_data["reason_codes"]
        ):
            raise ValueError("Phase 5C cannot assert complete valuation-request data")
        earnings = assessments["credible_near_term_earnings"]
        if (
            earnings["status"] != "pending_phase5d"
            or earnings["value"] is not None
            or "phase5d_earnings_pending" not in earnings["reason_codes"]
        ):
            raise ValueError("credible near-term earnings must remain pending_phase5d")
        object.__setattr__(self, "routing_assessments", freeze(assessments))
        raw_panels = freeze(self.method_panels)
        if set(raw_panels) != set(METHODS):
            raise ValueError("Phase 5C readiness must contain two method panels")
        panels = {method: _closed_method_panel(raw_panels[method], method) for method in METHODS}
        object.__setattr__(self, "method_panels", freeze(panels))
        upstream_role_status = {
            "accounting_reconciliation": upstream["accounting_reconciliation"],
            "mckinsey_method_view": upstream["mckinsey_method_view"],
            "penman_method_view": upstream["penman_method_view"],
            "equity_bridge_complete": (
                "pass" if upstream["equity_bridge"] == "complete" else upstream["equity_bridge"]
            ),
        }
        assessment_roles = {
            "stable_capital_structure": assessments["stable_capital_structure"]["status"],
            "operating_financing_separable": assessments["operating_financing_separable"]["status"],
            "credible_noa": assessments["credible_noa"]["status"],
            "equity_bridge_complete": assessments["equity_bridge_complete"]["status"],
        }
        for method, panel in panels.items():
            role_states: dict[str, str] = {}
            for role in METHOD_SUCCESSOR_REQUIRED_ROLES[method]:
                if role == "accounting_quality":
                    role_states[role] = upstream[f"{method}_accounting_quality"]
                elif role in upstream_role_status:
                    role_states[role] = upstream_role_status[role]
                else:
                    role_states[role] = assessment_roles[role]
                if role == "equity_bridge_complete" and assessment_roles[role] != "satisfied":
                    role_states[role] = assessment_roles[role]
            satisfied = {
                role for role, status in role_states.items() if status in {"pass", "satisfied"}
            }
            missing = set(role_states).difference(satisfied)
            if set(panel["satisfied_roles"]) != satisfied or set(panel["missing_roles"]) != missing:
                raise ValueError("successor readiness panel does not replay dependency states")
            has_blocked = any(status == "blocked" for status in role_states.values())
            expected_status = (
                "blocked"
                if self.specialist_route == "unresolved" or has_blocked
                else "specialist_required"
                if self.specialist_route != "none"
                else "partial"
                if missing
                else "ready_for_phase5d"
            )
            if panel["status"] != expected_status:
                raise ValueError("successor readiness panel status is not deterministic")
        if assessments["stable_capital_structure"]["status"] == "unsatisfied" and (
            self.specialist_route == "none"
        ):
            raise ValueError("unstable capital structure requires a specialist route")
        if self.specialist_route == "unresolved" and any(
            panel["status"] != "blocked" for panel in self.method_panels.values()
        ):
            raise ValueError("unresolved specialist route requires blocked panels")
        if self.specialist_route not in {"none", "unresolved"} and any(
            panel["status"] not in {"specialist_required", "blocked"}
            for panel in self.method_panels.values()
        ):
            raise ValueError("specialist route requires specialist or blocked method panels")
        if self.specialist_route == "none" and any(
            panel["status"] == "specialist_required" for panel in self.method_panels.values()
        ):
            raise ValueError("core specialist route cannot emit specialist-required panels")

    @property
    def fingerprint(self) -> str:
        return _fingerprint(self)

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)
