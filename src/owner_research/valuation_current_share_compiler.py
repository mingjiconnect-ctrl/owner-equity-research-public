"""Internal deterministic quote-date current-common-share compiler.

The compiler replays the frozen price-blind and governed market-access identities, selects or
derives one quote-date current-common-share Fact, and closes its recursive evidence lineage.  It
does not fetch market data, build market evidence, write artifacts, or invoke valuation code.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import date
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from .capital_allocation_policies import OFFICIAL_AUTHORITY_LEVELS, SOURCE_FAMILIES
from .contracts import Fact, SourceDocument
from .fingerprints import canonical_sha256, to_json_value
from .validation import ContractGraph, ContractGraphError
from .valuation_current_share_evidence import (
    COMPLETED_SHARE_EVENT_SIGNS,
    SHARE_COVERAGE_SEARCH_EVENT_TYPES,
    CurrentShareEvidenceClosure,
    CurrentShareEvidenceError,
)
from .valuation_current_share_evidence import (
    derive_current_share_evidence_closure as _derive_predecessor_evidence_closure,
)
from .valuation_current_share_vertical import derive_v2_closure
from .valuation_market_access import MarketAccessResult
from .valuation_market_execution_policies import (
    SHARE_BASIS_POLICY_ID,
    SHARE_BASIS_POLICY_VERSION,
    SUPPORTED_SHARE_BASIS,
)
from .valuation_market_execution_types import ShareBasisDecision
from .valuation_market_reference_types import Phase5CDilutionClaimAuthority
from .valuation_price_blind_freeze import (
    PriceBlindFreezeCompilationResult,
    PriceBlindFreezeError,
    load_price_blind_input_artifact,
)
from .valuation_security_identity import (
    SecurityIdentityCompilationResult,
    compile_security_identity,
)
from .valuation_share_event_grouping import (
    ShareEventGroupingError,
    group_governed_completed_share_events,
)
from .valuation_share_event_integration_types import (
    CANONICAL_EVENT_DERIVATION,
    COVERAGE_SEARCH_ENDPOINTS,
    COVERAGE_SEARCH_TOOL_NAMESPACE,
    COVERAGE_SEARCH_TOOL_VERSION,
    CURRENT_SHARE_INTEGRATION_POLICY_ID,
    CURRENT_SHARE_INTEGRATION_POLICY_VERSION,
    CURRENT_SHARE_ROLLFORWARD_CHANNEL,
    CURRENT_SHARE_ROLLFORWARD_DERIVATION,
    STANDARD_CLAIM_TRANSITION_EVENT_CONCEPTS,
    CanonicalShareEventFactMaterialization,
    CanonicalShareEventMemberBinding,
    CorporateActionCoverageLedgerV2,
    CurrentShareBundleEvidenceClosure,
    CurrentShareEvidenceClosureV2,
    GroupBoundClaimTransitionReconciliation,
    GroupBoundDilutionClaimAuthority,
    ShareEventNumericConsumption,
    _canonical_event_source_locator,
    _output_share_source_locator,
    _primary_member_source_id,
    _reserved_output_share_fact_id,
    current_share_integration_code_sha256,
)

# Retain the predecessor module seam for direct/issued compatibility and the frozen sparse-graph
# tests.  Rich graph-owned canonical groups never route through this symbol.
derive_current_share_evidence_closure = _derive_predecessor_evidence_closure
_V2_CLOSURE_CONTRACT_TYPES = (
    CorporateActionCoverageLedgerV2,
    CurrentShareBundleEvidenceClosure,
    CurrentShareEvidenceClosureV2,
    GroupBoundClaimTransitionReconciliation,
)

CURRENT_SHARE_COMPILATION_POLICY_ID = "quote-date-current-common-shares-compilation"
CURRENT_SHARE_COMPILATION_POLICY_VERSION = "1.0.0"
CURRENT_SHARE_COMPILATION_STATUSES = ("eligible", "specialist_required", "blocked")
CURRENT_SHARE_PATH_STATUSES = ("selected", "eligible", "excluded", "blocked")
CURRENT_SHARE_PATH_KINDS = (
    "direct_point_in_time",
    "issued_less_treasury",
    "completed_event_rollforward",
)
CURRENT_SHARE_COMPILATION_ISSUES = frozenset(
    {
        "artifact_reload_failed",
        "contract_graph_invalid",
        "security_identity_mismatch",
        "market_access_mismatch",
        "dilution_claim_authority_blocked",
        "dilution_claim_authority_specialist",
        "current_share_evidence_missing",
        "current_share_evidence_ambiguous",
        "current_share_path_conflict",
        "current_share_lineage_invalid",
        "corporate_action_coverage_incomplete",
        "split_factor_unsupported",
    }
)
_SPLIT_EVENT_CONCEPTS = frozenset(
    {"stock_split_completed", "reverse_stock_split_completed"}
)


def _unique_sorted(values: tuple[str, ...], label: str) -> tuple[str, ...]:
    if len(values) != len(set(values)) or any(not value.strip() for value in values):
        raise ValueError(f"{label} must contain unique non-empty values")
    return tuple(sorted(values))


def _decimal(value: object, label: str, *, allow_zero: bool = False) -> int:
    try:
        parsed = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ValueError(f"{label} is not an exact decimal") from exc
    if (
        not parsed.is_finite()
        or parsed != parsed.to_integral()
        or (parsed < 0 if allow_zero else parsed <= 0)
    ):
        raise ValueError(f"{label} is not an eligible integer magnitude")
    return int(parsed)


@dataclass(frozen=True, slots=True)
class CurrentSharePathDecision:
    path_kind: str
    candidate_fact_ids: tuple[str, ...]
    status: str
    output_value_decimal: str | None
    issue_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.path_kind not in CURRENT_SHARE_PATH_KINDS:
            raise ValueError("current-share path kind is not registered")
        if self.status not in CURRENT_SHARE_PATH_STATUSES:
            raise ValueError("current-share path status is not registered")
        candidates = _unique_sorted(self.candidate_fact_ids, "candidate Fact IDs")
        issues = _unique_sorted(self.issue_codes, "current-share path issues")
        if not set(issues).issubset(CURRENT_SHARE_COMPILATION_ISSUES):
            raise ValueError("current-share path contains an unregistered issue")
        if self.status in {"selected", "eligible"}:
            if self.output_value_decimal is None or issues:
                raise ValueError("eligible current-share path lacks its exact output")
            _decimal(self.output_value_decimal, "current-share path output")
        elif not issues:
            raise ValueError("non-eligible current-share path requires an issue")
        object.__setattr__(self, "candidate_fact_ids", candidates)
        object.__setattr__(self, "issue_codes", issues)

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(self.to_dict())


@dataclass(frozen=True, slots=True)
class CanonicalShareEventNumericConsumption:
    """Bind the frozen numeric-consumption record to its canonical magnitude."""

    record: ShareEventNumericConsumption
    canonical_share_magnitude: str

    def __post_init__(self) -> None:
        _decimal(self.canonical_share_magnitude, "canonical share-event magnitude")

    @property
    def group_id(self) -> str:
        return self.record.group_id

    @property
    def canonical_event_fact_id(self) -> str:
        return self.record.canonical_event_fact_id

    @property
    def sign(self) -> str:
        return self.record.sign

    @property
    def consumption_fingerprint(self) -> str:
        return self.record.consumption_fingerprint

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)


@dataclass(frozen=True, slots=True)
class CanonicalRollforwardResult:
    """Closed exactly-once arithmetic output for the separately governed 2B lineage."""

    opening_share_fact_id: str
    output_share_fact_id: str
    materializations: tuple[CanonicalShareEventFactMaterialization, ...]
    numeric_consumptions: tuple[CanonicalShareEventNumericConsumption, ...]
    rollforward_fingerprint: str

    def __post_init__(self) -> None:
        materials = tuple(sorted(self.materializations, key=lambda item: item.group_id))
        consumptions = tuple(
            sorted(self.numeric_consumptions, key=lambda item: item.group_id)
        )
        material_groups = tuple(item.group_id for item in materials)
        consumption_groups = tuple(item.group_id for item in consumptions)
        if (
            not self.opening_share_fact_id
            or not self.output_share_fact_id
            or len(material_groups) != len(set(material_groups))
            or material_groups != consumption_groups
            or any(
                material.canonical_event_fact_id
                != consumption.canonical_event_fact_id
                for material, consumption in zip(materials, consumptions, strict=True)
            )
        ):
            raise ValueError("canonical roll-forward is not group-bound exactly once")
        object.__setattr__(self, "materializations", materials)
        object.__setattr__(self, "numeric_consumptions", consumptions)
        if self.rollforward_fingerprint != self.expected_fingerprint():
            raise ValueError("canonical roll-forward fingerprint mismatch")

    def fingerprint_payload(self) -> dict[str, Any]:
        payload = to_json_value(self)
        payload.pop("rollforward_fingerprint")
        return payload

    def expected_fingerprint(self) -> str:
        return canonical_sha256(self.fingerprint_payload())

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)


@dataclass(frozen=True, slots=True)
class CurrentShareCompilationResult:
    policy_id: str
    policy_version: str
    issuer_id: str
    data_cutoff_date: str
    security_id: str
    quote_date: str
    status: str
    output_fact: Fact | None
    share_basis_decision: ShareBasisDecision | None
    evidence_closure: CurrentShareEvidenceClosure | CurrentShareEvidenceClosureV2 | None
    path_decisions: tuple[CurrentSharePathDecision, ...]
    issue_codes: tuple[str, ...]
    canonical_rollforward: CanonicalRollforwardResult | None = None

    def __post_init__(self) -> None:
        if (self.policy_id, self.policy_version) != (
            CURRENT_SHARE_COMPILATION_POLICY_ID,
            CURRENT_SHARE_COMPILATION_POLICY_VERSION,
        ):
            raise ValueError("current-share compilation policy mismatch")
        date.fromisoformat(self.data_cutoff_date)
        date.fromisoformat(self.quote_date)
        if self.status not in CURRENT_SHARE_COMPILATION_STATUSES:
            raise ValueError("current-share compilation status is not registered")
        paths = tuple(sorted(self.path_decisions, key=lambda item: item.path_kind))
        if len(paths) != len({item.path_kind for item in paths}):
            raise ValueError("current-share compilation contains duplicated paths")
        issues = _unique_sorted(self.issue_codes, "current-share compilation issues")
        if not set(issues).issubset(CURRENT_SHARE_COMPILATION_ISSUES):
            raise ValueError("current-share compilation contains an unregistered issue")
        if self.status == "eligible":
            if (
                self.output_fact is None
                or self.share_basis_decision is None
                or self.evidence_closure is None
                or issues
                or len([item for item in paths if item.status == "selected"]) != 1
            ):
                raise ValueError("eligible current-share compilation lacks its closed evidence")
            if (
                self.output_fact.fact_id != self.share_basis_decision.share_fact_id
                or self.output_fact.fact_id != self.evidence_closure.output_share_fact_id
                or self.output_fact.period["end"] != self.quote_date
            ):
                raise ValueError("current-share compilation outputs are not identity-bound")
            if self.canonical_rollforward is not None and (
                self.output_fact.fact_id
                != self.canonical_rollforward.output_share_fact_id
            ):
                raise ValueError("canonical roll-forward does not bind the promoted output")
        elif any(
            item is not None
            for item in (
                self.output_fact,
                self.share_basis_decision,
                self.evidence_closure,
                self.canonical_rollforward,
            )
        ) or not issues:
            raise ValueError("non-eligible current-share compilation cannot promote evidence")
        object.__setattr__(self, "path_decisions", paths)
        object.__setattr__(self, "issue_codes", issues)

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(self.to_dict())


def _result(
    *,
    artifact: dict[str, Any],
    security_id: str,
    quote_date: str,
    status: str,
    paths: tuple[CurrentSharePathDecision, ...] = (),
    issues: tuple[str, ...],
    output_fact: Fact | None = None,
    decision: ShareBasisDecision | None = None,
    closure: CurrentShareEvidenceClosure | CurrentShareEvidenceClosureV2 | None = None,
    canonical_rollforward: CanonicalRollforwardResult | None = None,
) -> CurrentShareCompilationResult:
    return CurrentShareCompilationResult(
        policy_id=CURRENT_SHARE_COMPILATION_POLICY_ID,
        policy_version=CURRENT_SHARE_COMPILATION_POLICY_VERSION,
        issuer_id=str(artifact["issuer_id"]),
        data_cutoff_date=str(artifact["data_cutoff_date"]),
        security_id=security_id,
        quote_date=quote_date,
        status=status,
        output_fact=output_fact,
        share_basis_decision=decision,
        evidence_closure=closure,
        path_decisions=paths,
        issue_codes=issues,
        canonical_rollforward=canonical_rollforward,
    )


def _formal_raw_share_fact(
    fact: Fact,
    *,
    concept: str,
    issuer_id: str,
    measurement_date: str,
    cutoff: date,
    documents: dict[str, SourceDocument],
    allow_zero: bool = False,
) -> int | None:
    source = documents.get(fact.source_document_id)
    if (
        fact.issuer_id != issuer_id
        or fact.concept != concept
        or fact.value_type != "number"
        or fact.unit != "shares"
        or fact.currency is not None
        or fact.period["start"] is not None
        or fact.period["end"] != measurement_date
        or fact.confidence != "high"
        or fact.derivation is not None
        or fact.parent_fact_ids
        or source is None
        or source.issuer_id != issuer_id
        or source.authority_level not in OFFICIAL_AUTHORITY_LEVELS
        or date.fromisoformat(source.published_date) > cutoff
    ):
        return None
    try:
        return _decimal(fact.value, concept, allow_zero=allow_zero)
    except ValueError:
        return None


def _formal_window_share_fact(
    fact: Fact,
    *,
    issuer_id: str,
    opening_date: str | None,
    quote_date: str,
    cutoff: date,
    documents: dict[str, SourceDocument],
    concepts: frozenset[str],
    allow_issued_opening: bool = False,
    include_quote_date: bool = False,
) -> int | None:
    """Return one cutoff-safe formal stock Fact inside the governed share window."""

    source = documents.get(fact.source_document_id)
    measurement_date = fact.period["end"]
    raw = fact.derivation is None and not fact.parent_fact_ids
    issued_opening = (
        allow_issued_opening
        and fact.derivation == "issued-less-treasury/1.0.0"
        and bool(fact.parent_fact_ids)
    )
    if (
        fact.issuer_id != issuer_id
        or fact.concept not in concepts
        or fact.value_type != "number"
        or fact.unit != "shares"
        or fact.currency is not None
        or fact.period["start"] is not None
        or measurement_date is None
        or str(measurement_date) > quote_date
        or (str(measurement_date) == quote_date and not include_quote_date)
        or (opening_date is not None and str(measurement_date) <= opening_date)
        or fact.confidence != "high"
        or not (raw or issued_opening)
        or source is None
        or source.issuer_id != issuer_id
        or source.authority_level not in OFFICIAL_AUTHORITY_LEVELS
        or date.fromisoformat(source.published_date) > cutoff
    ):
        return None
    try:
        return _decimal(fact.value, fact.concept)
    except ValueError:
        return None


def _v2_coverage_authority_state(
    graph: ContractGraph,
    *,
    issuer_id: str,
    opening_date: str,
    quote_date: str,
    data_cutoff_date: str,
) -> str:
    """Classify target-bound governed coverage without using unrelated graph presence."""

    target_window = tuple(
        item
        for item in graph.source_search_receipts
        if item.issuer_id == issuer_id
        and item.cutoff_date == data_cutoff_date
        and str(item.period["start"]) <= opening_date
        and str(item.period["end"]) >= quote_date
    )
    v2_trace = tuple(
        item
        for item in target_window
        if item.tool_version.startswith(COVERAGE_SEARCH_TOOL_NAMESPACE)
    )
    if not v2_trace:
        return "absent"
    if (
        len(v2_trace) != len(SOURCE_FAMILIES)
        or {item.source_family for item in v2_trace} != set(SOURCE_FAMILIES)
        or len({str(item.query_scope["cik"]) for item in v2_trace}) != 1
        or any(
            item.status != "completed"
            or item.issues
            or item.tool_version != COVERAGE_SEARCH_TOOL_VERSION
            or item.searched_endpoints
            != COVERAGE_SEARCH_ENDPOINTS.get(item.source_family)
            or not SHARE_COVERAGE_SEARCH_EVENT_TYPES.issubset(
                set(item.query_scope["event_types"])
            )
            for item in v2_trace
        )
    ):
        return "incomplete"
    return "complete"


def _authoritative_ids(graph: ContractGraph) -> set[str]:
    return {
        item.authoritative_fact_id
        for item in graph.reconciliations
        if item.authoritative_fact_id is not None
    }


def _select_equivalent(
    facts: tuple[Fact, ...],
    *,
    values: dict[str, int],
    documents: dict[str, SourceDocument],
    authoritative_ids: set[str],
) -> tuple[Fact | None, bool]:
    if not facts:
        return None, False
    authorities = tuple(item for item in facts if item.fact_id in authoritative_ids)
    if len(authorities) == 1:
        return authorities[0], False
    if len(authorities) > 1 or len({values[item.fact_id] for item in facts}) != 1:
        return None, True
    return max(
        facts,
        key=lambda item: (
            documents[item.source_document_id].document_type.endswith("/A"),
            documents[item.source_document_id].published_date,
            item.fact_id,
        ),
    ), False


def _primary_source(parents: tuple[Fact, ...], documents: dict[str, SourceDocument]) -> Fact:
    return max(
        parents,
        key=lambda item: (
            documents[item.source_document_id].document_type.endswith("/A"),
            documents[item.source_document_id].published_date,
            item.fact_id,
        ),
    )


def _derived_fact(
    *,
    issuer_id: str,
    quote_date: str,
    value: int,
    derivation: str,
    parents: tuple[Fact, ...],
    documents: dict[str, SourceDocument],
) -> Fact:
    identity = canonical_sha256(
        {
            "issuer_id": issuer_id,
            "quote_date": quote_date,
            "value": str(value),
            "derivation": derivation,
            "parents": tuple(sorted((item.fact_id, item.fingerprint) for item in parents)),
        }
    )
    primary = _primary_source(parents, documents)
    return Fact(
        schema_version="2.0.0",
        fact_id=f"derived:current-shares:{identity[:24]}",
        issuer_id=issuer_id,
        concept="common_shares_outstanding",
        value_type="number",
        value=int(value),
        unit="shares",
        currency=None,
        period={"start": None, "end": quote_date},
        source_document_id=primary.source_document_id,
        source_locator=f"current-share-compiler:{derivation}:{identity}",
        derivation=derivation,
        parent_fact_ids=tuple(sorted(item.fact_id for item in parents)),
        confidence="high",
    )


def _corporate_evidence_ids(
    closure: CurrentShareEvidenceClosure | CurrentShareEvidenceClosureV2,
) -> tuple[str, ...]:
    if isinstance(closure, CurrentShareEvidenceClosureV2):
        # A V2 closure deliberately contains the complete ResearchBundle dependency graph.
        # Only the share roll-forward, corporate-action coverage, and reviewed claim-transition
        # subgraphs are corporate-action evidence; unrelated revenue, business-quality, or other
        # Bundle evidence must not be relabelled as such by the Snapshot.
        identifiers = {
            closure.opening_share_fact.fact_id,
            closure.opening_share_fact.source_document_id,
        }
        for materialization in closure.materializations:
            identifiers.update(
                {
                    materialization.canonical_event_fact.fact_id,
                    materialization.canonical_event_fact.source_document_id,
                }
            )
            for member in materialization.members:
                identifiers.update(
                    {
                        member.fact.fact_id,
                        member.source_document.document_id,
                    }
                )
        coverage = closure.coverage_ledger
        identifiers.update(item.document_id for item in coverage.result_source_documents)
        for entry in coverage.entries:
            identifiers.update(item.fact_id for item in entry.observed_member_facts)
            identifiers.update(
                item.document_id for item in entry.observed_member_source_documents
            )
            if entry.zero_fact is not None:
                identifiers.update(
                    {entry.zero_fact.fact_id, entry.zero_fact.source_document_id}
                )
            if entry.not_applicable_claim is not None:
                identifiers.add(entry.not_applicable_claim.claim_id)
            for fact in (
                *entry.not_applicable_supporting_facts,
                *entry.not_applicable_counterevidence_facts,
            ):
                identifiers.update({fact.fact_id, fact.source_document_id})
        for transition in closure.claim_transition_reconciliation.records:
            identifiers.update(
                {
                    transition.affected_claim_root_fact.fact_id,
                    transition.affected_claim_source_document.document_id,
                    transition.remaining_claim_fact.fact_id,
                    transition.remaining_claim_source_document.document_id,
                }
            )
            for fact in transition.evidence_facts:
                identifiers.update({fact.fact_id, fact.source_document_id})
            identifiers.update(item.document_id for item in transition.evidence_source_documents)
            identifiers.update(item.claim_id for item in transition.claims)
        available = {
            object_id
            for contract_type, object_id, _ in closure.object_fingerprints
            if contract_type in {"SourceDocument", "Fact", "Claim"}
        }
        if not identifiers.issubset(available):
            raise ValueError("V2 corporate-action evidence is outside its recursive closure")
        return tuple(sorted(identifiers))
    return tuple(
        sorted(
            {
                object_id
                for contract_type, object_id, _ in closure.object_fingerprints
                if contract_type in {"SourceDocument", "Fact", "Claim"}
            }
        )
    )


def _path_decision(
    path: str,
    facts: tuple[Fact, ...],
    *,
    status: str,
    value: int | None = None,
    issue: str | None = None,
) -> CurrentSharePathDecision:
    return CurrentSharePathDecision(
        path_kind=path,
        candidate_fact_ids=tuple(item.fact_id for item in facts),
        status=status,
        output_value_decimal=str(value) if value is not None else None,
        issue_codes=(issue,) if issue is not None else (),
    )


def _overlay(graph: ContractGraph, fact: Fact) -> ContractGraph:
    existing = {item.fact_id: item for item in graph.facts}
    prior = existing.get(fact.fact_id)
    if prior is not None and prior.fingerprint != fact.fingerprint:
        raise ValueError("derived current-share Fact identity collides")
    facts = graph.facts if prior is not None else (*graph.facts, fact)
    return replace(graph, facts=facts)


def derive_current_share_evidence_closure_v2(
    *,
    graph,
    grouping_result,
    opening_share_fact,
    security_compilation_result,
    claim_control_authority,
    quote_date,
    data_cutoff_date,
    expected_research_bundle_id=None,
):
    """Construct the protected V2 closure through the production vertical implementation."""

    if expected_research_bundle_id is None:
        matching_bundles = tuple(
            item
            for item in graph.research_bundles
            if item.issuer_id == grouping_result.issuer_id
            and item.data_cutoff_date == data_cutoff_date
        )
        if len(matching_bundles) != 1:
            raise ValueError("current-share V2 closure lacks one exact ResearchBundle")
        expected_research_bundle_id = matching_bundles[0].bundle_id

    closure = derive_v2_closure(
        graph=graph,
        grouping_result=grouping_result,
        opening_share_fact=opening_share_fact,
        security_compilation_result=security_compilation_result,
        claim_control_authority=claim_control_authority,
        quote_date=quote_date,
        data_cutoff_date=data_cutoff_date,
        expected_research_bundle_id=expected_research_bundle_id,
    )
    if type(closure) is not CurrentShareEvidenceClosureV2:
        raise ValueError("current-share V2 derivation returned the wrong closure type")
    return closure


def _derive_predecessor_closure(**kwargs: Any) -> CurrentShareEvidenceClosure:
    closure_builder = derive_current_share_evidence_closure
    return closure_builder(**kwargs)


def _canonical_member_binding(
    *,
    graph: ContractGraph,
    member: Any,
    issuer_id: str,
    security_id: str,
    data_cutoff_date: str,
) -> CanonicalShareEventMemberBinding:
    facts = {item.fact_id: item for item in graph.facts}
    documents = {item.document_id: item for item in graph.documents}
    events = {item.event_id: item for item in graph.capital_allocation_events}
    candidates = {
        item.candidate_id: item
        for item in graph.capital_allocation_event_candidates
    }
    decisions = {
        item.decision_id: item
        for item in graph.capital_allocation_event_review_decisions
    }
    fact = facts[member.fact_id]
    source = documents[member.source_document_id]
    event = events[member.capital_allocation_event_id]
    bound_candidates = tuple(
        sorted(
            (candidates[identifier] for identifier in member.candidate_ids),
            key=lambda item: item.candidate_id,
        )
    )
    bound_decisions = tuple(
        sorted(
            (decisions[identifier] for identifier in member.review_decision_ids),
            key=lambda item: item.decision_id,
        )
    )
    payload = {
        "issuer_id": issuer_id,
        "security_id": security_id,
        "data_cutoff_date": data_cutoff_date,
        "member": member,
        "fact": fact,
        "source_document": source,
        "capital_allocation_event": event,
        "candidates": bound_candidates,
        "review_decisions": bound_decisions,
        "member_id": member.member_id,
        "member_fingerprint": member.member_fingerprint,
        "fact_id": fact.fact_id,
        "fact_fingerprint": fact.fingerprint,
        "source_document_id": source.document_id,
        "source_document_fingerprint": source.fingerprint,
        "capital_allocation_event_id": event.event_id,
        "capital_allocation_event_fingerprint": event.fingerprint,
        "candidate_bindings": tuple(
            (item.candidate_id, item.fingerprint) for item in bound_candidates
        ),
        "review_decision_bindings": tuple(
            (item.decision_id, item.fingerprint) for item in bound_decisions
        ),
    }
    return CanonicalShareEventMemberBinding(
        **payload,
        binding_fingerprint=canonical_sha256(payload),
    )


def _canonical_rollforward(
    *,
    graph: ContractGraph,
    opening: Fact,
    security: SecurityIdentityCompilationResult,
    issuer_id: str,
    quote_date: str,
    data_cutoff_date: str,
) -> tuple[Fact, CanonicalRollforwardResult, tuple[Fact, ...]] | None:
    security_decision = security.decision
    if security_decision is None or opening.period["end"] is None:
        raise ValueError("canonical roll-forward lacks its security or opening date")
    grouping = group_governed_completed_share_events(
        graph=graph,
        issuer_id=issuer_id,
        security_compilation_result=security,
        opening_date=str(opening.period["end"]),
        quote_date=quote_date,
        data_cutoff_date=data_cutoff_date,
    )
    if grouping.status != "grouped":
        raise ValueError("canonical share-event grouping is blocked")
    if not grouping.groups:
        return None

    members_by_id = {item.member_id: item for item in grouping.members}
    materializations: list[CanonicalShareEventFactMaterialization] = []
    consumptions: list[CanonicalShareEventNumericConsumption] = []
    canonical_facts: list[Fact] = []
    value = _decimal(opening.value, "opening common shares")
    integration_code_sha = current_share_integration_code_sha256()

    for group in grouping.groups:
        bindings = tuple(
            _canonical_member_binding(
                graph=graph,
                member=members_by_id[identifier],
                issuer_id=issuer_id,
                security_id=security_decision.security_id,
                data_cutoff_date=data_cutoff_date,
            )
            for identifier in group.member_ids
        )
        primary_source_id = _primary_member_source_id(bindings)
        canonical_fact_id = str(group.canonical_event_fact_id)
        canonical_fact = Fact(
            schema_version="2.0.0",
            fact_id=canonical_fact_id,
            issuer_id=issuer_id,
            concept=group.identity.event_concept,
            value_type="number",
            value=int(group.identity.canonical_share_magnitude),
            unit="shares",
            currency=None,
            period={
                "start": None,
                "end": group.identity.legal_effective_date,
            },
            source_document_id=primary_source_id,
            source_locator=_canonical_event_source_locator(canonical_fact_id),
            derivation=CANONICAL_EVENT_DERIVATION,
            parent_fact_ids=tuple(sorted(item.fact_id for item in bindings)),
            confidence="high",
        )
        material_payload = {
            "policy_id": CURRENT_SHARE_INTEGRATION_POLICY_ID,
            "policy_version": CURRENT_SHARE_INTEGRATION_POLICY_VERSION,
            "materialization_code_sha256": integration_code_sha,
            "issuer_id": issuer_id,
            "security_id": security_decision.security_id,
            "opening_date": str(opening.period["end"]),
            "quote_date": quote_date,
            "data_cutoff_date": data_cutoff_date,
            "grouping_result": grouping,
            "group": group,
            "canonical_event_fact": canonical_fact,
            "grouping_result_fingerprint": grouping.grouping_fingerprint,
            "group_id": group.group_id,
            "group_fingerprint": group.group_fingerprint,
            "identity_fingerprint": group.identity.identity_fingerprint,
            "canonical_event_fact_id": canonical_fact.fact_id,
            "canonical_event_fact_fingerprint": canonical_fact.fingerprint,
            "event_concept": group.identity.event_concept,
            "legal_effective_date": group.identity.legal_effective_date,
            "canonical_share_magnitude": group.identity.canonical_share_magnitude,
            "primary_source_document_id": primary_source_id,
            "members": bindings,
        }
        materialization = CanonicalShareEventFactMaterialization(
            **material_payload,
            materialization_fingerprint=canonical_sha256(material_payload),
        )
        consumption_payload = {
            "group_id": group.group_id,
            "group_fingerprint": group.group_fingerprint,
            "identity_fingerprint": group.identity.identity_fingerprint,
            "canonical_event_fact_id": canonical_fact.fact_id,
            "canonical_event_fact_fingerprint": canonical_fact.fingerprint,
            "event_concept": group.identity.event_concept,
            "sign": format(
                COMPLETED_SHARE_EVENT_SIGNS[group.identity.event_concept],
                "f",
            ),
            "channel": CURRENT_SHARE_ROLLFORWARD_CHANNEL,
            "window_start": str(opening.period["end"]),
            "window_end": quote_date,
        }
        frozen_consumption = ShareEventNumericConsumption(
            **consumption_payload,
            consumption_fingerprint=canonical_sha256(consumption_payload),
        )
        consumption = CanonicalShareEventNumericConsumption(
            record=frozen_consumption,
            canonical_share_magnitude=group.identity.canonical_share_magnitude,
        )
        value += (
            int(COMPLETED_SHARE_EVENT_SIGNS[group.identity.event_concept])
            * _decimal(
                group.identity.canonical_share_magnitude,
                "canonical share-event magnitude",
            )
        )
        materializations.append(materialization)
        consumptions.append(consumption)
        canonical_facts.append(canonical_fact)

    if value <= 0:
        raise ValueError("canonical roll-forward produces non-positive shares")
    output_fact_id = _reserved_output_share_fact_id(
        issuer_id=issuer_id,
        security_id=security_decision.security_id,
        quote_date=quote_date,
        opening_share_fact_id=opening.fact_id,
        grouping_result_fingerprint=grouping.grouping_fingerprint,
    )
    output = Fact(
        schema_version="2.0.0",
        fact_id=output_fact_id,
        issuer_id=issuer_id,
        concept="common_shares_outstanding",
        value_type="number",
        value=int(value),
        unit="shares",
        currency=None,
        period={"start": None, "end": quote_date},
        source_document_id=opening.source_document_id,
        source_locator=_output_share_source_locator(output_fact_id),
        derivation=CURRENT_SHARE_ROLLFORWARD_DERIVATION,
        parent_fact_ids=tuple(
            sorted((opening.fact_id, *(item.fact_id for item in canonical_facts)))
        ),
        confidence="high",
    )
    rollforward_payload = {
        "opening_share_fact_id": opening.fact_id,
        "output_share_fact_id": output.fact_id,
        "materializations": tuple(materializations),
        "numeric_consumptions": tuple(consumptions),
    }
    rollforward = CanonicalRollforwardResult(
        **rollforward_payload,
        rollforward_fingerprint=canonical_sha256(rollforward_payload),
    )
    return output, rollforward, tuple(canonical_facts)


def _canonical_rollforward_from_v2(
    closure: CurrentShareEvidenceClosureV2,
) -> CanonicalRollforwardResult:
    """Project the already-validated V2 numeric lineage into the compatibility result."""

    magnitudes = {
        item.group_id: item.canonical_share_magnitude for item in closure.materializations
    }
    numeric_consumptions = tuple(
        CanonicalShareEventNumericConsumption(
            record=item,
            canonical_share_magnitude=magnitudes[item.group_id],
        )
        for item in closure.numeric_consumptions
    )
    payload = {
        "opening_share_fact_id": closure.opening_share_fact_id,
        "output_share_fact_id": closure.output_share_fact_id,
        "materializations": closure.materializations,
        "numeric_consumptions": numeric_consumptions,
    }
    return CanonicalRollforwardResult(
        **payload,
        rollforward_fingerprint=canonical_sha256(payload),
    )


def compile_quote_date_current_common_shares(
    *,
    price_blind_artifact_directory: Path,
    graph: ContractGraph,
    expected_freeze: PriceBlindFreezeCompilationResult,
    expected_security: SecurityIdentityCompilationResult,
    expected_market_access: MarketAccessResult,
) -> CurrentShareCompilationResult:
    """Compile one governed quote-date current-common-share Fact and evidence closure."""

    artifact = expected_freeze.artifact.to_dict()
    fallback_security_id = (
        expected_security.decision.security_id
        if expected_security.decision is not None
        else "security:unresolved"
    )
    fallback_quote_date = (
        expected_market_access.receipt.receipt.trading_date
        if expected_market_access.receipt is not None
        else str(artifact["data_cutoff_date"])
    )
    try:
        graph.validate()
        loaded = load_price_blind_input_artifact(
            Path(price_blind_artifact_directory),
            graph=graph,
            expected_result=expected_freeze,
        )
    except (ContractGraphError, PriceBlindFreezeError, OSError, ValueError):
        return _result(
            artifact=artifact,
            security_id=fallback_security_id,
            quote_date=fallback_quote_date,
            status="blocked",
            issues=("artifact_reload_failed",),
        )
    artifact = loaded.artifact.to_dict()
    replayed_security = compile_security_identity(
        graph=graph,
        expected_freeze=loaded,
        proposal=expected_security.proposal,
    )
    if replayed_security.fingerprint != expected_security.fingerprint:
        return _result(
            artifact=artifact,
            security_id=fallback_security_id,
            quote_date=fallback_quote_date,
            status="blocked",
            issues=("security_identity_mismatch",),
        )
    security = replayed_security.decision
    access = expected_market_access
    if (
        replayed_security.status != "eligible"
        or security is None
        or replayed_security.evidence_closure is None
        or access.status != "eligible"
        or access.request is None
        or access.receipt is None
        or access.issuer_id != artifact["issuer_id"]
        or access.data_cutoff_date != artifact["data_cutoff_date"]
        or access.authorization_handoff_id != loaded.handoffs[-1].handoff_id
        or access.request.authorization_handoff_id != access.authorization_handoff_id
        or access.price_blind_input_fingerprint != loaded.artifact.fingerprint
        or access.protected_mckinsey_sha256 != artifact["protected_mckinsey_sha256"]
        or access.protected_penman_assumptions_sha256
        != artifact["protected_penman_assumptions_sha256"]
        or access.request.security_id != security.security_id
        or access.receipt.security_compilation_fingerprint != replayed_security.fingerprint
    ):
        return _result(
            artifact=artifact,
            security_id=fallback_security_id,
            quote_date=fallback_quote_date,
            status="blocked",
            issues=("market_access_mismatch",),
        )
    quote_date = access.receipt.receipt.trading_date
    try:
        claim_authority = Phase5CDilutionClaimAuthority.from_price_blind_artifact(
            loaded.artifact
        )
    except ValueError:
        return _result(
            artifact=artifact,
            security_id=security.security_id,
            quote_date=quote_date,
            status="blocked",
            issues=("dilution_claim_authority_blocked",),
        )
    if claim_authority.standard_path_disposition == "blocked":
        return _result(
            artifact=artifact,
            security_id=security.security_id,
            quote_date=quote_date,
            status="blocked",
            issues=("dilution_claim_authority_blocked",),
        )
    if claim_authority.standard_path_disposition == "specialist_required":
        return _result(
            artifact=artifact,
            security_id=security.security_id,
            quote_date=quote_date,
            status="specialist_required",
            issues=("dilution_claim_authority_specialist",),
        )

    cutoff = date.fromisoformat(str(artifact["data_cutoff_date"]))
    documents = {item.document_id: item for item in graph.documents}
    authority_ids = _authoritative_ids(graph)
    path_outputs: list[tuple[str, Fact, int]] = []
    path_decisions: list[CurrentSharePathDecision] = []
    canonical_rollforward: CanonicalRollforwardResult | None = None
    canonical_event_facts: tuple[Fact, ...] = ()
    canonical_v2_closure: CurrentShareEvidenceClosureV2 | None = None

    direct_values: dict[str, int] = {}
    direct_candidates: list[Fact] = []
    for fact in graph.facts:
        value = _formal_raw_share_fact(
            fact,
            concept="common_shares_outstanding",
            issuer_id=security.issuer_id,
            measurement_date=quote_date,
            cutoff=cutoff,
            documents=documents,
        )
        if value is not None:
            direct_candidates.append(fact)
            direct_values[fact.fact_id] = value
    direct, direct_conflict = _select_equivalent(
        tuple(direct_candidates),
        values=direct_values,
        documents=documents,
        authoritative_ids=authority_ids,
    )
    if direct_conflict:
        path_decisions.append(
            _path_decision(
                "direct_point_in_time",
                tuple(direct_candidates),
                status="blocked",
                issue="current_share_evidence_ambiguous",
            )
        )
    elif direct is not None:
        value = direct_values[direct.fact_id]
        path_outputs.append(("direct_point_in_time", direct, value))
        path_decisions.append(
            _path_decision(
                "direct_point_in_time",
                tuple(direct_candidates),
                status="eligible",
                value=value,
            )
        )
    else:
        path_decisions.append(
            _path_decision(
                "direct_point_in_time",
                (),
                status="excluded",
                issue="current_share_evidence_missing",
            )
        )

    issued_candidates: dict[str, tuple[list[Fact], dict[str, int]]] = {
        "common_shares_issued": ([], {}),
        "treasury_shares": ([], {}),
    }
    for concept, (items, values) in issued_candidates.items():
        for fact in graph.facts:
            value = _formal_raw_share_fact(
                fact,
                concept=concept,
                issuer_id=security.issuer_id,
                measurement_date=quote_date,
                cutoff=cutoff,
                documents=documents,
                allow_zero=concept == "treasury_shares",
            )
            if value is not None:
                items.append(fact)
                values[fact.fact_id] = value
    selected_roots: list[Fact] = []
    issued_conflict = False
    for items, values in issued_candidates.values():
        selected, conflict = _select_equivalent(
            tuple(items),
            values=values,
            documents=documents,
            authoritative_ids=authority_ids,
        )
        issued_conflict = issued_conflict or conflict
        if selected is not None:
            selected_roots.append(selected)
    all_issued_facts = tuple(
        item for items, _ in issued_candidates.values() for item in items
    )
    if issued_conflict:
        path_decisions.append(
            _path_decision(
                "issued_less_treasury",
                all_issued_facts,
                status="blocked",
                issue="current_share_evidence_ambiguous",
            )
        )
    elif len(selected_roots) == 2:
        issued = next(item for item in selected_roots if item.concept == "common_shares_issued")
        treasury = next(item for item in selected_roots if item.concept == "treasury_shares")
        value = issued_candidates["common_shares_issued"][1][issued.fact_id] - (
            issued_candidates["treasury_shares"][1][treasury.fact_id]
        )
        if value <= 0:
            path_decisions.append(
                _path_decision(
                    "issued_less_treasury",
                    tuple(selected_roots),
                    status="blocked",
                    issue="current_share_lineage_invalid",
                )
            )
        else:
            output = _derived_fact(
                issuer_id=security.issuer_id,
                quote_date=quote_date,
                value=value,
                derivation="issued-less-treasury/1.0.0",
                parents=tuple(selected_roots),
                documents=documents,
            )
            path_outputs.append(("issued_less_treasury", output, value))
            path_decisions.append(
                _path_decision(
                    "issued_less_treasury",
                    tuple(selected_roots),
                    status="eligible",
                    value=value,
                )
            )
    else:
        path_decisions.append(
            _path_decision(
                "issued_less_treasury",
                all_issued_facts,
                status="excluded",
                issue="current_share_evidence_missing",
            )
        )

    opening_candidates = tuple(
        item
        for item in graph.facts
        if _formal_window_share_fact(
            item,
            issuer_id=security.issuer_id,
            opening_date=None,
            quote_date=quote_date,
            cutoff=cutoff,
            documents=documents,
            concepts=frozenset({"common_shares_outstanding"}),
            allow_issued_opening=True,
        )
        is not None
    )
    latest_opening_date = max(
        (str(item.period["end"]) for item in opening_candidates), default=None
    )
    latest_openings = tuple(
        item for item in opening_candidates if item.period["end"] == latest_opening_date
    )
    opening_values = {
        item.fact_id: _decimal(item.value, "opening common shares") for item in latest_openings
    }
    opening, opening_conflict = _select_equivalent(
        latest_openings,
        values=opening_values,
        documents=documents,
        authoritative_ids=authority_ids,
    )
    event_facts = tuple(
        item
        for item in graph.facts
        if latest_opening_date is not None
        and _formal_window_share_fact(
            item,
            issuer_id=security.issuer_id,
            opening_date=latest_opening_date,
            quote_date=quote_date,
            cutoff=cutoff,
            documents=documents,
            concepts=frozenset(COMPLETED_SHARE_EVENT_SIGNS),
            include_quote_date=True,
        )
        is not None
    )
    split_facts = tuple(
        item
        for item in graph.facts
        if latest_opening_date is not None
        and _formal_window_share_fact(
            item,
            issuer_id=security.issuer_id,
            opening_date=latest_opening_date,
            quote_date=quote_date,
            cutoff=cutoff,
            documents=documents,
            concepts=_SPLIT_EVENT_CONCEPTS,
            include_quote_date=True,
        )
        is not None
    )
    reviewed_event_fact_ids = {
        str(binding["fact_id"])
        for event in graph.capital_allocation_events
        if event.issuer_id == security.issuer_id
        for binding in event.fact_bindings
    }
    reviewed_path = reviewed_event_fact_ids.intersection(
        item.fact_id for item in event_facts
    )
    coverage_authority_state = (
        _v2_coverage_authority_state(
            graph,
            issuer_id=security.issuer_id,
            opening_date=latest_opening_date,
            quote_date=quote_date,
            data_cutoff_date=str(artifact["data_cutoff_date"]),
        )
        if latest_opening_date is not None
        else "absent"
    )
    # Reviewed event identity is shared by the preserved sparse canonical path.  Only the
    # target-window V2 search authority distinguishes the richer Bundle/coverage contract.
    v2_authority_present = coverage_authority_state != "absent"
    if split_facts:
        return _result(
            artifact=artifact,
            security_id=security.security_id,
            quote_date=quote_date,
            status="specialist_required",
            paths=tuple(path_decisions),
            issues=("split_factor_unsupported",),
        )
    if opening_conflict:
        path_decisions.append(
            _path_decision(
                "completed_event_rollforward",
                latest_openings,
                status="blocked",
                issue="current_share_evidence_ambiguous",
            )
        )
    elif opening is not None and (event_facts or v2_authority_present):
        try:
            if coverage_authority_state == "incomplete":
                raise ValueError("target-bound V2 coverage authority is incomplete")
            if v2_authority_present and event_facts and not reviewed_path:
                raise ValueError(
                    "in-window completed share-event evidence lacks reviewed identity"
                )
            canonical_grouping = (
                group_governed_completed_share_events(
                    graph=graph,
                    issuer_id=security.issuer_id,
                    security_compilation_result=replayed_security,
                    opening_date=str(opening.period["end"]),
                    quote_date=quote_date,
                    data_cutoff_date=str(artifact["data_cutoff_date"]),
                )
                if reviewed_path or (v2_authority_present and not event_facts)
                else None
            )
            if canonical_grouping is not None and canonical_grouping.status != "grouped":
                raise ValueError("canonical share-event grouping is blocked")
            if canonical_grouping is not None:
                grouped_raw_fact_ids = {
                    member.fact_id for member in canonical_grouping.members
                }
                ungrouped_event_fact_ids = {
                    item.fact_id
                    for item in event_facts
                    if item.derivation != CANONICAL_EVENT_DERIVATION
                    and item.fact_id not in grouped_raw_fact_ids
                }
                if ungrouped_event_fact_ids:
                    raise ValueError(
                        "in-window completed share-event evidence is outside reviewed grouping"
                    )
            if (
                canonical_grouping is not None
                and v2_authority_present
            ):
                # The V2 Bundle constructor validates the official-occurrence collision domain
                # before its closure is projected into the compatibility roll-forward result.
                requires_claim_authority = any(
                    group.identity.event_concept in STANDARD_CLAIM_TRANSITION_EVENT_CONCEPTS
                    for group in canonical_grouping.groups
                )
                v2_claim_authority = (
                    GroupBoundDilutionClaimAuthority.from_price_blind_freeze(
                        freeze=loaded,
                        validation_graph=graph,
                    )
                    if requires_claim_authority
                    else None
                )
                canonical_v2_closure = derive_current_share_evidence_closure_v2(
                    graph=graph,
                    grouping_result=canonical_grouping,
                    opening_share_fact=opening,
                    security_compilation_result=replayed_security,
                    claim_control_authority=v2_claim_authority,
                    quote_date=quote_date,
                    data_cutoff_date=str(artifact["data_cutoff_date"]),
                    expected_research_bundle_id=str(
                        artifact["research_bundle"]["bundle_id"]
                    ),
                )
                output = canonical_v2_closure.output_share_fact
                canonical_rollforward = _canonical_rollforward_from_v2(canonical_v2_closure)
                canonical_event_facts = tuple(
                    item.canonical_event_fact for item in canonical_v2_closure.materializations
                )
                canonical = (output, canonical_rollforward, canonical_event_facts)
            elif canonical_grouping is not None:
                if (
                    derive_current_share_evidence_closure
                    is _derive_predecessor_evidence_closure
                ):
                    raise ValueError("reviewed canonical path lacks V2 evidence authority")
                canonical = _canonical_rollforward(
                    graph=graph,
                    opening=opening,
                    security=replayed_security,
                    issuer_id=security.issuer_id,
                    quote_date=quote_date,
                    data_cutoff_date=str(artifact["data_cutoff_date"]),
                )
            else:
                canonical = None
        except (KeyError, ShareEventGroupingError, ValueError):
            path_decisions.append(
                _path_decision(
                    "completed_event_rollforward",
                    (opening, *event_facts),
                    status="blocked",
                    issue="current_share_evidence_ambiguous",
                )
            )
        else:
            if canonical is None:
                legacy_semantic_keys = tuple(
                    (item.concept, str(item.period["end"])) for item in event_facts
                )
                if len(legacy_semantic_keys) != len(set(legacy_semantic_keys)):
                    path_decisions.append(
                        _path_decision(
                            "completed_event_rollforward",
                            (opening, *event_facts),
                            status="blocked",
                            issue="current_share_evidence_ambiguous",
                        )
                    )
                else:
                    try:
                        value = _decimal(opening.value, "opening common shares") + sum(
                            (
                                int(COMPLETED_SHARE_EVENT_SIGNS[item.concept])
                                * _decimal(item.value, "completed share event")
                                for item in event_facts
                            ),
                            0,
                        )
                        output = _derived_fact(
                            issuer_id=security.issuer_id,
                            quote_date=quote_date,
                            value=value,
                            derivation="completed-event-rollforward/1.0.0",
                            parents=(opening, *event_facts),
                            documents=documents,
                        )
                        path_outputs.append(
                            ("completed_event_rollforward", output, value)
                        )
                        path_decisions.append(
                            _path_decision(
                                "completed_event_rollforward",
                                (opening, *event_facts),
                                status="eligible",
                                value=value,
                            )
                        )
                    except ValueError:
                        path_decisions.append(
                            _path_decision(
                                "completed_event_rollforward",
                                (opening, *event_facts),
                                status="blocked",
                                issue="current_share_lineage_invalid",
                            )
                        )
            else:
                try:
                    output, canonical_rollforward, canonical_event_facts = canonical
                    value = _decimal(output.value, "canonical current shares")
                except ValueError:
                    canonical_rollforward = None
                    canonical_event_facts = ()
                    canonical_v2_closure = None
                    path_decisions.append(
                        _path_decision(
                            "completed_event_rollforward",
                            (opening, *event_facts),
                            status="blocked",
                            issue="current_share_lineage_invalid",
                        )
                    )
                else:
                    path_outputs.append(("completed_event_rollforward", output, value))
                    path_decisions.append(
                        _path_decision(
                            "completed_event_rollforward",
                            (opening, *canonical_event_facts),
                            status="eligible",
                            value=value,
                        )
                    )
    else:
        path_decisions.append(
            _path_decision(
                "completed_event_rollforward",
                (opening,) if opening is not None else (),
                status="excluded",
                issue="current_share_evidence_missing",
            )
        )

    if any(item.status == "blocked" for item in path_decisions):
        return _result(
            artifact=artifact,
            security_id=security.security_id,
            quote_date=quote_date,
            status="blocked",
            paths=tuple(path_decisions),
            issues=("current_share_evidence_ambiguous",),
        )
    if not path_outputs:
        return _result(
            artifact=artifact,
            security_id=security.security_id,
            quote_date=quote_date,
            status="blocked",
            paths=tuple(path_decisions),
            issues=("current_share_evidence_missing",),
        )
    if len({value for _, _, value in path_outputs}) != 1:
        return _result(
            artifact=artifact,
            security_id=security.security_id,
            quote_date=quote_date,
            status="blocked",
            paths=tuple(path_decisions),
            issues=("current_share_path_conflict",),
        )
    precedence = {name: index for index, name in enumerate(CURRENT_SHARE_PATH_KINDS)}
    selected_kind, selected_fact, _ = min(
        path_outputs, key=lambda item: precedence[item[0]]
    )
    selected_canonical_rollforward = (
        canonical_rollforward
        if selected_kind == "completed_event_rollforward"
        else None
    )
    selected_canonical_event_facts = (
        canonical_event_facts
        if selected_canonical_rollforward is not None
        else ()
    )
    selected_paths = tuple(
        replace(item, status="selected") if item.path_kind == selected_kind else item
        for item in path_decisions
    )
    decision_identity = canonical_sha256(
        (security.security_id, quote_date, selected_kind, selected_fact.fingerprint)
    )
    provisional = ShareBasisDecision(
        decision_id=f"share-basis-decision:{decision_identity[:24]}",
        policy_id=SHARE_BASIS_POLICY_ID,
        policy_version=SHARE_BASIS_POLICY_VERSION,
        issuer_id=security.issuer_id,
        security_id=security.security_id,
        share_fact_id=selected_fact.fact_id,
        basis_kind=SUPPORTED_SHARE_BASIS,
        evidence_kind=selected_kind,
        as_of_date=quote_date,
        quote_date=quote_date,
        split_factor="1",
        corporate_action_evidence_ids=(selected_fact.source_document_id,),
        disposition="eligible",
        reason_codes=(),
    )
    try:
        if selected_kind == "completed_event_rollforward" and canonical_v2_closure is not None:
            closure = canonical_v2_closure
            decision = replace(
                provisional,
                corporate_action_evidence_ids=_corporate_evidence_ids(closure),
            )
        else:
            replay_graph = graph
            for derived_fact in (*selected_canonical_event_facts, selected_fact):
                replay_graph = _overlay(replay_graph, derived_fact)
            closure = _derive_predecessor_closure(
                graph=replay_graph,
                share_fact=selected_fact,
                evidence_kind=selected_kind,
                trading_date=quote_date,
                data_cutoff_date=str(artifact["data_cutoff_date"]),
                security_compilation_result=replayed_security,
                share_basis_decision=provisional,
                claim_control_authority=claim_authority,
            )
            decision = replace(
                provisional,
                corporate_action_evidence_ids=_corporate_evidence_ids(closure),
            )
            closure = _derive_predecessor_closure(
                graph=replay_graph,
                share_fact=selected_fact,
                evidence_kind=selected_kind,
                trading_date=quote_date,
                data_cutoff_date=str(artifact["data_cutoff_date"]),
                security_compilation_result=replayed_security,
                share_basis_decision=decision,
                claim_control_authority=claim_authority,
            )
    except (CurrentShareEvidenceError, ValueError):
        return _result(
            artifact=artifact,
            security_id=security.security_id,
            quote_date=quote_date,
            status="blocked",
            paths=selected_paths,
            issues=("current_share_lineage_invalid",),
        )
    return _result(
        artifact=artifact,
        security_id=security.security_id,
        quote_date=quote_date,
        status="eligible",
        paths=selected_paths,
        issues=(),
        output_fact=selected_fact,
        decision=decision,
        closure=closure,
        canonical_rollforward=selected_canonical_rollforward,
    )


__all__ = ()
