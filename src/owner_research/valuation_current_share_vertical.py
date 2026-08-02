"""Deterministic production construction of the governed current-share V2 closure."""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
from typing import Any

from .contracts import Fact
from .fingerprints import canonical_sha256
from .research_bundle_policies import dependency_closure_sha256
from .research_bundle_validation import dependency_closure
from .validation import ContractGraph
from .valuation_current_share_evidence import (
    COMPLETED_SHARE_EVENT_SIGNS,
    EVENT_CONCEPT_TO_COVERAGE_CATEGORY,
)
from .valuation_security_identity import SecurityIdentityCompilationResult
from .valuation_share_event_identity import (
    SHARE_EVENT_GROUPING_POLICY_ID,
    SHARE_EVENT_GROUPING_POLICY_VERSION,
    ShareEventGroupingResult,
)
from .valuation_share_event_integration_types import (
    CANONICAL_EVENT_DERIVATION,
    COVERAGE_SEARCH_AUTHORITY_ID,
    COVERAGE_SEARCH_AUTHORITY_VERSION,
    COVERAGE_SEARCH_ENDPOINTS,
    COVERAGE_SEARCH_TOOL_VERSION,
    CURRENT_SHARE_EXTENSION_POLICY_ID,
    CURRENT_SHARE_EXTENSION_POLICY_VERSION,
    CURRENT_SHARE_INTEGRATION_POLICY_ID,
    CURRENT_SHARE_INTEGRATION_POLICY_VERSION,
    CURRENT_SHARE_ROLLFORWARD_CHANNEL,
    CURRENT_SHARE_ROLLFORWARD_DERIVATION,
    SPECIALIST_REQUIRED_CLAIM_TRANSITION_EVENT_CONCEPTS,
    STANDARD_CLAIM_TRANSITION_EVENT_CONCEPTS,
    CanonicalShareEventFactMaterialization,
    CanonicalShareEventMemberBinding,
    CorporateActionCoverageEntryV2,
    CorporateActionCoverageLedgerV2,
    CurrentShareBundleEvidenceClosure,
    CurrentShareEvidenceClosureV2,
    GroupBoundClaimTransition,
    GroupBoundClaimTransitionReconciliation,
    GroupBoundDilutionClaimAuthority,
    ShareEventNumericConsumption,
    _canonical_event_source_locator,
    _coverage_not_applicable_statement,
    _current_share_v2_closure_id,
    _output_share_source_locator,
    _primary_member_source_id,
    _remaining_claim_fact_id,
    _reserved_output_share_fact_id,
    _scoped_contract_graph_fingerprint,
    _typed_extension_dependency_closure,
    coverage_search_authority_sha256,
    current_share_integration_code_sha256,
    current_share_integration_contract_sha256,
    current_share_integration_policy_sha256,
)


def _integer(value: object, label: str, *, allow_zero: bool = False) -> int:
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


def _member_binding(
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
    candidates = {item.candidate_id: item for item in graph.capital_allocation_event_candidates}
    decisions = {item.decision_id: item for item in graph.capital_allocation_event_review_decisions}
    try:
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
    except KeyError as exc:
        raise ValueError("canonical share-event member has dangling lineage") from exc
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


def _materializations(
    *,
    graph: ContractGraph,
    grouping_result: ShareEventGroupingResult,
    issuer_id: str,
    security_id: str,
    data_cutoff_date: str,
) -> tuple[CanonicalShareEventFactMaterialization, ...]:
    members = {item.member_id: item for item in grouping_result.members}
    code_sha256 = current_share_integration_code_sha256()
    results: list[CanonicalShareEventFactMaterialization] = []
    for group in sorted(grouping_result.groups, key=lambda item: item.group_id):
        try:
            bindings = tuple(
                _member_binding(
                    graph=graph,
                    member=members[identifier],
                    issuer_id=issuer_id,
                    security_id=security_id,
                    data_cutoff_date=data_cutoff_date,
                )
                for identifier in group.member_ids
            )
        except KeyError as exc:
            raise ValueError("canonical group has a dangling member") from exc
        primary_source_id = _primary_member_source_id(bindings)
        canonical_fact_id = str(group.canonical_event_fact_id)
        magnitude = _integer(
            group.identity.canonical_share_magnitude,
            "canonical share-event magnitude",
        )
        canonical_fact = Fact(
            schema_version="2.0.0",
            fact_id=canonical_fact_id,
            issuer_id=issuer_id,
            concept=group.identity.event_concept,
            value_type="number",
            value=int(magnitude),
            unit="shares",
            currency=None,
            period={"start": None, "end": group.identity.legal_effective_date},
            source_document_id=primary_source_id,
            source_locator=_canonical_event_source_locator(canonical_fact_id),
            derivation=CANONICAL_EVENT_DERIVATION,
            parent_fact_ids=tuple(sorted(item.fact_id for item in bindings)),
            confidence="high",
        )
        payload = {
            "policy_id": CURRENT_SHARE_INTEGRATION_POLICY_ID,
            "policy_version": CURRENT_SHARE_INTEGRATION_POLICY_VERSION,
            "materialization_code_sha256": code_sha256,
            "issuer_id": issuer_id,
            "security_id": security_id,
            "opening_date": grouping_result.opening_date,
            "quote_date": grouping_result.quote_date,
            "data_cutoff_date": data_cutoff_date,
            "grouping_result": grouping_result,
            "group": group,
            "canonical_event_fact": canonical_fact,
            "grouping_result_fingerprint": grouping_result.grouping_fingerprint,
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
        results.append(
            CanonicalShareEventFactMaterialization(
                **payload,
                materialization_fingerprint=canonical_sha256(payload),
            )
        )
    return tuple(results)


def _consumptions(
    materializations: tuple[CanonicalShareEventFactMaterialization, ...],
    *,
    opening_date: str,
    quote_date: str,
) -> tuple[ShareEventNumericConsumption, ...]:
    results = []
    for item in materializations:
        payload = {
            "group_id": item.group_id,
            "group_fingerprint": item.group_fingerprint,
            "identity_fingerprint": item.identity_fingerprint,
            "canonical_event_fact_id": item.canonical_event_fact_id,
            "canonical_event_fact_fingerprint": item.canonical_event_fact_fingerprint,
            "event_concept": item.event_concept,
            "sign": format(COMPLETED_SHARE_EVENT_SIGNS[item.event_concept], "f"),
            "channel": CURRENT_SHARE_ROLLFORWARD_CHANNEL,
            "window_start": opening_date,
            "window_end": quote_date,
        }
        results.append(
            ShareEventNumericConsumption(
                **payload,
                consumption_fingerprint=canonical_sha256(payload),
            )
        )
    return tuple(results)


def _coverage_zero_facts(
    *,
    graph: ContractGraph,
    category: str,
    result_document_ids: set[str],
    opening_date: str,
    quote_date: str,
) -> tuple[Fact, ...]:
    results = []
    for item in graph.facts:
        if (
            item.concept != f"share_activity_{category}_count"
            or item.value_type != "number"
            or item.unit != "count"
            or item.currency is not None
            or item.period.get("start") != opening_date
            or item.period.get("end") != quote_date
            or item.source_document_id not in result_document_ids
            or item.derivation is not None
            or item.parent_fact_ids
            or item.confidence != "high"
        ):
            continue
        try:
            is_zero = _integer(item.value, "coverage zero Fact", allow_zero=True) == 0
        except ValueError:
            is_zero = False
        if is_zero:
            results.append(item)
    return tuple(sorted(results, key=lambda item: item.fact_id))


def _coverage_na_chains(
    *,
    graph: ContractGraph,
    statement: str,
) -> tuple[tuple[Any, Any, Any], ...]:
    claims = {item.claim_id: item for item in graph.claims}
    chains = []
    for candidate in graph.analytical_claim_candidates:
        if candidate.proposed_statement != statement or candidate.claim_role != "not_applicable":
            continue
        for decision in graph.analytical_claim_review_decisions:
            claim = claims.get(str(decision.output_claim_id))
            if (
                decision.candidate_id == candidate.candidate_id
                and decision.decision == "confirmed"
                and claim is not None
            ):
                chains.append((candidate, decision, claim))
    return tuple(chains)


def _coverage_entry(
    *,
    graph: ContractGraph,
    category: str,
    category_materializations: tuple[CanonicalShareEventFactMaterialization, ...],
    receipt_ids: tuple[str, ...],
    result_document_ids: set[str],
    security_id: str,
    opening_date: str,
    quote_date: str,
) -> CorporateActionCoverageEntryV2:
    zero_facts = _coverage_zero_facts(
        graph=graph,
        category=category,
        result_document_ids=result_document_ids,
        opening_date=opening_date,
        quote_date=quote_date,
    )
    chains = _coverage_na_chains(
        graph=graph,
        statement=_coverage_not_applicable_statement(category, security_id),
    )
    if category_materializations:
        if zero_facts or chains:
            raise ValueError("observed corporate-action coverage conflicts with no-activity proof")
        observed_facts = {
            member.fact_id: member.fact
            for materialization in category_materializations
            for member in materialization.members
        }
        observed_sources = {
            member.source_document_id: member.source_document
            for materialization in category_materializations
            for member in materialization.members
        }
        values = {
            "category": category,
            "status": "observed",
            "group_ids": tuple(item.group_id for item in category_materializations),
            "canonical_event_fact_ids": tuple(
                item.canonical_event_fact_id for item in category_materializations
            ),
            "member_event_fact_ids": tuple(sorted(observed_facts)),
            "observed_member_facts": tuple(
                sorted(observed_facts.values(), key=lambda item: item.fact_id)
            ),
            "observed_member_source_documents": tuple(
                sorted(observed_sources.values(), key=lambda item: item.document_id)
            ),
            "zero_fact_id": None,
            "zero_fact": None,
            "not_applicable_claim_id": None,
            "not_applicable_claim": None,
            "not_applicable_candidate": None,
            "review_decision_id": None,
            "review_decision": None,
            "not_applicable_supporting_facts": (),
            "not_applicable_counterevidence_facts": (),
            "source_search_receipt_ids": receipt_ids,
        }
    else:
        if len(zero_facts) == 1 and not chains:
            zero = zero_facts[0]
            values = {
                "category": category,
                "status": "official_zero_or_no_activity",
                "group_ids": (),
                "canonical_event_fact_ids": (),
                "member_event_fact_ids": (),
                "observed_member_facts": (),
                "observed_member_source_documents": (),
                "zero_fact_id": zero.fact_id,
                "zero_fact": zero,
                "not_applicable_claim_id": None,
                "not_applicable_claim": None,
                "not_applicable_candidate": None,
                "review_decision_id": None,
                "review_decision": None,
                "not_applicable_supporting_facts": (),
                "not_applicable_counterevidence_facts": (),
                "source_search_receipt_ids": receipt_ids,
            }
        elif not zero_facts and len(chains) == 1:
            candidate, decision, claim = chains[0]
            facts = {item.fact_id: item for item in graph.facts}

            def bound_facts(bindings: tuple[Any, ...]) -> tuple[Fact, ...]:
                try:
                    return tuple(
                        sorted(
                            (facts[str(item["fact_id"])] for item in bindings),
                            key=lambda item: item.fact_id,
                        )
                    )
                except KeyError as exc:
                    raise ValueError("coverage N/A chain has dangling Fact evidence") from exc

            supporting = bound_facts(candidate.supporting_evidence_bindings)
            counterevidence = bound_facts(candidate.counterevidence_bindings)
            values = {
                "category": category,
                "status": "not_applicable_with_reviewed_proof",
                "group_ids": (),
                "canonical_event_fact_ids": (),
                "member_event_fact_ids": (),
                "observed_member_facts": (),
                "observed_member_source_documents": (),
                "zero_fact_id": None,
                "zero_fact": None,
                "not_applicable_claim_id": claim.claim_id,
                "not_applicable_claim": claim,
                "not_applicable_candidate": candidate,
                "review_decision_id": decision.decision_id,
                "review_decision": decision,
                "not_applicable_supporting_facts": supporting,
                "not_applicable_counterevidence_facts": counterevidence,
                "source_search_receipt_ids": receipt_ids,
            }
        else:
            raise ValueError("corporate-action category coverage is ambiguous or incomplete")
    return CorporateActionCoverageEntryV2(
        **values,
        entry_fingerprint=canonical_sha256(values),
    )


def _coverage_ledger(
    *,
    graph: ContractGraph,
    materializations: tuple[CanonicalShareEventFactMaterialization, ...],
    issuer_id: str,
    security_id: str,
    opening_date: str,
    quote_date: str,
    data_cutoff_date: str,
) -> CorporateActionCoverageLedgerV2:
    receipts = tuple(
        sorted(
            (
                item
                for item in graph.source_search_receipts
                if item.issuer_id == issuer_id
                and item.cutoff_date == data_cutoff_date
                and str(item.period["start"]) <= opening_date
                and str(item.period["end"]) >= quote_date
                and item.tool_version == COVERAGE_SEARCH_TOOL_VERSION
                and item.searched_endpoints
                == COVERAGE_SEARCH_ENDPOINTS.get(item.source_family)
            ),
            key=lambda item: item.source_family,
        )
    )
    receipt_ids = tuple(sorted(item.receipt_id for item in receipts))
    ciks = {str(item.query_scope["cik"]) for item in receipts}
    if len(ciks) != 1:
        raise ValueError("coverage receipts do not bind one issuer CIK")
    result_document_ids = {
        identifier for item in receipts for identifier in item.result_document_ids
    }
    documents = {item.document_id: item for item in graph.documents}
    try:
        result_documents = tuple(
            sorted(
                (documents[identifier] for identifier in result_document_ids),
                key=lambda item: item.document_id,
            )
        )
    except KeyError as exc:
        raise ValueError("coverage receipt has a dangling SourceDocument") from exc
    by_category: dict[str, list[CanonicalShareEventFactMaterialization]] = {}
    for item in materializations:
        by_category.setdefault(EVENT_CONCEPT_TO_COVERAGE_CATEGORY[item.event_concept], []).append(
            item
        )
    entries = tuple(
        _coverage_entry(
            graph=graph,
            category=category,
            category_materializations=tuple(
                sorted(by_category.get(category, ()), key=lambda item: item.group_id)
            ),
            receipt_ids=receipt_ids,
            result_document_ids=result_document_ids,
            security_id=security_id,
            opening_date=opening_date,
            quote_date=quote_date,
        )
        for category in CorporateActionCoverageLedgerV2.required_categories()
    )
    payload = {
        "issuer_id": issuer_id,
        "issuer_cik": next(iter(ciks)),
        "security_id": security_id,
        "period_start": opening_date,
        "period_end": quote_date,
        "data_cutoff_date": data_cutoff_date,
        "expected_group_ids": tuple(item.group_id for item in materializations),
        "entries": tuple(sorted(entries, key=lambda item: item.category)),
        "receipts": receipts,
        "result_source_documents": result_documents,
        "receipt_ids": receipt_ids,
        "search_authority_id": COVERAGE_SEARCH_AUTHORITY_ID,
        "search_authority_version": COVERAGE_SEARCH_AUTHORITY_VERSION,
        "search_authority_code_sha256": coverage_search_authority_sha256(),
    }
    return CorporateActionCoverageLedgerV2(
        **payload,
        ledger_sha256=canonical_sha256(payload),
    )


def _direct_fact_binding_ids(bindings: tuple[Any, ...]) -> tuple[str, ...]:
    fact_ids: list[str] = []
    for binding in bindings:
        fact_id = binding.get("fact_id")
        if (
            fact_id is None
            or binding.get("calculation_result_id") is not None
            or binding.get("context_observation_id") is not None
        ):
            raise ValueError("claim-transition review evidence must bind direct Facts")
        fact_ids.append(str(fact_id))
    if len(fact_ids) != len(set(fact_ids)):
        raise ValueError("claim-transition review evidence repeats a Fact")
    return tuple(fact_ids)


def _reviewed_transition_candidates(
    *,
    graph: ContractGraph,
    materialization: CanonicalShareEventFactMaterialization,
    initial_root_fact_id: str,
    affected_fact_id: str,
    economic_claim_key: str,
) -> tuple[GroupBoundClaimTransition, ...]:
    facts = {item.fact_id: item for item in graph.facts}
    documents = {item.document_id: item for item in graph.documents}
    claims = {item.claim_id: item for item in graph.claims}
    remaining_fact_id = _remaining_claim_fact_id(
        issuer_id=materialization.issuer_id,
        economic_claim_key=economic_claim_key,
        group_id=materialization.group_id,
        affected_claim_root_fact_id=affected_fact_id,
        legal_effective_date=materialization.legal_effective_date,
    )
    affected_fact = facts.get(affected_fact_id)
    remaining_fact = facts.get(remaining_fact_id)
    if affected_fact is None or remaining_fact is None:
        return ()
    try:
        affected_source = documents[affected_fact.source_document_id]
        remaining_source = documents[remaining_fact.source_document_id]
    except KeyError as exc:
        raise ValueError("claim transition has a dangling source") from exc
    required_support = {
        affected_fact_id,
        remaining_fact_id,
        *(member.fact_id for member in materialization.members),
    }
    results: list[GroupBoundClaimTransition] = []
    decisions_by_candidate: dict[str, list[Any]] = {}
    for decision in graph.analytical_claim_review_decisions:
        decisions_by_candidate.setdefault(decision.candidate_id, []).append(decision)
    for candidate in graph.analytical_claim_candidates:
        try:
            supporting_ids = _direct_fact_binding_ids(candidate.supporting_evidence_bindings)
            counterevidence_ids = _direct_fact_binding_ids(candidate.counterevidence_bindings)
        except ValueError:
            continue
        if not required_support.issubset(supporting_ids):
            continue
        evidence_ids = set((*supporting_ids, *counterevidence_ids))
        try:
            evidence_facts = tuple(
                sorted(
                    (facts[identifier] for identifier in evidence_ids),
                    key=lambda item: item.fact_id,
                )
            )
            evidence_sources = tuple(
                sorted(
                    {
                        facts[identifier].source_document_id: documents[
                            facts[identifier].source_document_id
                        ]
                        for identifier in evidence_ids
                    }.values(),
                    key=lambda item: item.document_id,
                )
            )
        except KeyError as exc:
            raise ValueError("claim transition has dangling reviewed evidence") from exc
        for decision in decisions_by_candidate.get(candidate.candidate_id, ()):
            claim = claims.get(str(decision.output_claim_id))
            if claim is None:
                continue
            payload = {
                "claim_lineage_id": "claim-lineage:"
                + canonical_sha256(
                    {
                        "issuer_id": affected_fact.issuer_id,
                        "security_root_fact_id": initial_root_fact_id,
                    }
                )[:24],
                "economic_claim_key": economic_claim_key,
                "initial_claim_root_fact_id": initial_root_fact_id,
                "group_id": materialization.group_id,
                "group_fingerprint": materialization.group_fingerprint,
                "identity_fingerprint": materialization.identity_fingerprint,
                "canonical_event_fact_id": materialization.canonical_event_fact_id,
                "canonical_event_fact_fingerprint": (
                    materialization.canonical_event_fact_fingerprint
                ),
                "event_concept": materialization.event_concept,
                "legal_effective_date": materialization.legal_effective_date,
                "canonical_share_magnitude": materialization.canonical_share_magnitude,
                "affected_claim_root_fact_id": affected_fact.fact_id,
                "affected_claim_root_fact_fingerprint": affected_fact.fingerprint,
                "affected_claim_value": str(affected_fact.value),
                "affected_claim_root_fact": affected_fact,
                "affected_claim_source_document": affected_source,
                "remaining_claim_fact_id": remaining_fact.fact_id,
                "remaining_claim_fact_fingerprint": remaining_fact.fingerprint,
                "remaining_claim_value": str(remaining_fact.value),
                "remaining_claim_fact": remaining_fact,
                "remaining_claim_source_document": remaining_source,
                "evidence_facts": evidence_facts,
                "evidence_source_documents": evidence_sources,
                "claims": (claim,),
                "candidates": (candidate,),
                "review_decisions": (decision,),
                "claim_bindings": ((claim.claim_id, claim.fingerprint),),
                "candidate_bindings": ((candidate.candidate_id, candidate.fingerprint),),
                "review_decision_bindings": ((decision.decision_id, decision.fingerprint),),
                "disposition": (
                    "extinguished"
                    if _integer(
                        remaining_fact.value,
                        "remaining claim value",
                        allow_zero=True,
                    )
                    == 0
                    else "remaining_claim_rebound"
                ),
            }
            try:
                results.append(
                    GroupBoundClaimTransition(
                        **payload,
                        transition_fingerprint=canonical_sha256(payload),
                    )
                )
            except ValueError:
                continue
    return tuple(results)


def _claim_transitions(
    *,
    graph: ContractGraph,
    materializations: tuple[CanonicalShareEventFactMaterialization, ...],
    issuer_id: str,
    security_id: str,
    opening_date: str,
    quote_date: str,
    data_cutoff_date: str,
    claim_control_authority: object,
) -> GroupBoundClaimTransitionReconciliation:
    specialist = tuple(
        item
        for item in materializations
        if item.event_concept in SPECIALIST_REQUIRED_CLAIM_TRANSITION_EVENT_CONCEPTS
    )
    if specialist:
        raise ValueError("canonical share event requires specialist claim-transition authority")
    sensitive = tuple(
        item
        for item in materializations
        if item.event_concept in STANDARD_CLAIM_TRANSITION_EVENT_CONCEPTS
    )
    records: tuple[GroupBoundClaimTransition, ...] = ()
    authority: GroupBoundDilutionClaimAuthority | None = None
    if sensitive:
        if type(claim_control_authority) is not GroupBoundDilutionClaimAuthority:
            raise ValueError("standard claim-sensitive event lacks full-freeze claim authority")
        authority = claim_control_authority
        active_roots = {
            initial_root_id: (initial_root_id, economic_claim_key)
            for initial_root_id, economic_claim_key in authority.root_economic_claim_bindings
        }
        built: list[GroupBoundClaimTransition] = []
        for materialization in sorted(
            sensitive,
            key=lambda item: (item.legal_effective_date, item.group_id),
        ):
            matches = tuple(
                transition
                for initial_root_id, (affected_fact_id, economic_claim_key) in active_roots.items()
                for transition in _reviewed_transition_candidates(
                    graph=graph,
                    materialization=materialization,
                    initial_root_fact_id=initial_root_id,
                    affected_fact_id=affected_fact_id,
                    economic_claim_key=economic_claim_key,
                )
            )
            if len(matches) != 1:
                raise ValueError("claim-sensitive group has ambiguous reviewed transitions")
            transition = matches[0]
            built.append(transition)
            if transition.disposition == "extinguished":
                del active_roots[transition.initial_claim_root_fact_id]
            else:
                active_roots[transition.initial_claim_root_fact_id] = (
                    transition.remaining_claim_fact_id,
                    transition.economic_claim_key,
                )
        records = tuple(built)
    elif claim_control_authority is not None:
        raise ValueError("ordinary canonical events cannot carry dilution claim authority")
    payload = {
        "issuer_id": issuer_id,
        "security_id": security_id,
        "opening_date": opening_date,
        "quote_date": quote_date,
        "data_cutoff_date": data_cutoff_date,
        "claim_control_authority": authority,
        "claim_control_authority_fingerprint": (
            authority.authority_fingerprint if authority is not None else None
        ),
        "expected_claim_sensitive_group_ids": tuple(sorted(item.group_id for item in sensitive)),
        "records": records,
    }
    return GroupBoundClaimTransitionReconciliation(
        **payload,
        reconciliation_sha256=canonical_sha256(payload),
    )


def _bundle_closure(
    *,
    graph: ContractGraph,
    opening_share_fact: Fact,
    materializations: tuple[CanonicalShareEventFactMaterialization, ...],
    coverage: CorporateActionCoverageLedgerV2,
    transitions: GroupBoundClaimTransitionReconciliation,
    grouping_result: ShareEventGroupingResult,
    security_compilation_result: SecurityIdentityCompilationResult,
    reserved_output_share_fact_id: str,
    expected_research_bundle_id: str,
) -> CurrentShareBundleEvidenceClosure:
    bundles = tuple(
        item
        for item in graph.research_bundles
        if item.bundle_id == expected_research_bundle_id
        and item.issuer_id == grouping_result.issuer_id
        and item.data_cutoff_date == coverage.data_cutoff_date
    )
    if len(bundles) != 1:
        raise ValueError("current-share V2 closure requires one graph-owned ResearchBundle")
    research_bundle = bundles[0]
    manifests = tuple(item for item in graph.manifests if item.run_id == research_bundle.run_id)
    if len(manifests) != 1:
        raise ValueError("current-share V2 closure requires one graph-owned RunManifest")
    run_manifest = manifests[0]
    security_closure = security_compilation_result.evidence_closure
    if security_closure is None:
        raise ValueError("current-share V2 closure lacks security evidence")
    opening_sources = tuple(
        item
        for item in graph.documents
        if item.document_id == opening_share_fact.source_document_id
    )
    if len(opening_sources) != 1:
        raise ValueError("current-share V2 opening SourceDocument is not unique")
    opening_source = opening_sources[0]
    opening_filing_artifacts = tuple(
        item
        for item in graph.filing_artifacts
        if item.issuer_id == grouping_result.issuer_id
        and item.cik == coverage.issuer_cik
        and item.source_document_id == opening_share_fact.source_document_id
        and item.form == opening_source.document_type
        and item.filing_date == opening_source.published_date
        and item.report_period == opening_source.period["end"]
        and str(opening_share_fact.period["end"]) <= item.report_period
        and item.retrieved_at == opening_source.retrieved_at
        and item.raw_sha256 == opening_source.content_sha256
        and item.filing_date <= coverage.data_cutoff_date
        and item.report_period <= coverage.data_cutoff_date
        and any(
            receipt.source_family == item.form
            and item.source_document_id in receipt.result_document_ids
            for receipt in coverage.receipts
        )
    )
    if len(opening_filing_artifacts) != 1:
        raise ValueError(
            "current-share V2 closure lacks one receipt-bound opening FilingArtifact"
        )
    extension_roots: set[str] = {
        opening_share_fact.fact_id,
        opening_filing_artifacts[0].artifact_id,
        *(item.receipt_id for item in coverage.receipts),
    }
    for materialization in materializations:
        for member in materialization.members:
            extension_roots.update(
                {
                    member.fact_id,
                    member.capital_allocation_event_id,
                    *(identifier for identifier, _ in member.candidate_bindings),
                    *(identifier for identifier, _ in member.review_decision_bindings),
                }
            )
    for entry in coverage.entries:
        if entry.zero_fact is not None:
            extension_roots.add(entry.zero_fact.fact_id)
        if entry.not_applicable_claim_id is not None:
            extension_roots.add(entry.not_applicable_claim_id)
        if entry.not_applicable_candidate is not None:
            extension_roots.add(entry.not_applicable_candidate.candidate_id)
            for binding in (
                *entry.not_applicable_candidate.supporting_evidence_bindings,
                *entry.not_applicable_candidate.counterevidence_bindings,
            ):
                extension_roots.update(
                    str(binding[field_name])
                    for field_name in (
                        "fact_id",
                        "calculation_result_id",
                        "context_observation_id",
                    )
                    if binding[field_name] is not None
                )
        if entry.review_decision_id is not None:
            extension_roots.add(entry.review_decision_id)
    for transition in transitions.records:
        extension_roots.update(
            {
                transition.affected_claim_root_fact_id,
                transition.remaining_claim_fact_id,
                *(item.claim_id for item in transition.claims),
                *(item.candidate_id for item in transition.candidates),
                *(item.decision_id for item in transition.review_decisions),
            }
        )
        for candidate in transition.candidates:
            for binding in (
                *candidate.supporting_evidence_bindings,
                *candidate.counterevidence_bindings,
            ):
                extension_roots.update(
                    str(binding[field_name])
                    for field_name in (
                        "fact_id",
                        "calculation_result_id",
                        "context_observation_id",
                    )
                    if binding[field_name] is not None
                )
    authority = transitions.claim_control_authority
    if authority is not None:
        extension_roots.update(
            object_id
            for contract_type, object_id, _ in authority.phase5c_review_object_fingerprints
            if contract_type != "SourceDocument"
        )
    extension_roots.update(
        {
            *security_closure.fact_ids,
            security_closure.claim_id,
            security_closure.candidate_id,
            security_closure.review_decision_id,
        }
    )
    public_roots = tuple(
        str(object_id)
        for reference in research_bundle.module_references
        for object_id in reference["object_ids"]
    )
    public_closure = dependency_closure(graph, public_roots)
    base_bindings = tuple(
        sorted(
            (contract_type, object_id, item.fingerprint)
            for object_id, (contract_type, item) in public_closure.items()
        )
    )
    extension_closure = _typed_extension_dependency_closure(
        graph,
        tuple(sorted(extension_roots)),
    )
    extension_bindings = tuple(
        sorted(
            (contract_type, object_id, item.fingerprint)
            for object_id, (contract_type, item) in extension_closure.items()
            if object_id not in public_closure
        )
    )
    bindings = tuple(sorted((*base_bindings, *extension_bindings)))
    source_documents = tuple(
        sorted(
            (
                item
                for _, (contract_type, item) in extension_closure.items()
                if contract_type == "SourceDocument"
            ),
            key=lambda item: item.document_id,
        )
    )
    payload = {
        "research_bundle": research_bundle,
        "run_manifest": run_manifest,
        "research_bundle_id": research_bundle.bundle_id,
        "research_bundle_fingerprint": research_bundle.bundle_fingerprint,
        "issuer_id": grouping_result.issuer_id,
        "issuer_cik": coverage.issuer_cik,
        "data_cutoff_date": coverage.data_cutoff_date,
        "component_lock_sha256": research_bundle.component_lock_sha256,
        "dependency_closure_sha256": research_bundle.dependency_closure_sha256,
        "current_share_dependency_closure_sha256": dependency_closure_sha256(list(bindings)),
        "extension_policy_id": CURRENT_SHARE_EXTENSION_POLICY_ID,
        "extension_policy_version": CURRENT_SHARE_EXTENSION_POLICY_VERSION,
        "integration_contract_sha256": current_share_integration_contract_sha256(),
        "integration_policy_sha256": current_share_integration_policy_sha256(),
        "integration_code_sha256": current_share_integration_code_sha256(),
        "run_manifest_id": run_manifest.run_id,
        "security_compilation_result": security_compilation_result,
        "security_compilation_fingerprint": security_compilation_result.fingerprint,
        "grouping_result": grouping_result,
        "grouping_result_fingerprint": grouping_result.grouping_fingerprint,
        "opening_share_fact": opening_share_fact,
        "canonical_event_materializations": materializations,
        "canonical_event_fact_bindings": tuple(
            sorted(
                (
                    item.canonical_event_fact_id,
                    item.canonical_event_fact_fingerprint,
                )
                for item in materializations
            )
        ),
        "reserved_output_share_fact_id": reserved_output_share_fact_id,
        "claim_control_authority": authority,
        "claim_control_authority_fingerprint": (
            authority.authority_fingerprint if authority is not None else None
        ),
        "source_documents": source_documents,
        "base_dependency_object_fingerprints": base_bindings,
        "extension_root_ids": tuple(sorted(extension_roots)),
        "extension_object_fingerprints": extension_bindings,
        "object_fingerprints": bindings,
        "contract_graph_fingerprint": _scoped_contract_graph_fingerprint(graph, bindings),
    }
    return CurrentShareBundleEvidenceClosure(
        **payload,
        closure_sha256=canonical_sha256(payload),
        validation_graph=graph,
    )


def derive_v2_closure(
    *,
    graph: ContractGraph,
    grouping_result: ShareEventGroupingResult,
    opening_share_fact: Fact,
    security_compilation_result: SecurityIdentityCompilationResult,
    claim_control_authority: object,
    quote_date: str,
    data_cutoff_date: str,
    expected_research_bundle_id: str,
) -> CurrentShareEvidenceClosureV2:
    """Build the exact typed closure from graph-owned reviewed evidence only."""

    graph.validate()
    decision = security_compilation_result.decision
    if (
        decision is None
        or security_compilation_result.status != "eligible"
        or grouping_result.issuer_id != opening_share_fact.issuer_id
        or grouping_result.issuer_id != decision.issuer_id
        or grouping_result.security_id != decision.security_id
        or grouping_result.opening_date != opening_share_fact.period.get("end")
        or grouping_result.quote_date != quote_date
        or grouping_result.status != "grouped"
    ):
        raise ValueError("current-share V2 inputs do not share one governed identity")
    graph_openings = tuple(
        item for item in graph.facts if item.fact_id == opening_share_fact.fact_id
    )
    if len(graph_openings) != 1 or graph_openings[0] != opening_share_fact:
        raise ValueError("opening-share Fact is not graph-owned")
    issuer_id = decision.issuer_id
    security_id = decision.security_id
    opening_date = str(opening_share_fact.period["end"])
    materializations = _materializations(
        graph=graph,
        grouping_result=grouping_result,
        issuer_id=issuer_id,
        security_id=security_id,
        data_cutoff_date=data_cutoff_date,
    )
    coverage = _coverage_ledger(
        graph=graph,
        materializations=materializations,
        issuer_id=issuer_id,
        security_id=security_id,
        opening_date=opening_date,
        quote_date=quote_date,
        data_cutoff_date=data_cutoff_date,
    )
    transitions = _claim_transitions(
        graph=graph,
        materializations=materializations,
        issuer_id=issuer_id,
        security_id=security_id,
        opening_date=opening_date,
        quote_date=quote_date,
        data_cutoff_date=data_cutoff_date,
        claim_control_authority=claim_control_authority,
    )
    output_fact_id = _reserved_output_share_fact_id(
        issuer_id=issuer_id,
        security_id=security_id,
        quote_date=quote_date,
        opening_share_fact_id=opening_share_fact.fact_id,
        grouping_result_fingerprint=grouping_result.grouping_fingerprint,
    )
    # Construct the Bundle closure before numeric consumption.  Its frozen constructor owns the
    # official-occurrence collision domain and rejects economic-event-key drift across groups.
    bundle = _bundle_closure(
        graph=graph,
        opening_share_fact=opening_share_fact,
        materializations=materializations,
        coverage=coverage,
        transitions=transitions,
        grouping_result=grouping_result,
        security_compilation_result=security_compilation_result,
        reserved_output_share_fact_id=output_fact_id,
        expected_research_bundle_id=expected_research_bundle_id,
    )
    consumptions = _consumptions(
        materializations,
        opening_date=opening_date,
        quote_date=quote_date,
    )
    output_value = _integer(opening_share_fact.value, "opening common shares") + sum(
        (
            int(COMPLETED_SHARE_EVENT_SIGNS[item.event_concept])
            * _integer(item.canonical_share_magnitude, "canonical share-event magnitude")
            for item in materializations
        ),
        0,
    )
    if output_value <= 0:
        raise ValueError("canonical share-event roll-forward is non-positive")
    parents = tuple(
        sorted(
            (
                opening_share_fact.fact_id,
                *(item.canonical_event_fact_id for item in materializations),
            )
        )
    )
    output_fact = Fact(
        schema_version="2.0.0",
        fact_id=output_fact_id,
        issuer_id=issuer_id,
        concept="common_shares_outstanding",
        value_type="number",
        value=int(output_value),
        unit="shares",
        currency=None,
        period={"start": None, "end": quote_date},
        source_document_id=opening_share_fact.source_document_id,
        source_locator=_output_share_source_locator(output_fact_id),
        derivation=CURRENT_SHARE_ROLLFORWARD_DERIVATION,
        parent_fact_ids=parents,
        confidence="high",
    )
    edges = tuple(
        sorted(
            {
                *((output_fact.fact_id, parent) for parent in parents),
                *(
                    (item.canonical_event_fact_id, member.fact_id)
                    for item in materializations
                    for member in item.members
                ),
            }
        )
    )
    object_map = {
        (contract_type, object_id): (contract_type, object_id, fingerprint)
        for contract_type, object_id, fingerprint in bundle.object_fingerprints
    }
    object_map[("Fact", output_fact.fact_id)] = (
        "Fact",
        output_fact.fact_id,
        output_fact.fingerprint,
    )
    for item in materializations:
        object_map[("Fact", item.canonical_event_fact_id)] = (
            "Fact",
            item.canonical_event_fact_id,
            item.canonical_event_fact_fingerprint,
        )
    object_fingerprints = tuple(sorted(object_map.values()))
    numeric_lineage_sha256 = canonical_sha256(
        {
            "opening_fact": opening_share_fact.to_dict(),
            "output_fact": output_fact.to_dict(),
            "materialization_fingerprints": [
                item.materialization_fingerprint for item in materializations
            ],
            "consumption_fingerprints": [item.consumption_fingerprint for item in consumptions],
            "fact_parent_edges": edges,
        }
    )
    extension_sources = {item.document_id: item for item in bundle.source_documents}
    security_closure = security_compilation_result.evidence_closure
    if security_closure is None:
        raise ValueError("current-share V2 closure lacks security evidence")
    source_closure_sha256 = canonical_sha256(
        {
            "member_sources": sorted(
                {
                    (member.source_document_id, member.source_document_fingerprint)
                    for item in materializations
                    for member in item.members
                }
            ),
            "receipt_fingerprints": sorted(
                (item.receipt_id, item.fingerprint) for item in coverage.receipts
            ),
            "opening_source": (
                opening_share_fact.source_document_id,
                extension_sources[opening_share_fact.source_document_id].fingerprint,
            ),
            "coverage_zero_sources": sorted(
                (
                    item.zero_fact.source_document_id,
                    extension_sources[item.zero_fact.source_document_id].fingerprint,
                )
                for item in coverage.entries
                if item.zero_fact is not None
            ),
            "claim_transition_sources": sorted(
                {
                    (source.document_id, source.fingerprint)
                    for transition in transitions.records
                    for source in transition.evidence_source_documents
                }
            ),
            "security_sources": sorted(
                (identifier, extension_sources[identifier].fingerprint)
                for identifier in security_closure.source_document_ids
            ),
            "extension_sources": sorted(
                (item.document_id, item.fingerprint) for item in extension_sources.values()
            ),
        }
    )
    temporal_closure_sha256 = canonical_sha256(
        {
            "issuer_id": issuer_id,
            "security_id": security_id,
            "opening_date": opening_date,
            "quote_date": quote_date,
            "data_cutoff_date": data_cutoff_date,
            "event_effective_dates": sorted(item.legal_effective_date for item in materializations),
            "member_dates": sorted(
                (
                    member.member.fact_measurement_date,
                    member.member.source_published_date,
                    member.member.data_cutoff_date,
                )
                for item in materializations
                for member in item.members
            ),
            "receipt_periods": sorted(
                (
                    item.source_family,
                    item.period["start"],
                    item.period["end"],
                    item.cutoff_date,
                )
                for item in coverage.receipts
            ),
            "claim_transition_evidence_dates": sorted(
                (
                    fact.fact_id,
                    fact.period["end"],
                    extension_sources[fact.source_document_id].published_date,
                )
                for transition in transitions.records
                for fact in transition.evidence_facts
            ),
        }
    )
    payload = {
        "closure_id": _current_share_v2_closure_id(
            issuer_id=issuer_id,
            security_id=security_id,
            quote_date=quote_date,
            opening_share_fact_id=opening_share_fact.fact_id,
            output_share_fact_id=output_fact.fact_id,
            grouping_result_fingerprint=grouping_result.grouping_fingerprint,
        ),
        "issuer_id": issuer_id,
        "security_id": security_id,
        "quote_date": quote_date,
        "data_cutoff_date": data_cutoff_date,
        "grouping_result": grouping_result,
        "opening_share_fact": opening_share_fact,
        "output_share_fact": output_fact,
        "output_share_fact_id": output_fact.fact_id,
        "output_share_fact_fingerprint": output_fact.fingerprint,
        "opening_share_fact_id": opening_share_fact.fact_id,
        "rollforward_parent_fact_ids": parents,
        "ultimate_numeric_root_fact_ids": tuple(
            sorted(
                {
                    opening_share_fact.fact_id,
                    *(member.fact_id for item in materializations for member in item.members),
                }
            )
        ),
        "materializations": materializations,
        "numeric_consumptions": consumptions,
        "bundle_evidence_closure": bundle,
        "coverage_ledger": coverage,
        "claim_transition_reconciliation": transitions,
        "fact_parent_edges": edges,
        "object_fingerprints": object_fingerprints,
        "grouping_policy_id": SHARE_EVENT_GROUPING_POLICY_ID,
        "grouping_policy_version": SHARE_EVENT_GROUPING_POLICY_VERSION,
        "grouping_code_sha256": grouping_result.grouping_code_sha256,
        "integration_contract_sha256": current_share_integration_contract_sha256(),
        "integration_policy_sha256": current_share_integration_policy_sha256(),
        "integration_code_sha256": current_share_integration_code_sha256(),
        "grouping_result_fingerprint": grouping_result.grouping_fingerprint,
        "numeric_lineage_sha256": numeric_lineage_sha256,
        "coverage_closure_sha256": coverage.ledger_sha256,
        "claim_transition_sha256": transitions.reconciliation_sha256,
        "source_closure_sha256": source_closure_sha256,
        "temporal_closure_sha256": temporal_closure_sha256,
    }
    return CurrentShareEvidenceClosureV2(
        **payload,
        closure_sha256=canonical_sha256(payload),
    )


__all__ = ()
