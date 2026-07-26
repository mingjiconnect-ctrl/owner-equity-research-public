from __future__ import annotations

import copy
import inspect
from dataclasses import FrozenInstanceError, replace

import pytest
from jsonschema import ValidationError
from phase4a_support import replace_graph
from phase5e2a_support import (
    OPTION_CLAIM_KEY,
    OPTION_ROOT_ID,
    PHASE5C_DILUTED_ROOT_ID,
    resign_price_blind_artifact,
    resign_snapshot,
    valid_snapshot_graph,
)

import owner_research
from owner_research.contracts import MarketReferenceSnapshot, contract_from_dict
from owner_research.fingerprints import canonical_sha256
from owner_research.schema_store import validate_payload
from owner_research.validation import ContractGraphError
from owner_research.valuation_current_share_evidence import COMPLETED_SHARE_EVENT_SIGNS
from owner_research.valuation_handoff_validation import (
    ValuationHandoffValidationError,
    _validate_current_share_lineage,
)
from owner_research.valuation_market_reference_types import (
    MarketReferenceValidationContext,
    Phase5CDilutionClaimAuthority,
)


def test_market_reference_snapshot_v3_schema_is_closed_and_v2_is_a_hard_break(
    sample_payloads,
) -> None:
    payload = sample_payloads["market-reference-snapshot"]
    validate_payload("market-reference-snapshot", payload)
    assert payload["schema_version"] == "3.0.0"

    legacy = {
        "schema_version": "2.0.0",
        "snapshot_id": "legacy-market-reference",
        "issuer_id": "issuer:acme",
    }
    with pytest.raises(ValidationError):
        validate_payload("market-reference-snapshot", legacy)

    unknown = copy.deepcopy(payload)
    unknown["builder_output"] = True
    with pytest.raises(ValidationError):
        validate_payload("market-reference-snapshot", unknown)


@pytest.mark.parametrize(
    "value",
    (0, 50.0, "0", "-1", "+1", "01", "1e3", "NaN", "Infinity", "1,000"),
)
def test_snapshot_rejects_noncanonical_or_nonpositive_quote_decimal(
    sample_payloads,
    value,
) -> None:
    payload = copy.deepcopy(sample_payloads["market-reference-snapshot"])
    payload["quote_price_decimal"] = value
    with pytest.raises((ValidationError, ValueError)):
        contract_from_dict("market-reference-snapshot", payload)


@pytest.mark.parametrize(
    ("path", "value"),
    (
        (("quote_price_decimal",), "0"),
        (("share_basis", "current_common_shares_outstanding_decimal"), "0.0"),
        (("market_equity", "value_decimal"), "0.000"),
    ),
)
def test_public_schema_itself_rejects_zero_positive_decimals(
    sample_payloads,
    path,
    value,
) -> None:
    payload = copy.deepcopy(sample_payloads["market-reference-snapshot"])
    target = payload
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(ValidationError):
        validate_payload("market-reference-snapshot", payload)


def test_snapshot_schema_rejects_split_shortcut_and_fixture_valuation_use(
    sample_payloads,
) -> None:
    split = copy.deepcopy(sample_payloads["market-reference-snapshot"])
    split["share_basis"]["split_factor_decimal"] = "2"
    with pytest.raises(ValidationError):
        validate_payload("market-reference-snapshot", split)

    promoted = copy.deepcopy(sample_payloads["market-reference-snapshot"])
    promoted["usage_scope"] = "valuation_eligible"
    with pytest.raises(ValidationError):
        validate_payload("market-reference-snapshot", promoted)


def test_snapshot_is_immutable_and_uses_its_sealed_self_fingerprint(
    sample_payloads,
) -> None:
    snapshot = contract_from_dict(
        "market-reference-snapshot",
        sample_payloads["market-reference-snapshot"],
    )
    assert isinstance(snapshot, MarketReferenceSnapshot)
    assert snapshot.fingerprint == snapshot.snapshot_fingerprint
    with pytest.raises(FrozenInstanceError):
        snapshot.status = "changed"  # type: ignore[misc]

    forged = snapshot.to_dict()
    forged["market_evidence_closure_sha256"] = "9" * 64
    with pytest.raises(ValueError, match="fingerprint mismatch"):
        MarketReferenceSnapshot(**forged)


def test_validation_context_is_internal_closed_and_has_no_builder_surface() -> None:
    assert MarketReferenceValidationContext.__module__.endswith("valuation_market_reference_types")
    assert not hasattr(owner_research, "MarketReferenceValidationContext")
    for module in (
        owner_research,
        __import__("owner_research.valuation_market_reference_types", fromlist=["x"]),
    ):
        for forbidden in (
            "build_market_reference_snapshot",
            "compile_market_reference_snapshot",
            "compile_share_basis",
            "generate_market_evidence",
            "compile_final_request",
            "run_valuation_kernel",
        ):
            assert not hasattr(module, forbidden)


def test_valid_v3_snapshot_replays_the_entire_contract_graph(
    sample_payloads,
    monkeypatch,
    tmp_path,
) -> None:
    graph, snapshot, context, access, calculation = valid_snapshot_graph(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    graph.validate()
    assert snapshot.quote_price_decimal == "50.125"
    assert snapshot.market_equity["value_decimal"] == "5012500000"
    assert snapshot.market_access_result_fingerprint == access.fingerprint
    assert snapshot.share_basis["decision_fingerprint"] == (
        context.share_basis_decision.fingerprint
    )
    assert calculation.input_assumption_ids == ()


@pytest.mark.parametrize(
    ("changes", "message"),
    (
        ({"authorization_handoff_fingerprint": "9" * 64}, "authorization"),
        ({"component_lock_sha256": "9" * 64}, "authorization"),
        ({"market_access_result_fingerprint": "9" * 64}, "validation context"),
        ({"market_evidence_closure_sha256": "9" * 64}, "closure"),
        ({"quote_price_decimal": "50.126"}, "timestamp or retrieval"),
    ),
)
def test_contract_graph_rejects_snapshot_lineage_or_hash_drift(
    sample_payloads,
    monkeypatch,
    tmp_path,
    changes,
    message,
) -> None:
    graph, snapshot, _, _, _ = valid_snapshot_graph(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    forged = resign_snapshot(snapshot, **changes)
    with pytest.raises(ContractGraphError, match=message):
        replace_graph(graph, market_reference_snapshots=(forged,)).validate()


def test_contract_graph_rejects_missing_validation_context(
    sample_payloads,
    monkeypatch,
    tmp_path,
) -> None:
    graph, _, _, _, _ = valid_snapshot_graph(sample_payloads, monkeypatch, tmp_path)
    with pytest.raises(ContractGraphError, match="validation context"):
        replace_graph(graph, market_reference_validation_contexts=()).validate()


def test_one_v4_authorization_cannot_be_consumed_twice(
    sample_payloads,
    monkeypatch,
    tmp_path,
) -> None:
    graph, snapshot, _, _, _ = valid_snapshot_graph(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    duplicate = resign_snapshot(snapshot, snapshot_id=f"{snapshot.snapshot_id}:duplicate")
    with pytest.raises(ContractGraphError, match="cannot authorize two Snapshots"):
        replace_graph(graph, market_reference_snapshots=(snapshot, duplicate)).validate()


def test_raw_repository_locator_and_source_hash_are_replayed(
    sample_payloads,
    monkeypatch,
    tmp_path,
) -> None:
    graph, snapshot, _, _, _ = valid_snapshot_graph(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    raw = dict(snapshot.raw_evidence)
    raw["locator"] = "repo://tests/fixtures/phase5e2a/../secret.json"
    unsafe_payload = snapshot.to_dict()
    unsafe_payload["raw_evidence"] = raw
    with pytest.raises(ValidationError):
        validate_payload("market-reference-snapshot", unsafe_payload)

    market_document = next(
        item for item in graph.documents if item.document_id == snapshot.quote_source_document_id
    )
    documents = tuple(
        replace(item, content_sha256="9" * 64)
        if item.document_id == market_document.document_id
        else item
        for item in graph.documents
    )
    with pytest.raises(ContractGraphError, match="Quote source"):
        replace_graph(graph, documents=documents).validate()


def test_point_in_time_share_fact_cannot_be_weighted_average_or_wrong_date(
    sample_payloads,
    monkeypatch,
    tmp_path,
) -> None:
    graph, snapshot, _, _, _ = valid_snapshot_graph(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    share_id = snapshot.share_basis["shares_outstanding_fact_id"]
    facts = tuple(
        replace(
            item,
            concept="weighted_average_diluted_shares",
            period={"start": "2026-01-01", "end": "2026-06-30"},
        )
        if item.fact_id == share_id
        else item
        for item in graph.facts
    )
    with pytest.raises(ContractGraphError):
        replace_graph(graph, facts=facts).validate()


def test_direct_current_share_fact_rejects_parents(
    sample_payloads,
    monkeypatch,
    tmp_path,
) -> None:
    graph, snapshot, context, _, _ = valid_snapshot_graph(sample_payloads, monkeypatch, tmp_path)
    share_id = snapshot.share_basis["shares_outstanding_fact_id"]
    share = next(item for item in graph.facts if item.fact_id == share_id)
    legacy_denominator = next(
        item for item in graph.facts if item.fact_id == PHASE5C_DILUTED_ROOT_ID
    )
    option = replace(
        legacy_denominator,
        fact_id=OPTION_ROOT_ID,
        concept="option_or_dilution_claim",
    )
    forged = replace(share, parent_fact_ids=(option.fact_id,), derivation="claim-root-alias")
    test_graph = replace_graph(
        graph,
        facts=tuple(item for item in graph.facts if item.fact_id != share.fact_id)
        + (option, forged),
    )
    with pytest.raises(ValuationHandoffValidationError, match="raw leaf"):
        _validate_current_share_lineage(
            graph=test_graph,
            share_fact=forged,
            evidence_kind="direct_point_in_time",
            trading_date=share.period["end"],
            data_cutoff_date=context.data_cutoff_date,
            security_compilation_result=context.security_compilation_result,
            share_basis_decision=context.share_basis_decision,
            claim_control_authority=context.claim_control_authority,
        )


def test_issued_less_treasury_requires_exact_same_date_arithmetic(
    sample_payloads,
    monkeypatch,
    tmp_path,
) -> None:
    graph, snapshot, context, _, _ = valid_snapshot_graph(sample_payloads, monkeypatch, tmp_path)
    share_id = snapshot.share_basis["shares_outstanding_fact_id"]
    share = next(item for item in graph.facts if item.fact_id == share_id)
    issued = replace(
        share,
        fact_id="fact:acme:common-shares-issued:2026-06-30",
        concept="common_shares_issued",
        value=110_000_000,
    )
    treasury = replace(
        share,
        fact_id="fact:acme:treasury-shares:2026-06-30",
        concept="treasury_shares",
        value=10_000_000,
    )
    derived = replace(
        share,
        parent_fact_ids=(issued.fact_id, treasury.fact_id),
        derivation="issued-less-treasury/1.0.0",
    )
    test_graph = replace_graph(
        graph,
        facts=tuple(item for item in graph.facts if item.fact_id != share.fact_id)
        + (issued, treasury, derived),
    )
    closure = _validate_current_share_lineage(
        graph=test_graph,
        share_fact=derived,
        evidence_kind="issued_less_treasury",
        trading_date=share.period["end"],
        data_cutoff_date=context.data_cutoff_date,
        security_compilation_result=context.security_compilation_result,
        share_basis_decision=replace(
            context.share_basis_decision,
            evidence_kind="issued_less_treasury",
        ),
        claim_control_authority=context.claim_control_authority,
    )
    assert closure.numeric_root_fact_ids == tuple(sorted((issued.fact_id, treasury.fact_id)))
    with pytest.raises(ValuationHandoffValidationError, match="arithmetic"):
        forged = replace(derived, value=99_999_999)
        _validate_current_share_lineage(
            graph=replace_graph(
                test_graph,
                facts=tuple(
                    forged if item.fact_id == derived.fact_id else item for item in test_graph.facts
                ),
            ),
            share_fact=forged,
            evidence_kind="issued_less_treasury",
            trading_date=share.period["end"],
            data_cutoff_date=context.data_cutoff_date,
            security_compilation_result=context.security_compilation_result,
            share_basis_decision=replace(
                context.share_basis_decision,
                evidence_kind="issued_less_treasury",
            ),
            claim_control_authority=context.claim_control_authority,
        )


def test_completed_event_rollforward_registry_is_correct_and_requires_search_coverage(
    sample_payloads,
    monkeypatch,
    tmp_path,
) -> None:
    graph, snapshot, context, _, _ = valid_snapshot_graph(sample_payloads, monkeypatch, tmp_path)
    assert "common_shares_repurchased_completed" in COMPLETED_SHARE_EVENT_SIGNS
    assert "common_shares_repurched_completed" not in COMPLETED_SHARE_EVENT_SIGNS
    share_id = snapshot.share_basis["shares_outstanding_fact_id"]
    share = next(item for item in graph.facts if item.fact_id == share_id)
    opening = replace(
        share,
        fact_id="fact:acme:current-common-shares:2026-03-31",
        value=98_000_000,
        period={"start": None, "end": "2026-03-31"},
    )
    issuance = replace(
        share,
        fact_id="fact:acme:shares-issued-completed:2026-05-01",
        concept="common_shares_issued_completed",
        value=3_000_000,
        period={"start": None, "end": "2026-05-01"},
    )
    repurchase = replace(
        share,
        fact_id="fact:acme:shares-repurchased-completed:2026-06-01",
        concept="common_shares_repurchased_completed",
        value=1_000_000,
        period={"start": None, "end": "2026-06-01"},
    )
    derived = replace(
        share,
        parent_fact_ids=(opening.fact_id, issuance.fact_id, repurchase.fact_id),
        derivation="completed-event-rollforward/1.0.0",
    )
    test_graph = replace_graph(
        graph,
        facts=tuple(item for item in graph.facts if item.fact_id != share.fact_id)
        + (opening, issuance, repurchase, derived),
    )
    with pytest.raises(ValuationHandoffValidationError, match="share-activity category"):
        _validate_current_share_lineage(
            graph=test_graph,
            share_fact=derived,
            evidence_kind="completed_event_rollforward",
            trading_date=share.period["end"],
            data_cutoff_date=context.data_cutoff_date,
            security_compilation_result=context.security_compilation_result,
            share_basis_decision=replace(
                context.share_basis_decision,
                evidence_kind="completed_event_rollforward",
            ),
            claim_control_authority=context.claim_control_authority,
        )


def test_claim_control_is_recomputed_and_separate_from_current_share_roots(
    sample_payloads,
    monkeypatch,
    tmp_path,
) -> None:
    graph, snapshot, context, _, _ = valid_snapshot_graph(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    assert (
        "equity_bridge_dilution_root_fact_ids"
        not in inspect.signature(MarketReferenceValidationContext).parameters
    )
    expected_root = context.claim_control_authority.excluded_option_root_fact_ids[0]
    assert snapshot.share_basis["claim_control_check"]["excluded_claim_root_fact_ids"] == (
        expected_root,
    )

    share_basis = dict(snapshot.share_basis)
    claim_control = dict(share_basis["claim_control_check"])
    claim_control["excluded_claim_root_fact_ids"] = []
    claim_control["check_fingerprint"] = "9" * 64
    share_basis["claim_control_check"] = claim_control
    forged = resign_snapshot(snapshot, share_basis=share_basis)
    with pytest.raises(ContractGraphError, match="Claim-control"):
        replace_graph(graph, market_reference_snapshots=(forged,)).validate()


def test_included_and_blocked_option_treatments_replay_from_frozen_phase5c(
    sample_payloads,
    monkeypatch,
    tmp_path,
) -> None:
    _, _, context, _, _ = valid_snapshot_graph(sample_payloads, monkeypatch, tmp_path)
    readiness = context.price_blind_artifact.to_dict()["phase5c_readiness"]
    bridge = readiness["equity_bridge_result"]
    binding = bridge["method_view_result"]["reconciliation_result"]["economic_claim_bindings"][0]
    binding["diluted_share_treatment"] = "included"
    bridge["role_decisions"][0]["status"] = "not_applicable"
    bridge["consumption_records"] = [
        {
            "root_fact_id": OPTION_ROOT_ID,
            "economic_claim_key": OPTION_CLAIM_KEY,
            "economic_identity": "option_or_dilution_claim",
            "channel": f"{method}_diluted_shares",
            "method": method,
            "group_id": f"diluted-shares:{OPTION_CLAIM_KEY}",
            "consumption_kind": "economic_deduction",
        }
        for method in ("mckinsey", "penman")
    ]
    readiness["equity_bridge_fingerprint"] = canonical_sha256(bridge)
    artifact = resign_price_blind_artifact(context.price_blind_artifact, readiness)
    authority = Phase5CDilutionClaimAuthority.from_price_blind_artifact(artifact)
    assert authority.included_option_root_fact_ids == (OPTION_ROOT_ID,)
    assert authority.excluded_option_root_fact_ids == ()
    assert authority.option_bridge_status == "not_applicable"
    assert authority.standard_path_disposition == "specialist_required"
    assert authority.consumption_records_sha256 == canonical_sha256(bridge["consumption_records"])
    included_access = replace(
        context.market_access_result,
        price_blind_input_fingerprint=artifact.fingerprint,
        protected_mckinsey_sha256=artifact.payload["protected_mckinsey_sha256"],
    )
    with pytest.raises(ValueError, match="specialist routing"):
        MarketReferenceValidationContext(
            context_id="market-reference-context:included-option-root",
            price_blind_artifact=artifact,
            security_compilation_result=context.security_compilation_result,
            market_access_result=included_access,
            current_share_compilation_result=context.current_share_compilation_result,
            raw_evidence_locator=context.raw_evidence_locator,
        )

    binding["diluted_share_treatment"] = "blocked"
    binding["diluted_share_fact_ids"] = []
    bridge["role_decisions"][0]["status"] = "unresolved"
    bridge["consumption_records"] = []
    readiness["equity_bridge_fingerprint"] = canonical_sha256(bridge)
    blocked_artifact = resign_price_blind_artifact(artifact, readiness)
    blocked = Phase5CDilutionClaimAuthority.from_price_blind_artifact(blocked_artifact)
    assert blocked.blocked_option_root_fact_ids == (OPTION_ROOT_ID,)
    assert blocked.option_bridge_status == "unresolved"
    assert blocked.standard_path_disposition == "blocked"
    blocked_access = replace(
        context.market_access_result,
        price_blind_input_fingerprint=blocked_artifact.fingerprint,
        protected_mckinsey_sha256=blocked_artifact.payload["protected_mckinsey_sha256"],
    )
    with pytest.raises(ValueError, match="blocked Phase 5C claims"):
        MarketReferenceValidationContext(
            context_id="market-reference-context:blocked-option-root",
            price_blind_artifact=blocked_artifact,
            security_compilation_result=context.security_compilation_result,
            market_access_result=blocked_access,
            current_share_compilation_result=context.current_share_compilation_result,
            raw_evidence_locator=context.raw_evidence_locator,
        )


def test_snapshot_contract_exports_no_callable_compiler_or_writer() -> None:
    public_callables = {
        name for name, value in inspect.getmembers(owner_research) if callable(value)
    }
    assert not public_callables.intersection(
        {
            "build_market_reference_snapshot",
            "compile_market_reference_snapshot",
            "compile_share_basis",
            "generate_market_evidence",
            "compile_final_request",
            "run_valuation_kernel",
            "write_valuation_artifacts",
        }
    )
