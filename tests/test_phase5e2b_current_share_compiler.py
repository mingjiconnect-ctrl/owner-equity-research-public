from __future__ import annotations

import inspect
from dataclasses import FrozenInstanceError, replace

import pytest
from phase4a_support import replace_graph
from phase5e2b_support import current_share_compile_context
from test_phase5e2a21_recursive_evidence import _rollforward_graph

import owner_research
import owner_research.valuation_current_share_compiler as current_share_compiler
from owner_research.contracts import Fact
from owner_research.valuation_current_share_compiler import (
    CurrentShareCompilationResult,
    CurrentSharePathDecision,
    compile_quote_date_current_common_shares,
)
from owner_research.valuation_market_reference_types import (
    MarketReferenceValidationContext,
    Phase5CDilutionClaimAuthority,
)


def _compile(sample_payloads, monkeypatch, tmp_path):
    graph, freeze, directory, security, access, shares = current_share_compile_context(
        sample_payloads, monkeypatch, tmp_path
    )
    result = compile_quote_date_current_common_shares(
        price_blind_artifact_directory=directory,
        graph=graph,
        expected_freeze=freeze,
        expected_security=security,
        expected_market_access=access,
    )
    return graph, freeze, directory, security, access, shares, result


def test_direct_quote_date_current_common_shares_compile_deterministically(
    sample_payloads, monkeypatch, tmp_path
) -> None:
    graph, freeze, directory, security, access, shares, result = _compile(
        sample_payloads, monkeypatch, tmp_path
    )
    assert result.status == "eligible"
    assert result.output_fact == shares
    assert result.share_basis_decision is not None
    assert result.share_basis_decision.evidence_kind == "direct_point_in_time"
    assert result.evidence_closure is not None
    assert result.evidence_closure.numeric_root_fact_ids == (shares.fact_id,)
    replay = compile_quote_date_current_common_shares(
        price_blind_artifact_directory=directory,
        graph=replace_graph(graph, facts=tuple(reversed(graph.facts))),
        expected_freeze=freeze,
        expected_security=security,
        expected_market_access=access,
    )
    assert replay.to_dict() == result.to_dict()
    assert replay.fingerprint == result.fingerprint


def test_issued_less_treasury_is_derived_without_caller_fact_selection(
    sample_payloads, monkeypatch, tmp_path
) -> None:
    graph, freeze, directory, security, access, shares, _ = _compile(
        sample_payloads, monkeypatch, tmp_path
    )
    issued = replace(
        shares,
        fact_id="fact:acme:common-shares-issued:2026-06-30",
        concept="common_shares_issued",
        value=110_000_000,
    )
    treasury = replace(
        shares,
        fact_id="fact:acme:treasury-shares:2026-06-30",
        concept="treasury_shares",
        value=10_000_000,
    )
    test_graph = replace_graph(
        graph,
        facts=tuple(item for item in graph.facts if item.fact_id != shares.fact_id)
        + (issued, treasury),
    )
    result = compile_quote_date_current_common_shares(
        price_blind_artifact_directory=directory,
        graph=test_graph,
        expected_freeze=freeze,
        expected_security=security,
        expected_market_access=access,
    )
    assert result.status == "eligible"
    assert result.output_fact is not None
    assert result.output_fact.value == 100_000_000
    assert result.output_fact.derivation == "issued-less-treasury/1.0.0"
    assert result.output_fact.parent_fact_ids == tuple(sorted((issued.fact_id, treasury.fact_id)))
    assert result.share_basis_decision is not None
    assert result.share_basis_decision.evidence_kind == "issued_less_treasury"


def test_conflicting_quote_date_paths_fail_closed(
    sample_payloads, monkeypatch, tmp_path
) -> None:
    graph, freeze, directory, security, access, shares, _ = _compile(
        sample_payloads, monkeypatch, tmp_path
    )
    issued = replace(
        shares,
        fact_id="fact:acme:common-shares-issued:conflict",
        concept="common_shares_issued",
        value=112_000_000,
    )
    treasury = replace(
        shares,
        fact_id="fact:acme:treasury-shares:conflict",
        concept="treasury_shares",
        value=10_000_000,
    )
    result = compile_quote_date_current_common_shares(
        price_blind_artifact_directory=directory,
        graph=replace_graph(graph, facts=graph.facts + (issued, treasury)),
        expected_freeze=freeze,
        expected_security=security,
        expected_market_access=access,
    )
    assert result.status == "blocked"
    assert result.issue_codes == ("current_share_path_conflict",)
    assert result.output_fact is None


def test_conflicting_duplicate_direct_facts_fail_closed(
    sample_payloads, monkeypatch, tmp_path
) -> None:
    graph, freeze, directory, security, access, shares, _ = _compile(
        sample_payloads, monkeypatch, tmp_path
    )
    conflict = replace(shares, fact_id="fact:acme:current-shares:conflict", value=99_000_000)
    result = compile_quote_date_current_common_shares(
        price_blind_artifact_directory=directory,
        graph=replace_graph(graph, facts=graph.facts + (conflict,)),
        expected_freeze=freeze,
        expected_security=security,
        expected_market_access=access,
    )
    assert result.status == "blocked"
    assert result.issue_codes == ("current_share_evidence_ambiguous",)


def test_market_access_and_artifact_identity_are_replayed(
    sample_payloads, monkeypatch, tmp_path
) -> None:
    graph, freeze, directory, security, access, _, _ = _compile(
        sample_payloads, monkeypatch, tmp_path
    )
    forged_access = replace(access, authorization_handoff_id="handoff:forged")
    result = compile_quote_date_current_common_shares(
        price_blind_artifact_directory=directory,
        graph=graph,
        expected_freeze=freeze,
        expected_security=security,
        expected_market_access=forged_access,
    )
    assert result.status == "blocked"
    assert result.issue_codes == ("market_access_mismatch",)
    (directory / "price-blind-input.json").write_text("{}", encoding="utf-8")
    result = compile_quote_date_current_common_shares(
        price_blind_artifact_directory=directory,
        graph=graph,
        expected_freeze=freeze,
        expected_security=security,
        expected_market_access=access,
    )
    assert result.status == "blocked"
    assert result.issue_codes == ("artifact_reload_failed",)


def test_compiler_types_are_frozen_and_internal_only(
    sample_payloads, monkeypatch, tmp_path
) -> None:
    *_, result = _compile(sample_payloads, monkeypatch, tmp_path)
    with pytest.raises(FrozenInstanceError):
        result.status = "blocked"  # type: ignore[misc]
    assert CurrentShareCompilationResult.__module__.endswith(
        "valuation_current_share_compiler"
    )
    assert CurrentSharePathDecision.__module__.endswith("valuation_current_share_compiler")
    assert not hasattr(owner_research, "compile_quote_date_current_common_shares")
    assert "share_basis_decision" not in inspect.signature(
        MarketReferenceValidationContext
    ).parameters
    assert "current_share_compilation_result" in inspect.signature(
        MarketReferenceValidationContext
    ).parameters


def test_non_share_objects_cannot_be_selected_as_current_shares(
    sample_payloads, monkeypatch, tmp_path
) -> None:
    graph, freeze, directory, security, access, shares, _ = _compile(
        sample_payloads, monkeypatch, tmp_path
    )
    forbidden = Fact(
        **{
            **shares.to_dict(),
            "fact_id": "fact:acme:weighted-average-shares",
            "concept": "weighted_average_diluted_shares",
        }
    )
    result = compile_quote_date_current_common_shares(
        price_blind_artifact_directory=directory,
        graph=replace_graph(
            graph,
            facts=tuple(item for item in graph.facts if item.fact_id != shares.fact_id)
            + (forbidden,),
        ),
        expected_freeze=freeze,
        expected_security=security,
        expected_market_access=access,
    )
    assert result.status == "blocked"
    assert result.issue_codes == ("current_share_evidence_missing",)


def test_completed_event_rollforward_compiles_only_with_closed_coverage(
    sample_payloads, monkeypatch, tmp_path
) -> None:
    graph, freeze, directory, security, access, shares, _ = _compile(
        sample_payloads, monkeypatch, tmp_path
    )
    rollforward_graph, _, _, _, _ = _rollforward_graph(graph, shares)
    result = compile_quote_date_current_common_shares(
        price_blind_artifact_directory=directory,
        graph=rollforward_graph,
        expected_freeze=freeze,
        expected_security=security,
        expected_market_access=access,
    )
    assert result.status == "eligible"
    assert result.output_fact is not None
    assert result.output_fact.derivation == "completed-event-rollforward/1.0.0"
    assert result.share_basis_decision is not None
    assert result.share_basis_decision.evidence_kind == "completed_event_rollforward"
    assert result.evidence_closure is not None
    assert result.evidence_closure.coverage_receipt_ids


def test_rollforward_split_window_routes_specialist(
    sample_payloads, monkeypatch, tmp_path
) -> None:
    graph, freeze, directory, security, access, shares, _ = _compile(
        sample_payloads, monkeypatch, tmp_path
    )
    opening = replace(
        shares,
        fact_id="fact:acme:current-common-shares:2026-03-31",
        value=50_000_000,
        period={"start": None, "end": "2026-03-31"},
    )
    split = replace(
        shares,
        fact_id="fact:acme:stock-split:2026-05-15",
        concept="stock_split_completed",
        value=2,
        period={"start": None, "end": "2026-05-15"},
    )
    result = compile_quote_date_current_common_shares(
        price_blind_artifact_directory=directory,
        graph=replace_graph(
            graph,
            facts=tuple(item for item in graph.facts if item.fact_id != shares.fact_id)
            + (opening, split),
        ),
        expected_freeze=freeze,
        expected_security=security,
        expected_market_access=access,
    )
    assert result.status == "specialist_required"
    assert result.issue_codes == ("split_factor_unsupported",)
    assert result.output_fact is None


@pytest.mark.parametrize(
    ("disposition", "expected_status", "expected_issue"),
    (
        ("specialist_required", "specialist_required", "dilution_claim_authority_specialist"),
        ("blocked", "blocked", "dilution_claim_authority_blocked"),
    ),
)
def test_phase5c_claim_authority_controls_compiler_route(
    sample_payloads,
    monkeypatch,
    tmp_path,
    disposition,
    expected_status,
    expected_issue,
) -> None:
    graph, freeze, directory, security, access, _, _ = _compile(
        sample_payloads, monkeypatch, tmp_path
    )
    authority = Phase5CDilutionClaimAuthority.from_price_blind_artifact(freeze.artifact)
    monkeypatch.setattr(
        current_share_compiler.Phase5CDilutionClaimAuthority,
        "from_price_blind_artifact",
        classmethod(
            lambda cls, artifact: replace(
                authority,
                standard_path_disposition=disposition,
            )
        ),
    )
    result = compile_quote_date_current_common_shares(
        price_blind_artifact_directory=directory,
        graph=graph,
        expected_freeze=freeze,
        expected_security=security,
        expected_market_access=access,
    )
    assert result.status == expected_status
    assert result.issue_codes == (expected_issue,)
    assert result.output_fact is None
