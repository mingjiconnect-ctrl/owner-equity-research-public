from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from test_phase5_v1_owner_scorecard import _lens_scorecard
from test_phase5_v1_release_assembler import _build_private_evidence
from test_phase5_v1_valuation_synthesis import _contested_composite

from owner_research.owner_equity_research import (
    KernelValuationInput,
    MarketExpectationsInput,
    MarketReferenceInput,
    NonPriceVerificationInput,
    OwnerEquityResearchRequest,
    PhaseReceipt,
    PhaseStatus,
    PriceBlindRefreezeInput,
    PublicationProfile,
    ResearchIntent,
    ScoringInput,
    SynthesisInput,
)
from owner_research.owner_equity_runtime import (
    OwnerEquityRuntime,
    OwnerEquityRuntimeError,
    RuntimeResearchAuthority,
    _LiveRuntimeState,
    _ResearchReadBudget,
    build_runtime_dependencies,
    load_research_runtime_context,
    write_research_runtime_context,
)
from owner_research.valuation_run_context import (
    ValuationRunInputContext,
    _context_payload,
)


def _valuation_runtime(inputs: Any, runtime_root: Path) -> OwnerEquityRuntime:
    run_receipt = inputs.run_result.input_receipt
    graph_file = write_research_runtime_context(
        graph=run_receipt.graph,
        output_file=runtime_root / "research-runtime-context.json",
    )
    research_context = load_research_runtime_context(graph_file)
    valuation_payload = _context_payload(
        graph=run_receipt.graph,
        bundle_artifact_directory=inputs.research.source_directory,
        expected_freeze=inputs.freeze,
        security_proposal=run_receipt.expected_security.proposal,
        assumption_proposals=(),
        assumption_reviews=(),
        clock=run_receipt.clock,
    )
    return OwnerEquityRuntime(
        intent=ResearchIntent.VALUATION,
        profile=PublicationProfile.FULL_VALUATION,
        research_authority=RuntimeResearchAuthority(
            context=research_context,
            research=inputs.research,
            source_index=inputs.source_index,
        ),
        valuation_context=ValuationRunInputContext(
            graph=run_receipt.graph,
            expected_freeze=inputs.freeze,
            expected_security=run_receipt.expected_security,
            assumption_proposals=(),
            assumption_reviews=(),
            clock=run_receipt.clock,
            research_bundle_contents=inputs.research.file_bytes,
            context_fingerprint=valuation_payload["context_fingerprint"],
        ),
        report_spec=None,
        publication_output=None,
        publication_source_package=None,
        audit_package=None,
        valuation_locators=None,
        config_fingerprint="0" * 64,
        research_read_budget=_ResearchReadBudget(1024),
    )


def _make_removable(root: Path) -> None:
    root.chmod(0o700)
    for member in root.rglob("*"):
        member.chmod(0o700 if member.is_dir() else 0o600)


class _ContestedExpectationsAdmitted(Exception):
    pass


def test_synthesis_rejects_equal_but_distinct_receipts_before_peer_futu(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    evidence_root, inputs = _build_private_evidence(
        sample_payloads,
        monkeypatch,
        tmp_path,
        futu_only=True,
    )
    try:
        contested_composite = _contested_composite(
            inputs.run_result,
            inputs.forward._basis_authority,
            inputs.forward,
            inputs.comparables,
        )
        contested_forward = contested_composite._forward_authority
        assert contested_forward is not None
        contested_scores, contested_scorecard = _lens_scorecard(
            inputs.run_result,
            contested_composite,
        )
        runtime = _valuation_runtime(inputs, tmp_path / "runtime")
        dependencies = build_runtime_dependencies(runtime)
        bundle = inputs.research.result.bundle
        request = OwnerEquityResearchRequest(
            issuer_id=bundle.issuer_id,
            data_cutoff_date=bundle.data_cutoff_date,
            intent=ResearchIntent.VALUATION,
            profile=PublicationProfile.FULL_VALUATION,
            requested_by="human:runtime-receipt-identity-reviewer",
            requested_at="2026-08-15T09:00:00+08:00",
        )
        pre_price_calls: list[OwnerEquityResearchRequest] = []
        kernel_calls: list[str] = []
        live_calls: list[OwnerEquityResearchRequest] = []

        def replay_pre_price(
            state: _LiveRuntimeState,
            candidate: OwnerEquityResearchRequest,
        ):
            assert candidate is request
            pre_price_calls.append(candidate)
            state.pre_execution = inputs.pre_execution
            state.optional_data_dispositions = inputs.optional_data_dispositions
            state.authority_decision = inputs.session.authority_decision
            return inputs.pre_execution

        def replay_price_blind(state: _LiveRuntimeState):
            assert state.pre_execution is inputs.pre_execution
            return inputs.freeze

        def replay_market_reference(
            state: _LiveRuntimeState,
            candidate: OwnerEquityResearchRequest,
        ):
            assert candidate is request
            state.market_evidence = inputs.market_evidence
            state.market_provider = inputs.market_provider
            return inputs.market_provider

        def replay_kernel(state: _LiveRuntimeState):
            kernel_calls.append("kernel")
            state.run_result = inputs.run_result
            return inputs.run_result

        def record_synthesis_call(
            state: _LiveRuntimeState,
            candidate: OwnerEquityResearchRequest,
        ):
            assert candidate is request
            live_calls.append(candidate)
            state.peer_evidence_set = inputs.peer_evidence_set
            state.forward_reoi = contested_forward
            state.comparable = inputs.comparables
            state.composite = contested_composite
            return contested_composite

        def replay_score(state: _LiveRuntimeState):
            state.lens_scores = contested_scores
            state.owner_scorecard = contested_scorecard
            return contested_scorecard

        def replay_expectations(
            state: _LiveRuntimeState,
            candidate: OwnerEquityResearchRequest,
        ):
            assert candidate is request
            raise _ContestedExpectationsAdmitted

        monkeypatch.setattr(_LiveRuntimeState, "run_pre_price", replay_pre_price)
        monkeypatch.setattr(_LiveRuntimeState, "replay_price_blind", replay_price_blind)
        monkeypatch.setattr(
            _LiveRuntimeState,
            "run_market_reference",
            replay_market_reference,
        )
        monkeypatch.setattr(_LiveRuntimeState, "run_kernel", replay_kernel)
        monkeypatch.setattr(_LiveRuntimeState, "run_synthesis", record_synthesis_call)
        monkeypatch.setattr(_LiveRuntimeState, "run_score", replay_score)
        monkeypatch.setattr(
            _LiveRuntimeState,
            "run_market_expectations",
            replay_expectations,
        )

        official = dependencies.official_research(request)
        assert official.receipt is not None
        different_request = replace(
            request,
            requested_by="human:different-runtime-receipt-reviewer",
        )
        different_official = dependencies.official_research(different_request)
        with pytest.raises(
            OwnerEquityRuntimeError,
            match="runtime official research authority",
        ):
            dependencies.futu_nonprice(
                NonPriceVerificationInput(
                    request=different_request,
                    official_research=different_official,
                )
            )
        assert pre_price_calls == []
        cloned_official = replace(official, receipt=replace(official.receipt))
        with pytest.raises(
            OwnerEquityRuntimeError,
            match="runtime official research authority",
        ):
            dependencies.futu_nonprice(
                NonPriceVerificationInput(
                    request=request,
                    official_research=cloned_official,
                )
            )
        assert pre_price_calls == []
        nonprice = dependencies.futu_nonprice(
            NonPriceVerificationInput(request=request, official_research=official)
        )
        price_blind = dependencies.refreeze_price_blind(
            PriceBlindRefreezeInput(
                request=request,
                official_research=official,
                futu_nonprice=nonprice,
            )
        )
        market = dependencies.futu_market_reference(
            MarketReferenceInput(
                request=request,
                price_blind=price_blind,
                futu_nonprice=nonprice,
            )
        )
        assert market.receipt is not None
        cloned_market = replace(market, receipt=replace(market.receipt))
        with pytest.raises(
            OwnerEquityRuntimeError,
            match="exact market sequence",
        ):
            dependencies.run_owner_valuation(
                KernelValuationInput(
                    request=request,
                    price_blind=price_blind,
                    market_reference=cloned_market,
                )
            )
        assert kernel_calls == []
        kernel = dependencies.run_owner_valuation(
            KernelValuationInput(
                request=request,
                price_blind=price_blind,
                market_reference=market,
            )
        )
        assert kernel_calls == ["kernel"]
        assert price_blind.receipt is not None
        assert nonprice.receipt is not None
        assert market.receipt is not None
        assert kernel.receipt is not None

        cloned_price_blind_receipt = replace(price_blind.receipt)
        assert cloned_price_blind_receipt == price_blind.receipt
        assert cloned_price_blind_receipt is not price_blind.receipt
        rebound_market_receipt = PhaseReceipt.create(
            phase="futu_market_reference",
            input_receipt=market.receipt.input_receipt,
            upstream_receipts=(cloned_price_blind_receipt, nonprice.receipt),
            authorities=market.receipt.authorities,
        )
        rebound_market = replace(market, receipt=rebound_market_receipt)
        rebound_kernel_receipt = PhaseReceipt.create(
            phase="owner_valuation_kernel",
            input_receipt=kernel.receipt.input_receipt,
            upstream_receipts=(price_blind.receipt, rebound_market_receipt),
            authorities=kernel.receipt.authorities,
        )
        rebound_kernel = replace(kernel, receipt=rebound_kernel_receipt)

        cloned_freeze = replace(inputs.freeze)
        assert cloned_freeze == inputs.freeze
        assert cloned_freeze is not inputs.freeze
        authority_only_rebound_price_blind = replace(
            price_blind,
            price_blind_input=cloned_freeze,
        )
        rebound_price_blind_receipt = PhaseReceipt.create(
            phase="price_blind_refreeze",
            input_receipt=price_blind.receipt.input_receipt,
            upstream_receipts=price_blind.receipt.upstream_receipts,
            authorities=(price_blind.research_input, cloned_freeze),
        )
        rebound_price_blind = replace(
            price_blind,
            receipt=rebound_price_blind_receipt,
        )
        authority_rebound_market_receipt = PhaseReceipt.create(
            phase="futu_market_reference",
            input_receipt=market.receipt.input_receipt,
            upstream_receipts=(rebound_price_blind_receipt, nonprice.receipt),
            authorities=market.receipt.authorities,
        )
        authority_rebound_market = replace(
            market,
            receipt=authority_rebound_market_receipt,
        )
        authority_rebound_kernel_receipt = PhaseReceipt.create(
            phase="owner_valuation_kernel",
            input_receipt=kernel.receipt.input_receipt,
            upstream_receipts=(
                rebound_price_blind_receipt,
                authority_rebound_market_receipt,
            ),
            authorities=kernel.receipt.authorities,
        )
        authority_rebound_kernel = replace(
            kernel,
            receipt=authority_rebound_kernel_receipt,
        )

        cases = (
            SynthesisInput(
                request=request,
                price_blind=price_blind,
                market_reference=rebound_market,
                kernel=rebound_kernel,
            ),
            SynthesisInput(
                request=request,
                price_blind=authority_only_rebound_price_blind,
                market_reference=market,
                kernel=kernel,
            ),
            SynthesisInput(
                request=request,
                price_blind=rebound_price_blind,
                market_reference=authority_rebound_market,
                kernel=authority_rebound_kernel,
            ),
        )
        for synthesis_input in cases:
            with pytest.raises(
                OwnerEquityRuntimeError,
                match="exact valuation sequence",
            ):
                dependencies.synthesize(synthesis_input)
            assert live_calls == []

        synthesis = dependencies.synthesize(
            SynthesisInput(
                request=request,
                price_blind=price_blind,
                market_reference=market,
                kernel=kernel,
            )
        )
        assert synthesis.status is PhaseStatus.CONTESTED
        assert live_calls == [request]
        score = dependencies.score(
            ScoringInput(
                request=request,
                price_blind=price_blind,
                synthesis=synthesis,
            )
        )
        assert score.status is PhaseStatus.CONTESTED
        assert score.recommendation == "无法评级"
        with pytest.raises(_ContestedExpectationsAdmitted):
            dependencies.futu_market_expectations(
                MarketExpectationsInput(
                    request=request,
                    price_blind=price_blind,
                    market_reference=market,
                    synthesis=synthesis,
                    score=score,
                )
            )
    finally:
        _make_removable(evidence_root)
