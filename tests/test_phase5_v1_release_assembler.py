from __future__ import annotations

import base64
import hashlib
import json
import os
import runpy
import shutil
import subprocess
import sys
from dataclasses import replace
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).parents[1]
NAMESPACE = runpy.run_path(str(ROOT / "scripts/assemble_release_artifacts.py"))
ASSEMBLE = NAMESPACE["assemble_release"]
ERROR = NAMESPACE["ReleaseAssemblyError"]
CANONICAL = NAMESPACE["canonical_json_bytes"]
ARTIFACT_ROLES = NAMESPACE["ARTIFACT_ROLES"]
PUBLIC_ARTIFACT_ROLES = NAMESPACE["PUBLIC_ARTIFACT_ROLES"]
SCORE_LENSES = NAMESPACE["SCORE_LENSES"]
OWNER_PHASE_NAMES = NAMESPACE["OWNER_PHASE_NAMES"]
REQUIRED_OWNER_PHASES = NAMESPACE["REQUIRED_OWNER_PHASES"]
FUTU_CLOSED_RUNTIME_PROTOCOL_IDS = NAMESPACE["FUTU_CLOSED_RUNTIME_PROTOCOL_IDS"]
PRODUCTION_TRUST_POLICY_PATH = ASSEMBLE.__globals__["RELEASE_TRUST_POLICY_PATH"]

EXECUTED_AT = "2026-07-14T01:08:35Z"
VERIFICATION_TIME = "2026-07-14T01:08:45Z"
TEST_ONLY_SIGNER_KEY_ID = "test-only-release-canary-key"
TEST_ONLY_FINANCIAL_FIELDS = {
    "5001": ("income", "flow", "revenue", "1250"),
    "5034": ("income", "flow", "operating_income", "250"),
    "5040": ("income", "flow", "pretax_income", "230"),
    "5043": ("income", "flow", "income_tax_expense", "30"),
    "5045": ("income", "flow", "net_income", "200"),
    "6001": ("balance_sheet", "stock", "total_assets", "2500"),
    "6002": ("balance_sheet", "stock", "total_liabilities", "1500"),
    "6003": ("balance_sheet", "stock", "common_equity", "1000"),
    "6004": ("balance_sheet", "stock", "cash_and_cash_equivalents", "350"),
    "6005": ("balance_sheet", "stock", "interest_bearing_debt", "500"),
    "7001": ("cash_flow", "flow", "operating_cash_flow", "300"),
    "7002": ("cash_flow", "flow", "capital_expenditure_outflow", "100"),
}


@pytest.mark.parametrize(
    ("value", "microsecond"),
    (
        ("2026-07-14T00:58:00Z", 0),
        ("2026-07-14T00:58:00.1Z", 100000),
        ("2026-07-14T00:58:00.12Z", 120000),
        ("2026-07-14T00:58:00.123Z", 123000),
        ("2026-07-14T00:58:00.1234Z", 123400),
        ("2026-07-14T00:58:00.12345Z", 123450),
        ("2026-07-14T00:58:00.123456Z", 123456),
    ),
)
def test_release_timestamp_accepts_canonical_rfc3339_utc_precision(
    value: str,
    microsecond: int,
) -> None:
    parsed = NAMESPACE["_parse_time"](value, label="release test timestamp")
    assert parsed.tzinfo is UTC
    assert parsed.microsecond == microsecond


@pytest.mark.parametrize(
    "value",
    (
        "2026-07-14T00:58:00z",
        "2026-07-14T00:58:00+00:00",
        "2026-07-14T00:58:00.1234567Z",
        "2026-07-14T00:58:00,1Z",
        "2026-02-30T00:58:00Z",
        "2026-7-14T00:58:00Z",
    ),
)
def test_release_timestamp_rejects_noncanonical_or_invalid_forms(value: str) -> None:
    with pytest.raises(ERROR, match="RFC3339 UTC timestamp"):
        NAMESPACE["_parse_time"](value, label="release test timestamp")


@pytest.fixture(autouse=True)
def _restore_production_release_control_anchor():
    yield
    ASSEMBLE.__globals__["RELEASE_TRUST_POLICY_PATH"] = PRODUCTION_TRUST_POLICY_PATH
    ASSEMBLE.__globals__["RELEASE_CONTROL_TRUST_POLICY_SHA256"] = None


def _install_test_only_financial_registry(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[dict[str, Any], dict[str, tuple[str, ...]]]:
    import owner_research.futu_sidecar as futu_sidecar_module
    import owner_research.owner_equity_runtime as owner_runtime_module
    from owner_research.fingerprints import FrozenMap

    registry = {
        field_id: FrozenMap(
            {
                "accounting_standard_scope": "US_GAAP",
                "canonical_concept": concept,
                "data_family": "financial_statements",
                "field_id": field_id,
                "futu_api_version": "10.10.7008",
                "materiality_tier": "kernel_required",
                "normalized_display_name": f"test-only reviewed {concept}",
                "period_kind": period_kind,
                "sign_convention": "reported_signed",
                "statement_type": statement_type,
                "unit": "currency_millions",
            }
        )
        for field_id, (statement_type, period_kind, concept, _value) in (
            TEST_ONLY_FINANCIAL_FIELDS.items()
        )
    }
    critical = {
        statement_type: tuple(
            sorted(
                concept
                for candidate_statement, _period_kind, concept, _value in (
                    TEST_ONLY_FINANCIAL_FIELDS.values()
                )
                if candidate_statement == statement_type
            )
        )
        for statement_type in ("income", "balance_sheet", "cash_flow")
    }
    for module in (futu_sidecar_module, owner_runtime_module):
        monkeypatch.setattr(module, "load_financial_field_registry", lambda: registry)
        monkeypatch.setattr(module, "load_critical_financial_concepts", lambda: critical)
    return registry, critical


def _write_canonical(path: Path, value: dict[str, Any], *, mode: int = 0o400) -> Path:
    path.write_bytes(CANONICAL(value))
    path.chmod(mode)
    return path


def _seal(value: dict[str, Any], field: str) -> None:
    value.pop(field, None)
    value[field] = NAMESPACE["_projection_sha256"](value)


def _source_repository(tmp_path: Path) -> tuple[Path, str, str]:
    source = tmp_path / "source"
    (source / "sidecars/futu-opend").mkdir(parents=True)
    (source / "plugins/owner-equity-research/.codex-plugin").mkdir(parents=True)
    (source / "pyproject.toml").write_bytes(
        (ROOT / "pyproject.toml")
        .read_bytes()
        .replace(b'version = "1.0.0.dev0"', b'version = "1.0.0rc1"', 1)
    )
    (source / "sidecars/futu-opend/pyproject.toml").write_bytes(
        (ROOT / "sidecars/futu-opend/pyproject.toml")
        .read_bytes()
        .replace(b'version = "1.0.0.dev0"', b'version = "1.0.0rc1"', 1)
    )
    for relative in NAMESPACE["DEPENDENCY_SUPPLY_AUTHORITY_PATHS"]:
        if relative in {"pyproject.toml", "sidecars/futu-opend/pyproject.toml"}:
            continue
        target = source / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / relative).read_bytes())
        target.chmod(0o644)
    _write_canonical(
        source / "plugins/owner-equity-research/.codex-plugin/plugin.json",
        {"name": "owner-equity-research", "version": "1.0.0-rc.1"},
        mode=0o644,
    )
    subprocess.run(("git", "init", "-q"), cwd=source, check=True)
    subprocess.run(("git", "add", "-A"), cwd=source, check=True)
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_AUTHOR_EMAIL": "release@example.invalid",
            "GIT_AUTHOR_NAME": "Release Test",
            "GIT_COMMITTER_EMAIL": "release@example.invalid",
            "GIT_COMMITTER_NAME": "Release Test",
        }
    )
    subprocess.run(
        ("git", "commit", "-q", "-m", "exact release source"),
        cwd=source,
        check=True,
        env=environment,
    )
    commit = subprocess.check_output(("git", "rev-parse", "HEAD"), cwd=source, text=True).strip()
    tree = subprocess.check_output(
        ("git", "rev-parse", "HEAD^{tree}"), cwd=source, text=True
    ).strip()
    return source, commit, tree


def _artifacts(tmp_path: Path) -> dict[str, Path]:
    directory = tmp_path / "inputs"
    directory.mkdir()
    names = {
        "owner_wheel": "owner_equity_research-1.0.0rc1-py3-none-any.whl",
        "owner_sdist": "owner_equity_research-1.0.0rc1.tar.gz",
        "plugin_bundle": "owner-equity-research-plugin-1.0.0-rc.1.zip",
        "sidecar_wheel": "owner_research_futu_sidecar-1.0.0rc1-py3-none-any.whl",
        "sidecar_sdist": "owner_research_futu_sidecar-1.0.0rc1.tar.gz",
    }
    result = {}
    for role, name in names.items():
        path = directory / name
        path.write_bytes(f"verified-{role}\n".encode())
        result[role] = path
    return result


def _stub_verifiers(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "ROOT_WHEEL_VERIFY",
        "ROOT_SDIST_VERIFY",
        "PLUGIN_VERIFY",
        "SIDECAR_WHEEL_VERIFY",
        "SIDECAR_SDIST_VERIFY",
    ):
        monkeypatch.setitem(ASSEMBLE.__globals__, name, lambda *_args, **_kwargs: ())


def _artifact_records(artifacts: dict[str, Path]) -> list[dict[str, Any]]:
    return [NAMESPACE["_artifact_info"](role, artifacts[role])[0] for role in ARTIFACT_ROLES]


def _authority_payload(authority: Any) -> dict[str, Any]:
    return {
        name: None if getattr(authority, name) is None else getattr(authority, name).to_dict()
        for name in (
            "legal",
            "account",
            "supply_chain",
            "runtime_authorization",
            "runtime",
            "security_identity",
        )
    }


def _patch_real_futu_signing(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Any, Ed25519PrivateKey, str]:
    import test_phase5_v1_futu_data_plane as futu_fixture

    private = Ed25519PrivateKey.generate()
    public_hex = (
        private.public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex()
    )

    class RealVerifier:
        def verify(
            self,
            *,
            signer_key_id: str,
            payload: bytes,
            signature_hex: str,
        ) -> bool:
            if signer_key_id != "test-key":
                return False
            try:
                private.public_key().verify(bytes.fromhex(signature_hex), payload)
            except (ValueError, TypeError):
                return False
            return True

    def signed_payload(prefix: str, values: dict[str, Any]) -> dict[str, Any]:
        payload = {
            **values,
            "signature_algorithm": "ed25519",
            "signer_key_id": "test-key",
        }
        payload["receipt_id"] = futu_fixture.signed_receipt_identity(prefix, payload)
        payload["signature_hex"] = private.sign(futu_fixture.canonical_json(payload).encode()).hex()
        return payload

    def signed_wire(values: dict[str, Any]) -> dict[str, Any]:
        payload = {
            **values,
            "signature_algorithm": "ed25519",
            "signer_key_id": "test-key",
        }
        payload["signature_hex"] = private.sign(futu_fixture.canonical_json(payload).encode()).hex()
        return payload

    monkeypatch.setattr(futu_fixture, "DeterministicVerifier", RealVerifier)
    monkeypatch.setattr(futu_fixture, "_signed_payload", signed_payload)
    monkeypatch.setattr(futu_fixture, "_signed_wire_payload", signed_wire)
    monkeypatch.setattr(futu_fixture, "HASH_C", public_hex)
    return futu_fixture, private, public_hex


def _ordered_futu_records(inputs: Any) -> list[dict[str, Any]]:
    target = inputs.futu.session.executions
    peers = inputs.futu.session.peer_evidence_set.peers
    ordered = (target[0], target[1], *(item.execution for item in peers), target[2])
    records = []
    for execution in ordered:
        peer = next(
            (item for item in peers if item.execution.bundle == execution.bundle),
            None,
        )
        authority = (
            inputs.futu.session.authority_decision if peer is None else peer.authority_decision
        )
        security = (
            inputs.futu.session.authority_set.security_identity
            if peer is None
            else peer.authority_set.security_identity
        )
        assert security is not None
        records.append(
            {
                "authority_decision": authority.to_dict(),
                "bundle": execution.bundle.to_dict(),
                "history_quota": (
                    None
                    if execution.history_quota is None
                    else execution.history_quota.to_dict()
                ),
                "observations": [item.to_dict() for item in execution.observations],
                "requests": [item.to_dict() for item in execution.requests],
                "responses": [item.to_dict() for item in execution.responses],
                "security_identity": security.to_dict(),
            }
        )
    return records


def _run_high_level_result(*, inputs: Any, package: Any, report: Any) -> Any:
    from owner_research.owner_equity_research import (
        AuditPhaseResult,
        FutuMarketReferencePhaseResult,
        FutuNonPricePhaseResult,
        KernelValuationPhaseResult,
        MarketExpectationsPhaseResult,
        OfficialResearchPhaseResult,
        OwnerEquityResearchDependencies,
        OwnerEquityResearchInputReceipt,
        OwnerEquityResearchRequest,
        PhaseReceipt,
        PhaseStatus,
        PriceBlindRefreezePhaseResult,
        PublicationPhaseResult,
        PublicationProfile,
        ReportPhaseResult,
        ResearchIntent,
        ScorePhaseResult,
        SecurityScope,
        SynthesisPhaseResult,
        run_owner_equity_research,
    )

    request = OwnerEquityResearchRequest(
        issuer_id=inputs.run_result.issuer_id,
        data_cutoff_date=inputs.run_result.data_cutoff_date,
        intent=ResearchIntent.VALUATION,
        profile=PublicationProfile.FULL_VALUATION,
        requested_by="human:release-canary-reviewer",
        requested_at="2026-07-14T00:57:00Z",
    )
    input_receipt = OwnerEquityResearchInputReceipt.from_request(request)
    security = inputs.session.authority_set.security_identity
    assert security is not None
    scope = SecurityScope(
        listing_mics=(security.mic,),
        currency=security.currency,
        security_kind="single_common_stock",
        share_classes=("common",),
        sec_reporting=True,
        industry_kind="general_operating_company",
    )
    assert package.publication_manifest["score_v2_fingerprints"] == tuple(
        sorted(item.fingerprint for item in inputs.score_v2)
    )

    def receipt(
        phase: str,
        authorities: tuple[Any, ...],
        upstream: tuple[PhaseReceipt, ...] = (),
    ) -> PhaseReceipt:
        return PhaseReceipt.create(
            phase=phase,
            input_receipt=input_receipt,
            upstream_receipts=upstream,
            authorities=authorities,
        )

    def official(_request: Any) -> OfficialResearchPhaseResult:
        return OfficialResearchPhaseResult(
            status=PhaseStatus.COMPLETED,
            issuer_id=request.issuer_id,
            data_cutoff_date=request.data_cutoff_date,
            receipt=receipt(
                "official_research_freeze",
                (inputs.research, inputs.source_index, scope),
            ),
            security_scope=scope,
            research_input=inputs.research,
            source_index=inputs.source_index,
            price_blind=True,
        )

    def nonprice(value: Any) -> FutuNonPricePhaseResult:
        return FutuNonPricePhaseResult(
            status=PhaseStatus.COMPLETED,
            issuer_id=request.issuer_id,
            data_cutoff_date=request.data_cutoff_date,
            receipt=receipt(
                "futu_nonprice_verification",
                (inputs.pre_execution, inputs.optional_data_dispositions),
                (value.official_research.receipt,),
            ),
            execution=inputs.pre_execution,
            optional_data_dispositions=inputs.optional_data_dispositions,
            has_material_conflict=False,
            quote_only_attested=True,
            sec_ir_authority_preserved=True,
        )

    def refreeze(value: Any) -> PriceBlindRefreezePhaseResult:
        return PriceBlindRefreezePhaseResult(
            status=PhaseStatus.COMPLETED,
            issuer_id=request.issuer_id,
            data_cutoff_date=request.data_cutoff_date,
            receipt=receipt(
                "price_blind_refreeze",
                (inputs.research, inputs.freeze),
                (value.official_research.receipt, value.futu_nonprice.receipt),
            ),
            research_input=inputs.research,
            price_blind_input=inputs.freeze,
            sec_ir_authority_preserved=True,
        )

    def market(value: Any) -> FutuMarketReferencePhaseResult:
        return FutuMarketReferencePhaseResult(
            status=PhaseStatus.COMPLETED,
            issuer_id=request.issuer_id,
            data_cutoff_date=request.data_cutoff_date,
            receipt=receipt(
                "futu_market_reference",
                (inputs.market_evidence, inputs.market_provider),
                (value.price_blind.receipt, value.futu_nonprice.receipt),
            ),
            evidence_bundle=inputs.market_evidence,
            market_reference=inputs.market_provider,
            quote_only_attested=True,
        )

    kernel_calls = 0

    def kernel(value: Any) -> KernelValuationPhaseResult:
        nonlocal kernel_calls
        kernel_calls += 1
        return KernelValuationPhaseResult(
            status=PhaseStatus.COMPLETED,
            issuer_id=request.issuer_id,
            data_cutoff_date=request.data_cutoff_date,
            receipt=receipt(
                "owner_valuation_kernel",
                (inputs.run_result, inputs.archive),
                (value.price_blind.receipt, value.market_reference.receipt),
            ),
            valuation_run=inputs.run_result,
            six_file_archive=inputs.archive,
        )

    def synthesis(value: Any) -> SynthesisPhaseResult:
        return SynthesisPhaseResult(
            status=PhaseStatus.COMPLETED,
            issuer_id=request.issuer_id,
            data_cutoff_date=request.data_cutoff_date,
            receipt=receipt(
                "three_panel_synthesis",
                (
                    inputs.run_result,
                    inputs.forward,
                    inputs.comparables,
                    inputs.composite,
                    inputs.peer_evidence_set,
                ),
                (
                    value.price_blind.receipt,
                    value.market_reference.receipt,
                    value.kernel.receipt,
                ),
            ),
            mckinsey_panel=inputs.run_result,
            forward_reoi_panel=inputs.forward,
            comparable_panel=inputs.comparables,
            composite_valuation=inputs.composite,
            peer_evidence_set=inputs.peer_evidence_set,
            three_panel_complete=True,
            current_value_available=True,
            twelve_month_target_available=True,
            recommendation_eligible=True,
        )

    def scoring(value: Any) -> ScorePhaseResult:
        return ScorePhaseResult(
            status=PhaseStatus.COMPLETED,
            issuer_id=request.issuer_id,
            data_cutoff_date=request.data_cutoff_date,
            receipt=receipt(
                "owner_scorecard",
                (inputs.score_v2, inputs.scorecard),
                (value.synthesis.receipt,),
            ),
            lens_scores=inputs.score_v2,
            scorecard=inputs.scorecard,
            recommendation=inputs.scorecard.recommendation,
        )

    def expectations(value: Any) -> MarketExpectationsPhaseResult:
        comparison_status = (
            PhaseStatus.COMPLETED
            if inputs.market_expectations.status == "complete"
            else PhaseStatus.PARTIAL
        )
        return MarketExpectationsPhaseResult(
            status=comparison_status,
            issuer_id=request.issuer_id,
            data_cutoff_date=request.data_cutoff_date,
            receipt=receipt(
                "futu_market_expectations",
                (inputs.session, inputs.market_expectations),
                (
                    value.market_reference.receipt,
                    value.synthesis.receipt,
                    value.score.receipt,
                ),
            ),
            session=inputs.session,
            comparison=inputs.market_expectations,
            gap=None,
            quote_only_attested=True,
            issue_codes=inputs.market_expectations.issue_codes,
        )

    def build_report(value: Any) -> ReportPhaseResult:
        return ReportPhaseResult(
            status=PhaseStatus.COMPLETED,
            issuer_id=request.issuer_id,
            data_cutoff_date=request.data_cutoff_date,
            receipt=receipt(
                "report",
                (report, report.receipt),
                (
                    value.official_research.receipt,
                    value.price_blind.receipt,
                    value.market_reference.receipt,
                    value.kernel.receipt,
                    value.synthesis.receipt,
                    value.score.receipt,
                    value.market_expectations.receipt,
                ),
            ),
            profile=PublicationProfile.FULL_VALUATION,
            report_build=report,
            report_build_receipt=report.receipt,
            contains_market_price=True,
            contains_target_price=True,
        )

    def publish(value: Any) -> PublicationPhaseResult:
        return PublicationPhaseResult(
            status=PhaseStatus.COMPLETED,
            issuer_id=request.issuer_id,
            data_cutoff_date=request.data_cutoff_date,
            receipt=receipt(
                "publication",
                (package, package.publication_manifest),
                (
                    value.official_research.receipt,
                    value.price_blind.receipt,
                    value.kernel.receipt,
                    value.synthesis.receipt,
                    value.score.receipt,
                    value.market_expectations.receipt,
                    value.report.receipt,
                ),
            ),
            profile=PublicationProfile.FULL_VALUATION,
            published_package=package,
            publication_manifest=package.publication_manifest,
        )

    def unused(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("closed valuation route called an unrelated phase")

    result = run_owner_equity_research(
        request=request,
        dependencies=OwnerEquityResearchDependencies(
            official_research=official,
            quarterly=unused,
            futu_nonprice=nonprice,
            refreeze_price_blind=refreeze,
            futu_market_reference=market,
            run_owner_valuation=kernel,
            synthesize=synthesis,
            score=scoring,
            futu_market_expectations=expectations,
            build_report=build_report,
            publish=publish,
            audit=lambda _request: AuditPhaseResult(
                status=PhaseStatus.BLOCKED,
                issuer_id=request.issuer_id,
                data_cutoff_date=request.data_cutoff_date,
                receipt=None,
                audit_result=None,
                read_only=True,
                issue_codes=("audit_blocked:not_requested",),
            ),
            intent=ResearchIntent.VALUATION,
            profile=PublicationProfile.FULL_VALUATION,
        ),
    )
    assert result.status is PhaseStatus.COMPLETED
    assert kernel_calls == 1
    return result


def _write_owner_result(root: Path, result: Any) -> None:
    receipts = [getattr(result, name).receipt.to_dict() for name in REQUIRED_OWNER_PHASES]
    phase_set = {
        "artifact_type": "owner-equity-research-phase-receipt-set",
        "input_receipt_fingerprint": result.input_receipt.fingerprint,
        "input_receipt_id": result.input_receipt.receipt_id,
        "receipts": receipts,
        "schema_version": "1.0.0",
    }
    _seal(phase_set, "set_fingerprint")
    _write_canonical(root / "owner-equity-result.json", result.to_dict())
    _write_canonical(root / "owner-equity-phase-receipts.json", phase_set)


def _build_private_evidence(
    sample_payloads: Any,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    futu_only: bool = False,
) -> tuple[Path, Any]:
    import test_phase5_v1_futu_data_plane as futu_data
    import test_phase5_v1_futu_market_bridge as bridge
    import test_phase5a_contract_graph as phase5a_fixtures
    from phase4a_support import replace_graph
    from phase4e2_support import complete_phase4e_graph
    from test_phase4e1_research_bundle_builder import _completed_graph

    from owner_research.contracts import Fact, ReportSpec, contract_from_dict
    from owner_research.fingerprints import to_json_value
    from owner_research.owner_equity_types import (
        build_futu_optional_data_dispositions,
        build_market_expectations_comparison,
        build_research_source_index,
    )
    from owner_research.research_bundle_artifacts import write_research_bundle_artifacts
    from owner_research.research_bundle_builder import (
        ResearchBundleBuildResult,
        build_research_bundle,
    )
    from owner_research.research_publisher import publish_owner_research
    from owner_research.research_report import (
        LatexReportRenderer,
        build_research_report,
        reload_research_input,
        reload_valuation_input,
    )
    from owner_research.valuation_pinned_kernel import PinnedKernelExecutionResult
    from owner_research.valuation_run_context import _context_payload
    from owner_research.valuation_synthesis import build_forward_reoi_valuation
    from owner_research.valuation_synthesis_types import (
        build_named_human_review_authority,
    )

    global _REAL_FUTU_PRIVATE
    _kernel_repository, kernel_example = bridge._pinned_kernel_fixture()
    futu_fixture, _futu_private, futu_public_hex = _patch_real_futu_signing(monkeypatch)
    _REAL_FUTU_PRIVATE = _futu_private
    monkeypatch.setattr(bridge, "DeterministicVerifier", futu_fixture.DeterministicVerifier)
    monkeypatch.setattr(bridge, "_signed", futu_fixture._signed)
    monkeypatch.setattr(bridge, "RUN_ID", "valuation-run:acme:probe")

    def complete_phase5a_graph(payloads: dict[str, dict]) -> Any:
        source = complete_phase4e_graph(payloads)
        built = build_research_bundle(source, run_id=source.manifests[0].run_id)
        assert built.bundle.status == "complete"
        graph = _completed_graph(source, built)
        candidate, decision = phase5a_fixtures._candidate_and_decision(
            graph,
            payloads,
        )
        graph = replace_graph(
            graph,
            valuation_assumption_candidates=(candidate,),
            valuation_assumption_review_decisions=(decision,),
            valuation_handoffs=(),
        )
        graph.validate()
        return graph

    monkeypatch.setattr(
        bridge.price_blind_fixtures,
        "_valid_graph",
        complete_phase5a_graph,
    )

    test_only_registry, _test_only_critical = _install_test_only_financial_registry(
        monkeypatch
    )
    product_registry = bridge.load_protocol_registry()
    closed_runtime_registry = {
        protocol_id: item
        for protocol_id, item in product_registry.items()
        if protocol_id != 3235
    }
    closed_runtime_registry.update(
        {
            protocol_id: bridge.FrozenMap(
                {
                    "data_family": "runtime_transport",
                    "market_scope": ["XNAS", "XNYS"],
                    "name": name,
                    "protocol_id": protocol_id,
                    "required_for_complete": True,
                    "stage": "runtime_authority",
                }
            )
            for protocol_id, name in ((1001, "InitConnect"), (1004, "KeepAlive"))
        }
    )
    assert tuple(sorted(closed_runtime_registry)) == FUTU_CLOSED_RUNTIME_PROTOCOL_IDS
    monkeypatch.setattr(
        bridge,
        "load_protocol_registry",
        lambda: closed_runtime_registry,
    )

    original_unacquired_inputs = bridge._unacquired_inputs

    def reviewed_test_unacquired_inputs(*args: Any, **kwargs: Any):
        graph, freeze, directory, security, review, raw = original_unacquired_inputs(
            *args,
            **kwargs,
        )
        source = graph.documents[0]
        retained_concepts = {item.concept for item in graph.facts}
        added_facts = tuple(
            Fact(
                schema_version="2.0.0",
                fact_id=f"fact:acme:test-only-futu-crosscheck:{concept}",
                issuer_id=security.decision.issuer_id,
                concept=concept,
                value_type="number",
                value=int(value),
                unit="currency_millions",
                currency="USD",
                period={
                    "start": None if period_kind == "stock" else "2025-01-01",
                    "end": "2025-12-31",
                },
                source_document_id=source.document_id,
                source_locator=f"test-only reviewed Futu cross-check:{concept}",
                derivation=None,
                parent_fact_ids=(),
                confidence="high",
            )
            for _field_id, (
                _statement_type,
                period_kind,
                concept,
                value,
            ) in TEST_ONLY_FINANCIAL_FIELDS.items()
            if concept not in retained_concepts
        )
        graph = replace(graph, facts=(*graph.facts, *added_facts))
        graph.validate()
        return graph, freeze, directory, security, review, raw

    monkeypatch.setattr(bridge, "_unacquired_inputs", reviewed_test_unacquired_inputs)

    def canary_runtime_request_plan(security_compilation: Any):
        decision = security_compilation.decision
        assert decision is not None
        target_code = f"US.{decision.ticker}"
        peer_codes = tuple(f"US.P{index:02d}" for index in range(1, 6))
        registry = bridge.load_protocol_registry()
        operations = [
            (target_code, 3104, bridge.FrozenMap({"get_detail": True}), 1),
            *[
                (
                    target_code,
                    protocol_id,
                    bridge._parameters(protocol_id),
                    10 if protocol_id == 3227 else 1,
                )
                for protocol_id, item in registry.items()
                if item["stage"] == "valuation_pre_price_verification"
                and item["required_for_complete"]
                and decision.exchange in item["market_scope"]
            ],
        ]
        financial_index = next(
            index for index, item in enumerate(operations) if item[1] == 3227
        )
        operations[financial_index : financial_index + 1] = [
            (
                target_code,
                3227,
                bridge.FrozenMap(
                    {
                        "statement_type": statement_type,
                        "financial_type": 7,
                        "currency_code": "USD",
                        "num": 10,
                    }
                ),
                10,
            )
            for statement_type in (1, 2, 3)
        ]
        operations.append(
            (
                target_code,
                3246,
                bridge.FrozenMap({"currency_code": "USD", "num": 50}),
                50,
            )
        )
        daily = bridge.FrozenMap(
            {
                "start": security_compilation.proposal.data_cutoff_date,
                "end": security_compilation.proposal.data_cutoff_date,
                "ktype": "K_DAY",
                "autype": "NONE",
                "fields": ["CLOSE", "VOLUME"],
                "max_count": 1,
                "extended_time": False,
                "session": "RTH",
            }
        )
        operations.append((target_code, 3103, daily, 1))
        for peer_code in peer_codes:
            operations.extend(
                (
                    (peer_code, 3202, bridge.FrozenMap({}), 1),
                    (peer_code, 3103, daily, 1),
                )
            )
        operations.extend(
            (target_code, protocol_id, bridge._parameters(protocol_id), 1)
            for protocol_id in (3229, 3230, 3232)
        )
        plan = tuple(
            bridge.build_futu_runtime_request_plan_item(
                plan_index=index,
                security_code=security_code,
                protocol_id=protocol_id,
                parameters=parameters,
                maximum_pages=maximum_pages,
            )
            for index, (security_code, protocol_id, parameters, maximum_pages) in enumerate(
                operations
            )
        )
        return (target_code, *peer_codes), plan

    original_stage_specs = bridge._stage_specs

    def canary_stage_specs(stage: str, **kwargs: Any):
        specs = original_stage_specs(stage, **kwargs)
        if stage != "valuation_pre_price_verification":
            return specs
        return (
            *specs,
            bridge.FutuRequestSpec(
                stage,
                3246,
                bridge.FrozenMap({"currency_code": "USD", "num": 50}),
            ),
        )

    monkeypatch.setattr(bridge, "_runtime_request_plan", canary_runtime_request_plan)
    monkeypatch.setattr(bridge, "_stage_specs", canary_stage_specs)

    class CanaryDataTransport(bridge.BridgeTransport):
        def exchange(self, request_bytes: bytes, *, maximum_response_bytes: int) -> bytes:
            encoded = super().exchange(
                request_bytes,
                maximum_response_bytes=maximum_response_bytes,
            )
            request = json.loads(request_bytes)
            protocol_id = request["protocol"]["id"]
            if protocol_id not in {
                3104,
                3227,
                3229,
                3230,
                3232,
                3236,
                3243,
                3246,
            }:
                return encoded
            envelope = json.loads(encoded)
            if protocol_id == 3104:
                quota_qualifiers = {
                    "get_detail": True,
                    "quota_kind": "historical_candlestick_distinct_security_7d",
                    "quota_window_days": 7,
                }
                observations = [
                    futu_data._wire_observation(
                        field_id="history_quota_used",
                        value="0",
                        unit="distinct_securities",
                        currency=None,
                        period_end=None,
                        qualifiers=quota_qualifiers,
                    ),
                    futu_data._wire_observation(
                        field_id="history_quota_remaining",
                        value="100",
                        unit="distinct_securities",
                        currency=None,
                        period_end=None,
                        qualifiers=quota_qualifiers,
                    ),
                ]
            elif protocol_id == 3227:
                statement_type = request["parameters"]["statement_type"]
                statement_name = {1: "income", 2: "balance_sheet", 3: "cash_flow"}[
                    statement_type
                ]
                observations = []
                for field_id, mapping in test_only_registry.items():
                    if mapping["statement_type"] != statement_name:
                        continue
                    observations.append(
                        futu_data._wire_financial_structure_observation(
                            field_id=field_id,
                            display_name=mapping["normalized_display_name"],
                            statement_type=statement_name,
                        )
                    )
                    current_value = TEST_ONLY_FINANCIAL_FIELDS[field_id][3]
                    periods = (
                        ((2025, "2025-12-31", current_value),)
                        if mapping["period_kind"] == "stock"
                        else (
                            (2024, "2024-12-31", str(Decimal(current_value) * Decimal("0.9"))),
                            (2025, "2025-12-31", current_value),
                        )
                    )
                    observations.extend(
                        futu_data._wire_observation(
                            field_id=field_id,
                            value=value,
                            unit=mapping["unit"],
                            currency="USD",
                            period_start=None,
                            period_end=period_end,
                            qualifiers={
                                "accounting_standard": "US_GAAP",
                                "auditor_report": "unqualified",
                                "financial_type": 7,
                                "fiscal_year": fiscal_year,
                                "period_kind": mapping["period_kind"],
                                "statement_type": statement_name,
                                "vendor_period": "FY",
                            },
                        )
                        for fiscal_year, period_end, value in periods
                    )
                if statement_name == "balance_sheet":
                    observations.extend(
                        (
                            futu_data._wire_financial_structure_observation(
                                field_id="6999",
                                display_name="Unmapped Vendor Balance Field",
                                statement_type=statement_name,
                            ),
                            futu_data._wire_observation(
                                field_id="6999",
                                value="42",
                                unit="currency_millions",
                                currency="USD",
                                period_start=None,
                                period_end="2025-12-31",
                                qualifiers={
                                    "accounting_standard": "US_GAAP",
                                    "auditor_report": "unqualified",
                                    "financial_type": 7,
                                    "fiscal_year": 2025,
                                    "period_kind": "stock",
                                    "statement_type": statement_name,
                                    "vendor_period": "FY",
                                },
                            ),
                        )
                    )
            elif protocol_id == 3236:
                observations = [
                    futu_data._wire_current_shares_vendor_disposition(),
                    futu_data._wire_empty_split_event_set(),
                ]
            elif protocol_id == 3229:
                observations = [
                    bridge._wire_number(
                        field_id="average_target_price",
                        value="60",
                        unit="currency_per_share",
                        currency="USD",
                        period_end="2026-07-13",
                        qualifiers={"consensus_scope": "current_snapshot"},
                    )
                ]
            elif protocol_id == 3230:
                observations = [
                    {
                        "field_id": "rating",
                        "period": {"start": None, "end": "2026-07-13"},
                        "qualifiers": {
                            "rating_dimension_type": 1,
                            "rating_scope": "current_snapshot",
                        },
                        "value_type": "text",
                        "value": "BUY",
                        "unit": None,
                        "currency": None,
                        "binary64_hex": None,
                        "exact_binary64_decimal": None,
                    }
                ]
            elif protocol_id == 3232:
                observations = [
                    bridge._wire_number(
                        field_id="pe_ttm",
                        value="20",
                        unit="ratio",
                        currency=None,
                        period_end="2026-07-13",
                        qualifiers={"valuation_basis": "ttm"},
                    )
                ]
            elif protocol_id == 3243:
                observations = [
                    bridge._wire_number(
                        field_id="employee_count",
                        value="10000",
                        unit="people",
                        currency=None,
                        period_end="2025-12-31",
                        qualifiers={"profile_section": "operations"},
                    )
                ]
            else:
                observations = [
                    bridge._wire_number(
                        field_id="asset_turnover",
                        value="1.25",
                        unit="ratio",
                        currency=None,
                        period_end="2025-12-31",
                        qualifiers={"metric_scope": "consolidated"},
                    )
                ]
            envelope["data_response"]["observations"] = observations
            return bridge.canonical_json(envelope).encode("utf-8")

    monkeypatch.setattr(bridge, "BridgeTransport", CanaryDataTransport)
    original_finalize_market_evidence = bridge.finalize_futu_market_execution_evidence

    def finalize_complete_test_crosschecks(*args: Any, **kwargs: Any):
        graph = kwargs["contract_graph"]
        observations = tuple(
            item
            for execution in kwargs["executions"]
            if execution.bundle.stage == "valuation_pre_price_verification"
            for item in execution.observations
            if item.source_role == "vendor_secondary" and item.comparison_eligible
        )
        operands = []
        cross_checks = []
        for observation in observations:
            candidates = tuple(
                fact
                for fact in graph.facts
                if fact.issuer_id == observation.issuer_id
                and fact.concept == observation.canonical_concept
                and to_json_value(fact.period) == to_json_value(observation.period)
                and fact.value_type == observation.value_type
                and fact.unit == observation.unit
                and fact.currency == observation.currency
            )
            assert len(candidates) == 1, (
                observation.field_id,
                observation.canonical_concept,
                candidates,
            )
            operand = bridge.build_official_evidence_operand(
                graph=graph,
                official_object=candidates[0],
            )
            receipt = bridge.crosscheck_vendor_observation(
                graph=graph,
                official=operand,
                vendor=observation,
                created_at="2026-07-14T00:57:30Z",
            )
            assert receipt.result == "consistent" and receipt.status == "resolved"
            operands.append(operand)
            cross_checks.append(receipt)
        kwargs["official_operands"] = tuple(operands)
        kwargs["cross_checks"] = tuple(cross_checks)
        return original_finalize_market_evidence(*args, **kwargs)

    monkeypatch.setattr(
        bridge,
        "finalize_futu_market_execution_evidence",
        finalize_complete_test_crosschecks,
    )
    probe = bridge._bridge_context(
        sample_payloads,
        monkeypatch,
        tmp_path / "bridge-run-id-probe",
        kernel_example=kernel_example,
    )
    handoff_run_id = probe["freeze"].handoffs[0].handoff_run_id
    monkeypatch.setattr(bridge, "RUN_ID", handoff_run_id)
    root = tmp_path / "private-evidence"
    root.mkdir(mode=0o700)
    context = bridge._bridge_context(
        sample_payloads,
        monkeypatch,
        tmp_path / "bridge-context",
        kernel_example=kernel_example,
    )
    ticket = context["provider"].ticket
    assert ticket is context["ticket"]
    context["freeze"] = ticket.expected_freeze_result
    context["security"] = ticket.expected_security_result
    latest_nonprice_response = max(
        datetime.fromisoformat(item.retrieved_at.replace("Z", "+00:00"))
        for item in context["pre_price"].responses
    )
    crosscheck_times = tuple(
        datetime.fromisoformat(item.created_at.replace("Z", "+00:00"))
        for item in context["evidence"].cross_checks
    )
    final_refreeze = max(
        datetime.fromisoformat(item.transitioned_at.replace("Z", "+00:00"))
        for item in context["freeze"].handoffs
    )
    assert crosscheck_times
    assert latest_nonprice_response < min(crosscheck_times)
    assert max(crosscheck_times) <= final_refreeze
    run_result = bridge._run_fixed_valuation(context, monkeypatch, root)
    assert run_result.archive is not None
    assert run_result.archive.output_directory == root / "six-file-archive"
    assert run_result.archive.handoff.handoff_run_id == bridge.RUN_ID
    assert run_result.input_receipt.graph is ticket.contract_graph
    assert run_result.input_receipt.expected_security is ticket.expected_security_result
    execution = run_result.execution
    assert execution is not None and execution.final_request_result is not None
    request_payload = to_json_value(execution.final_request_result.request_payload)
    share_fact_id = request_payload["mckinsey"]["equity_bridge"]["share_denominator_fact_id"]
    penman = request_payload["penman"]
    current_noa_fact_id = penman.get("current_noa_fact_id") or share_fact_id
    nfo_fact_id = (
        penman.get("net_financial_obligations_fact_id") or penman["market_equity_value_fact_id"]
    )
    facts = {item["fact_id"]: item for item in request_payload["fact_ledger"]["facts"]}
    basis, forward = bridge._basis_and_forward(
        run_result,
        current_noa_fact_id=current_noa_fact_id,
        nfo_fact_id=nfo_fact_id,
        share_value=str(facts[share_fact_id]["value"]),
        nfo_value=str(facts[nfo_fact_id]["value"]),
    )
    forward_review = bridge._review(
        run_result,
        scope="forward_reoi",
        reviewed_at="2026-07-01T01:01:00Z",
        reviewed_payload={
            "current_noa_fact_id": current_noa_fact_id,
            "scenarios": [
                {
                    "name": name,
                    "hurdle_rate": hurdle,
                    "terminal_growth": growth,
                    "forecast": [
                        {
                            "period_end": period_end,
                            "operating_income_after_tax": income,
                            "ending_noa": "20",
                        }
                        for period_end, income in zip(
                            ("2027-06-30", "2028-06-30", "2029-06-30"),
                            incomes,
                            strict=True,
                        )
                    ],
                }
                for name, hurdle, growth, incomes in (
                    ("black_swan", "0.12", "0.01", ("11.3", "39.5", "20.4")),
                    ("base", "0.10", "0.03", ("10.9", "17.6", "17")),
                    ("bull", "0.09", "0.04", ("10.7", "11.4", "13.8")),
                )
            ],
        },
    )
    forward = build_forward_reoi_valuation(
        run_result,
        basis_receipt=basis,
        review_authority=forward_review,
    )
    peer_evidence_set, peer_executions = bridge._peer_evidence_set(context)
    peer_graphs, selected_peers, metric_inputs = bridge._peer_graphs_and_inputs(peer_evidence_set)
    for metric in metric_inputs:
        for scenario in metric["scenarios"]:
            scenario["current_target_measure_per_share"] = str(
                Decimal(scenario["current_target_measure_per_share"]) * Decimal(320)
            )
            scenario["twelve_month_target_measure_per_share"] = str(
                Decimal(scenario["twelve_month_target_measure_per_share"]) * Decimal(320)
            )
    selection_review = bridge._review(
        run_result,
        scope="peer_set_selection",
        reviewed_at="2026-07-14T01:00:30Z",
        reviewed_payload={
            "selection_frozen_at": "2026-07-14T01:00:30Z",
            "peers": selected_peers,
            "registered_metrics": ["price_earnings", "price_fcf"],
            "missing_data_policy": "complete_case_all_preselected_peers",
        },
    )
    forecast_review = bridge._review(
        run_result,
        scope="comparable_forecast",
        reviewed_at="2026-07-14T01:00:20Z",
        reviewed_payload={"metric_inputs": metric_inputs},
    )
    peer_authority = bridge.build_reviewed_peer_set_authority(
        run_result=run_result,
        selection_review=selection_review,
        forecast_review=forecast_review,
        peer_graphs=peer_graphs,
        futu_peer_evidence_set=peer_evidence_set,
        verifier=futu_fixture.DeterministicVerifier(),
    )
    comparables = bridge.build_comparable_valuation(
        run_result,
        basis_receipt=basis,
        peer_authority=peer_authority,
    )
    composite = bridge.build_composite_valuation(
        run_result,
        basis_receipt=basis,
        forward_reoi=forward,
        comparables=comparables,
    )
    assert composite.status == "complete", (
        f"basis={basis.current_shares}/{basis.current_net_financial_obligations}/"
        f"{forward.input_receipt['current_noa']};"
        + ";".join(
        f"{name}={scenario['current_value_per_share']}/{scenario['twelve_month_value_per_share']}"
        for name, scenarios in composite.panel_scenarios.items()
        for scenario in scenarios
        if scenario["name"] == "base"
        )
    )
    binding = bridge._bundle_fact_binding(run_result)
    scores = tuple(
        bridge.build_score_v2(
            composite_valuation=composite,
            review_authority=bridge._review(
                run_result,
                scope=f"score:{lens}",
                reviewed_at="2026-07-14T01:07:00Z",
                reviewed_payload={
                    "composite_valuation_fingerprint": composite.fingerprint,
                    "components": [
                        {
                            "component_id": component_id,
                            "status": "complete",
                            "score": "17",
                            "confidence_percent": "90",
                            "rationale": "Bound evidence supports the fixed component score.",
                            "evidence_bindings": [binding],
                            "missing_evidence": [],
                            "red_flags": [],
                        }
                        for component_id in component_ids
                    ]
                },
            ),
        )
        for lens, component_ids in bridge.LENS_COMPONENTS.items()
    )
    scorecard = bridge.build_owner_scorecard(
        composite_valuation=composite,
        lens_scores=scores,
    )
    conclusion = bridge.build_futu_frozen_conclusion_receipt(
        run_id=bridge.RUN_ID,
        security_id=context["authority_set"].security_identity.security_id,
        composite_valuation=composite,
        owner_scorecard=scorecard,
        conclusion_frozen_at="2026-07-14T01:07:30Z",
    )
    post = bridge.execute_futu_plan(
        transport=context["transport"],
        authority=context["authority_decision"],
        runtime_authorization=context["authority_set"].runtime_authorization,
        security_identity=context["authority_set"].security_identity,
        supply_chain=context["authority_set"].supply_chain,
        run_id=bridge.RUN_ID,
        issuer_id=context["authority_set"].security_identity.issuer_id,
        security_id=context["authority_set"].security_identity.security_id,
        stage="post_valuation_context",
        data_cutoff_date=context["security"].proposal.data_cutoff_date,
        request_started_at=bridge.POST_CONTEXT_REQUEST_AT,
        specs=bridge._stage_specs(
            "post_valuation_context",
            mic=context["authority_set"].security_identity.mic,
            freeze_fingerprint=context["freeze"].artifact.fingerprint,
            frozen_conclusion=conclusion,
        ),
    )
    ordered_executions = (
        context["pre_price"],
        context["market"],
        *peer_executions,
        post,
    )
    runtime_receipt = bridge._completed_runtime(
        context["authority_set"],
        ordered_executions,
    )
    attested_finalization = futu_data.build_futu_attested_finalization_fixture(
        executions=ordered_executions,
        runtime_receipt=runtime_receipt,
        supply_chain=context["authority_set"].supply_chain,
        runtime_authorization=context["authority_set"].runtime_authorization,
        verifier=futu_fixture.DeterministicVerifier(),
    )
    prepared = run_result.preparation.prepared_market_reference
    assert prepared is not None
    acquisition = prepared.graph.market_reference_validation_contexts[0].vendor_market_acquisition
    completion = bridge.futu_market.complete_futu_market_session(
        acquisition=acquisition,
        authority_set=replace(context["authority_set"], runtime=runtime_receipt),
        authority_decision=context["authority_decision"],
        peer_evidence_set=peer_evidence_set,
        frozen_conclusion=conclusion,
        attested_finalization=attested_finalization,
        post_valuation_execution=post,
        finalized_at="2026-07-14T01:08:32Z",
        verifier=futu_fixture.DeterministicVerifier(),
    )
    session = completion.session_evidence
    graph = run_result.input_receipt.graph
    bundle = graph.research_bundles[0]
    manifest = next(item for item in graph.manifests if item.run_id == bundle.run_id)
    research_result = ResearchBundleBuildResult(bundle=bundle, run_manifest=manifest)
    research_directory = root / "research-input"
    write_research_bundle_artifacts(
        graph,
        research_result,
        output_directory=research_directory,
    )
    research = reload_research_input(research_directory, graph=graph)
    source_index = build_research_source_index(graph=graph, research=research.result)
    report_spec = contract_from_dict(
        "report-spec",
        {**sample_payloads["report-spec"], "output_formats": ["json", "markdown", "latex_pdf"]},
    )
    assert isinstance(report_spec, ReportSpec)
    evidence_fact = graph.facts[0]
    optional_review = build_named_human_review_authority(
        scope="futu_optional_data_plan",
        graph=graph,
        research_bundle=bundle,
        reviewer_id="human:futu-data-reviewer",
        reviewed_at="2026-07-14T00:58:00Z",
        rationale="Freeze the optional quote-only vendor plan before execution.",
        reviewed_payload={
            "company_executives": False,
            "executive_background_leader_name": None,
            "operational_efficiency": True,
            "us_buybacks_disposition": "not_supported_for_us_sec_primary",
        },
        evidence_bindings=(
            {
                "object_type": "Fact",
                "object_id": evidence_fact.fact_id,
                "fingerprint": evidence_fact.fingerprint,
            },
        ),
    )
    optional_data_dispositions = build_futu_optional_data_dispositions(
        execution=context["pre_price"],
        review_authority=optional_review,
    )
    market_expectations = build_market_expectations_comparison(
        session=session,
        composite_valuation=composite,
        owner_scorecard=scorecard,
        verifier=futu_fixture.DeterministicVerifier(),
    )
    assert market_expectations.status == "complete"
    assert market_expectations.issue_codes == ()
    assert {
        observation["data_family"]
        for observation in market_expectations.to_dict()["observations"]
    } == {"analyst_consensus", "analyst_ratings", "valuation_context"}
    valuation = reload_valuation_input(run_result.archive.output_directory)
    inputs = SimpleNamespace(
        run_result=run_result,
        archive=run_result.archive,
        research=research,
        source_index=source_index,
        report_spec=report_spec,
        valuation=valuation,
        freeze=context["freeze"],
        pre_execution=context["pre_price"],
        market_evidence=context["evidence"],
        market_provider=context["provider"],
        forward=forward,
        comparables=comparables,
        composite=composite,
        score_v2=scores,
        scorecard=scorecard,
        peer_evidence_set=peer_evidence_set,
        session=session,
        futu=SimpleNamespace(
            session=session,
            verifier=futu_fixture.DeterministicVerifier(),
        ),
        optional_data_dispositions=optional_data_dispositions,
        market_expectations=market_expectations,
    )

    def write_private_futu_loader_inputs() -> None:
        keyring_identity = {
            "algorithm": "ed25519",
            "keyring_id": "keyring:release-canary-futu",
            "keys": {"test-key": futu_public_hex},
        }
        _write_canonical(
            root / "futu-keyring.json",
            {
                "algorithm": "ed25519",
                "artifact_type": "owner-research-public-keyring",
                "keyring_fingerprint": NAMESPACE["_projection_sha256"](
                    keyring_identity
                ),
                "keyring_id": keyring_identity["keyring_id"],
                "keys": [{"key_id": "test-key", "public_key_hex": futu_public_hex}],
                "schema_version": "1.0.0",
            },
        )
        futu_payload = {
            "artifact_type": "owner-equity-private-futu-evidence",
            "attested_session_finalization": (
                inputs.futu.session.attested_finalization.to_dict()
            ),
            "authority_decision": inputs.futu.session.authority_decision.to_dict(),
            "authority_set": _authority_payload(inputs.futu.session.authority_set),
            "cross_checks": [
                item.to_dict() for item in inputs.futu.session.cross_checks
            ],
            "executions": _ordered_futu_records(inputs),
            "schema_version": "1.0.0",
        }
        _write_canonical(root / "futu-private-evidence.json", futu_payload)

    if futu_only:
        write_private_futu_loader_inputs()
        for member in root.rglob("*"):
            if member.is_file():
                member.chmod(0o444)
        for directory in sorted(
            (item for item in root.rglob("*") if item.is_dir()),
            key=lambda item: len(item.parts),
            reverse=True,
        ):
            directory.chmod(0o555)
        root.chmod(0o555)
        return root, inputs

    report = build_research_report(
        profile="full_valuation",
        research=inputs.research,
        report_spec=inputs.report_spec,
        research_source_index=inputs.source_index,
        scores=(),
        valuation=inputs.valuation,
        futu_session_evidence=inputs.session,
        futu_verifier=inputs.futu.verifier,
        futu_optional_data_dispositions=inputs.optional_data_dispositions,
        forward_reoi=inputs.forward,
        comparable_valuation=inputs.comparables,
        composite_valuation=inputs.composite,
        score_v2=inputs.score_v2,
        owner_scorecard=inputs.scorecard,
        market_expectations=inputs.market_expectations,
        renderer=LatexReportRenderer(),
    )
    package = publish_owner_research(
        report,
        inputs.research,
        valuation=inputs.valuation,
        output_directory=root / "publication",
        futu_verifier=inputs.futu.verifier,
    )
    write_private_futu_loader_inputs()
    _write_canonical(
        root / "valuation-run-input-receipt.json",
        inputs.run_result.input_receipt.to_dict(),
    )
    valuation_execution = inputs.run_result.execution
    assert valuation_execution is not None
    final_request_result = valuation_execution.final_request_result
    fact_ledger_result = final_request_result.fact_ledger_result
    kernel_execution_result = valuation_execution.kernel_execution_result
    assert fact_ledger_result is not None and kernel_execution_result is not None
    validation_contexts = prepared.graph.market_reference_validation_contexts
    assert len(validation_contexts) == 1
    vendor_acquisition = validation_contexts[0].vendor_market_acquisition
    assert vendor_acquisition is not None
    final_request_execution_evidence = {
        "current_share_projection": (
            fact_ledger_result.current_share_projection.to_dict()
        ),
        "numeric_projection": {
            "current_share_numeric_witnesses": [
                item.to_dict()
                for item in fact_ledger_result.current_share_projection.numeric_witnesses
            ],
            "quote_projection_witness": (
                fact_ledger_result.quote_projection_witness.to_dict()
            ),
            "market_equity_projection_witness": (
                fact_ledger_result.market_equity_projection_witness.to_dict()
            ),
        },
        "market_execution_evidence": (
            vendor_acquisition.market_execution_evidence.to_dict()
        ),
        "vendor_market_acquisition": vendor_acquisition.to_dict(),
    }
    kernel_execution_evidence = {
        name: to_json_value(getattr(kernel_execution_result, name))
        for name in PinnedKernelExecutionResult.__dataclass_fields__
        if name != "result_bytes"
    }
    _write_canonical(
        root / "owner-equity-typed-authorities.json",
        {
            "artifact_type": "owner-equity-canary-typed-authorities",
            "final_request_execution_evidence": final_request_execution_evidence,
            "final_request_receipt": (
                valuation_execution.final_request_receipt.to_dict()
            ),
            "kernel_execution_evidence": kernel_execution_evidence,
            "kernel_execution_receipt": (
                valuation_execution.kernel_execution_receipt.to_dict()
            ),
            "market_provider": context["provider"].to_dict(),
            "market_ticket": context["ticket"].to_dict(),
            "prepared_market_reference": {
                "current_shares": prepared.current_shares.to_dict(),
                "market_equity_calculation": prepared.market_equity_calculation.to_dict(),
                "market_source": prepared.market_source.to_dict(),
                "quote_fact": prepared.quote_fact.to_dict(),
                "snapshot": prepared.snapshot.to_dict(),
            },
            "schema_version": "1.0.0",
            "valuation_run_context": _context_payload(
                graph=inputs.run_result.input_receipt.graph,
                bundle_artifact_directory=research_directory,
                expected_freeze=inputs.run_result.input_receipt.expected_freeze,
                security_proposal=inputs.run_result.input_receipt.expected_security.proposal,
                assumption_proposals=(),
                assumption_reviews=(),
                clock=inputs.run_result.input_receipt.clock,
            ),
        },
    )
    result = _run_high_level_result(inputs=inputs, package=package, report=report)
    _write_owner_result(root, result)
    for member in root.rglob("*"):
        if member.is_file():
            member.chmod(0o444)
    for directory in sorted(
        (item for item in root.rglob("*") if item.is_dir()),
        key=lambda item: len(item.parts),
        reverse=True,
    ):
        directory.chmod(0o555)
    root.chmod(0o555)
    return root, inputs


def _trusted_key(
    tmp_path: Path,
    *,
    not_before: str = "2026-07-13T00:00:00Z",
    not_after: str = "2026-07-15T00:00:00Z",
) -> tuple[Path, Ed25519PrivateKey]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    private = Ed25519PrivateKey.generate()
    public_hex = (
        private.public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex()
    )
    path = tmp_path / f"trusted-{hashlib.sha256(not_before.encode()).hexdigest()[:8]}.json"
    _write_canonical(
        path,
        {
            "algorithm": "Ed25519",
            "artifact_type": "owner-equity-rc-canary-trusted-signer-key",
            "key_id": TEST_ONLY_SIGNER_KEY_ID,
            "not_after": not_after,
            "not_before": not_before,
            "public_key_hex": public_hex,
            "revoked": False,
            "schema_version": "1.0.0",
            "usages": ["owner_equity_rc_canary"],
        },
    )
    policy_path = tmp_path / "release-trust-policy.json"
    policy = {
        "artifact_type": "owner-equity-release-canary-trust-policy",
        "keys": [
            {
                "key_id": TEST_ONLY_SIGNER_KEY_ID,
                "not_after": not_after,
                "not_before": not_before,
                "public_key_sha256": hashlib.sha256(bytes.fromhex(public_hex)).hexdigest(),
                "revoked": False,
                "status": "active",
                "usage": "owner_equity_rc_canary",
            }
        ],
        "policy_id": "owner-equity-rc-release-control-v1",
        "schema_version": "1.0.0",
        "signer_keys_installed": True,
        "status": "active",
        "valid_from": "2026-07-13T00:00:00Z",
        "valid_until": "2026-07-15T00:00:00Z",
    }
    _write_canonical(policy_path, policy)
    ASSEMBLE.__globals__["RELEASE_TRUST_POLICY_PATH"] = policy_path
    ASSEMBLE.__globals__["RELEASE_CONTROL_TRUST_POLICY_SHA256"] = hashlib.sha256(
        policy_path.read_bytes()
    ).hexdigest()
    return path, private


def _darwin_logical_var_path(path: Path) -> Path:
    absolute = path.absolute()
    if sys.platform != "darwin" or absolute.parts[:3] != ("/", "private", "var"):
        pytest.skip("test temporary directory is not below Darwin /private/var")
    return Path("/var").joinpath(*absolute.parts[3:])


def _gates(evidence: dict[str, Any]) -> dict[str, dict[str, Any]]:
    gates = {
        "legal": {
            "artifact_type": "owner-equity-canary-legal-gate-receipt",
            "status": "passed",
            "scope": "futu_quote_only_us_equities",
            "valid_from": "2026-07-13T00:00:00Z",
            "valid_until": "2026-07-15T00:00:00Z",
            "revocable": True,
            "authority_fingerprint": evidence["legal_fingerprint"],
        },
        "account_entitlement": {
            "artifact_type": "owner-equity-canary-account-entitlement-gate-receipt",
            "status": "passed",
            "scope": "futu_quote_only_us_equities",
            "valid_from": "2026-07-13T00:00:00Z",
            "valid_until": "2026-07-15T00:00:00Z",
            "quote_only": True,
            "authorized": True,
            "authority_fingerprint": evidence["account_fingerprint"],
        },
        "supply_chain": {
            "artifact_type": "owner-equity-canary-supply-chain-gate-receipt",
            "status": "passed",
            "exact_commit_verified": True,
            "exact_tree_verified": True,
            "artifact_hashes_verified": True,
            "authority_fingerprint": evidence["supply_chain_fingerprint"],
        },
        "runtime_isolation": {
            "artifact_type": "owner-equity-canary-runtime-isolation-gate-receipt",
            "status": "passed",
            "quote_protocol_allowlist_closed": True,
            "trade_protocols_blocked": True,
            "raw_data_private_encrypted_cas": True,
            "authority_fingerprint": evidence["runtime_authorization_fingerprint"],
            "completed_runtime_fingerprint": evidence["runtime_receipt_fingerprint"],
            "replay_authority_decision_fingerprint": evidence[
                "replay_authority_decision_fingerprint"
            ],
            "valid_from": "2026-07-14T00:53:00Z",
            "valid_until": "2026-07-14T01:09:00Z",
        },
        "security_identity": {
            "artifact_type": "owner-equity-canary-security-identity-gate-receipt",
            "status": "passed",
            "security_identity_matched": True,
            "currency_matched": True,
            "share_basis_matched": True,
            "authority_fingerprint": evidence["security_fingerprint"],
        },
        "session": {
            "artifact_type": "owner-equity-canary-session-gate-receipt",
            "status": "passed",
            "qot_logined": True,
            "trd_logined": evidence["session_trd_logined"],
            "quote_only": True,
            "attested_finalization_fingerprint": evidence["finalization_fingerprint"],
        },
        "sec_ir_reconciliation": {
            "artifact_type": "owner-equity-canary-sec-ir-reconciliation-gate-receipt",
            "status": "passed",
            "sec_ir_primary": True,
            "material_conflicts": 0,
            "cross_check_root_fingerprint": evidence["cross_check_root_fingerprint"],
        },
        "six_file_archive": {
            "artifact_type": "owner-equity-canary-six-file-archive-gate-receipt",
            "status": "passed",
            "strict_reload": True,
            "member_count": 6,
            "hashes_verified": True,
            "archive_fingerprint": evidence["archive_fingerprint"],
        },
        "publisher_pdf": {
            "artifact_type": "owner-equity-canary-publisher-pdf-gate-receipt",
            "status": "passed",
            "profile": "full_valuation",
            "strict_package_reload": True,
            "pdf_reload": True,
            "pdf_pages": evidence["pdf_pages"],
            "target_price_present": True,
            "scorecard_present": True,
            "publication_manifest_fingerprint": evidence["publication_manifest_fingerprint"],
        },
    }
    for gate in gates.values():
        _seal(gate, "receipt_sha256")
    return gates


def _signed_receipt(
    path: Path,
    *,
    private: Ed25519PrivateKey,
    commit: str,
    tree: str,
    artifacts: list[dict[str, Any]],
    evidence: dict[str, Any],
    mutate_gates: Any = None,
    output_root: str | None = None,
) -> Path:
    gates = _gates(evidence)
    if mutate_gates is not None:
        mutate_gates(gates)
        for gate in gates.values():
            _seal(gate, "receipt_sha256")
    by_role = {item["role"]: item for item in artifacts}
    sidecar_install = {
        "artifact_type": "owner-equity-sidecar-install-attestation",
        "boot_attestation_fingerprint": evidence["sidecar_boot_attestation_fingerprint"],
        "execution_attestation_fingerprint": evidence["sidecar_execution_attestation_fingerprint"],
        "sidecar_sdist_sha256": by_role["sidecar_sdist"]["sha256"],
        "sidecar_wheel_sha256": by_role["sidecar_wheel"]["sha256"],
        "status": "executed",
        "supply_chain_fingerprint": evidence["supply_chain_fingerprint"],
    }
    _seal(sidecar_install, "install_attestation_fingerprint")
    invocation = {
        "artifact_type": "owner-equity-research-canary-invocation-attestation",
        "candidate_commit": commit,
        "candidate_tree": tree,
        "console_script": "owner-equity-research",
        "output_evidence_root_sha256": output_root or evidence["evidence_root_sha256"],
        "owner_wheel_sha256": by_role["owner_wheel"]["sha256"],
        "plugin_bundle_sha256": by_role["plugin_bundle"]["sha256"],
        "sidecar_install_attestation": sidecar_install,
        "skill_name": "owner-equity-research",
        "status": "completed",
        "subcommand": "valuation",
    }
    _seal(invocation, "invocation_attestation_fingerprint")
    root = {
        "artifact_type": "owner-equity-rc-canary-root",
        "artifacts": artifacts,
        "candidate_commit": commit,
        "candidate_tree": tree,
        "evidence_root_sha256": evidence["evidence_root_sha256"],
        "executed_at": EXECUTED_AT,
        "gate_receipt_sha256": {
            name: gates[name]["receipt_sha256"] for name in NAMESPACE["GATE_NAMES"]
        },
        "invocation_attestation_fingerprint": invocation["invocation_attestation_fingerprint"],
        "schema_version": "2.0.0",
    }
    receipt = {
        "artifact_type": "owner-equity-rc-canary-receipt",
        "artifacts": artifacts,
        "canary_root_sha256": NAMESPACE["_projection_sha256"](root),
        "candidate_commit": commit,
        "candidate_tree": tree,
        "executed_at": EXECUTED_AT,
        "expires_at": "2026-07-14T01:09:00Z",
        "gates": gates,
        "invocation_attestation": invocation,
        "schema_version": "3.0.0",
        "signer_key_id": TEST_ONLY_SIGNER_KEY_ID,
    }
    receipt["signature"] = {
        "algorithm": "Ed25519",
        "key_id": TEST_ONLY_SIGNER_KEY_ID,
        "value_base64": base64.b64encode(private.sign(CANONICAL(receipt, newline=False))).decode(),
    }
    return _write_canonical(path, receipt)


_REAL_EVIDENCE: Path | None = None
_REAL_FUTU_LOADER_EVIDENCE: Path | None = None
_REAL_FUTU_PRIVATE: Ed25519PrivateKey | None = None


@pytest.fixture
def real_evidence(
    sample_payloads: Any,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path_factory: pytest.TempPathFactory,
) -> Path:
    import test_phase5_v1_futu_market_bridge as bridge

    from owner_research.fingerprints import canonical_sha256

    global _REAL_EVIDENCE
    _install_test_only_financial_registry(monkeypatch)
    if _REAL_EVIDENCE is None:
        root = tmp_path_factory.mktemp("release-real-evidence")
        _REAL_EVIDENCE = _build_private_evidence(
            sample_payloads,
            monkeypatch,
            root,
        )[0]
    monkeypatch.setattr(
        bridge.market_provider_module,
        "_AUTHORIZATION_STATE_BASE",
        _REAL_EVIDENCE.parent / "bridge-context" / "authorization-state",
    )
    monkeypatch.setattr(
        bridge.market_provider_module,
        "_authorization_store_policy",
        lambda _component_lock_path: (
            "market-authorizations-v1",
            canonical_sha256({"bridge_fixture": "authorization_store_policy"}),
        ),
    )
    return _REAL_EVIDENCE


@pytest.fixture
def real_futu_loader_evidence(
    sample_payloads: Any,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path_factory: pytest.TempPathFactory,
) -> Path:
    global _REAL_FUTU_LOADER_EVIDENCE
    _install_test_only_financial_registry(monkeypatch)
    if _REAL_FUTU_LOADER_EVIDENCE is None:
        root = tmp_path_factory.mktemp("release-real-futu-loader-evidence")
        _REAL_FUTU_LOADER_EVIDENCE = _build_private_evidence(
            sample_payloads,
            monkeypatch,
            root,
            futu_only=True,
        )[0]
    return _REAL_FUTU_LOADER_EVIDENCE


def test_real_private_futu_evidence_reaches_market_and_post_request_validation(
    real_futu_loader_evidence: Path,
) -> None:
    payload = json.loads(
        (real_futu_loader_evidence / "futu-private-evidence.json").read_text()
    )
    result = NAMESPACE["_load_private_futu"](
        payload,
        keyring_file=real_futu_loader_evidence / "futu-keyring.json",
        executed_at=datetime.strptime(EXECUTED_AT, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=UTC
        ),
    )
    market_record = next(
        item
        for item in payload["executions"]
        if item["bundle"]["stage"] == "market_reference"
    )
    assert result["market_trading_date"] == market_record["requests"][0][
        "expected_trading_date"
    ]
    assert result["session_trd_logined"] is True
    assert set(result["target_stage_requests"]) == {
        "market_reference",
        "post_valuation_context",
        "valuation_pre_price_verification",
    }


def _case(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    real_evidence: Path,
) -> dict[str, Any]:
    _stub_verifiers(monkeypatch)
    _install_test_only_financial_registry(monkeypatch)
    source, commit, tree = _source_repository(tmp_path)
    artifacts = _artifacts(tmp_path)
    key, private = _trusted_key(tmp_path)
    evidence = NAMESPACE["_load_private_canary_evidence"](
        real_evidence,
        executed_at=datetime.strptime(EXECUTED_AT, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC),
    )
    receipt = _signed_receipt(
        tmp_path / "canary.json",
        private=private,
        commit=commit,
        tree=tree,
        artifacts=_artifact_records(artifacts),
        evidence=evidence,
    )
    return {
        "mode": "rc",
        "source_root": source,
        "expected_commit": commit,
        "expected_tree": tree,
        "output_directory": tmp_path / "release",
        "assembled_at": VERIFICATION_TIME,
        "canary_receipt": receipt,
        "canary_evidence_bundle": real_evidence,
        "trusted_signer_key": key,
        "trusted_signer_key_id": TEST_ONLY_SIGNER_KEY_ID,
        "verification_time": VERIFICATION_TIME,
        **artifacts,
    }


def test_rc_strictly_reloads_real_private_evidence_and_keeps_sidecar_private(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    real_evidence: Path,
) -> None:
    import owner_research.research_publisher as publisher
    import owner_research.valuation_run_archive as archive_module

    calls = {"archive": 0, "package": 0}
    real_archive = archive_module.load_valuation_run_archive
    real_package = publisher.load_owner_research_package

    def archive_loader(*args: Any, **kwargs: Any):
        calls["archive"] += 1
        return real_archive(*args, **kwargs)

    def package_loader(*args: Any, **kwargs: Any):
        calls["package"] += 1
        return real_package(*args, **kwargs)

    monkeypatch.setattr(archive_module, "load_valuation_run_archive", archive_loader)
    monkeypatch.setattr(publisher, "load_owner_research_package", package_loader)
    kwargs = _case(tmp_path, monkeypatch, real_evidence)
    output = ASSEMBLE(**kwargs)

    assert calls == {"archive": 2, "package": 2}
    public = {path.name for path in output.iterdir()}
    assert not any("futu_sidecar" in name for name in public)
    assert public == {kwargs[role].name for role in PUBLIC_ARTIFACT_ROLES} | {
        "SHA256SUMS",
        "release-manifest.json",
        "sbom.cdx.json",
    }
    checksums = (output / "SHA256SUMS").read_text()
    assert "futu_sidecar" not in checksums
    manifest = json.loads((output / "release-manifest.json").read_text())
    assert manifest["canary"]["signer_key_id"] == TEST_ONLY_SIGNER_KEY_ID
    assert manifest["rc_blockers"] == []

    archive_manifest = json.loads(
        (real_evidence / "six-file-archive" / "valuation-run-manifest.json").read_text()
    )
    assert {
        "final_request_projection",
        "kernel_execution_projection",
        "kernel_runtime_authority",
    }.issubset(archive_manifest)
    assert {
        "final_request_receipt",
        "kernel_execution_receipt",
        "kernel_runtime_manifest",
    }.isdisjoint(archive_manifest)
    typed = json.loads(
        (real_evidence / "owner-equity-typed-authorities.json").read_text()
    )
    for receipt_name, projection_name in (
        ("final_request_receipt", "final_request_projection"),
        ("kernel_execution_receipt", "kernel_execution_projection"),
    ):
        receipt = typed[receipt_name]
        projection = archive_manifest[projection_name]
        assert {name: receipt[name] for name in projection} == projection


def _rebind_execution_receipt_id(
    receipt_name: str,
    receipt: dict[str, Any],
) -> None:
    identity = dict(receipt)
    identity.pop("receipt_id")
    if receipt_name == "final_request_receipt":
        receipt["receipt_id"] = (
            f"final-request-receipt:{receipt['issuer_id']}:"
            f"{NAMESPACE['_projection_sha256'](identity)[:24]}"
        )
    else:
        receipt["receipt_id"] = (
            f"kernel-execution-receipt:{NAMESPACE['_projection_sha256'](identity)[:24]}"
        )


@pytest.mark.parametrize(
    ("receipt_name", "field", "value"),
    (
        ("final_request_receipt", "market_quote_fact_id", "fact:rebound"),
        ("kernel_execution_receipt", "request_sha256", "f" * 64),
    ),
)
def test_private_execution_receipt_must_exactly_project_to_archive(
    tmp_path: Path,
    real_evidence: Path,
    receipt_name: str,
    field: str,
    value: str,
) -> None:
    copied = tmp_path / "private-evidence"
    shutil.copytree(real_evidence, copied, copy_function=shutil.copy2)
    path = copied / "owner-equity-typed-authorities.json"
    payload = json.loads(path.read_text())
    receipt = payload[receipt_name]
    receipt[field] = value
    _rebind_execution_receipt_id(receipt_name, receipt)
    path.chmod(0o600)
    _write_canonical(path, payload)
    with pytest.raises(
        ERROR,
        match="execution receipts differ from .*archive projections",
    ):
        NAMESPACE["_load_private_canary_evidence"](
            copied,
            executed_at=datetime.strptime(EXECUTED_AT, "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=UTC
            ),
        )


def test_private_execution_receipt_requires_exact_json_roundtrip(
    tmp_path: Path,
    real_evidence: Path,
) -> None:
    copied = tmp_path / "private-evidence"
    shutil.copytree(real_evidence, copied, copy_function=shutil.copy2)
    path = copied / "owner-equity-typed-authorities.json"
    payload = json.loads(path.read_text())
    added = payload["final_request_receipt"]["added_fact_ids"]
    assert len(added) > 1
    added.reverse()
    path.chmod(0o600)
    _write_canonical(path, payload)
    with pytest.raises(ERROR, match="differ from exact input"):
        NAMESPACE["_load_private_canary_evidence"](
            copied,
            executed_at=datetime.strptime(EXECUTED_AT, "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=UTC
            ),
        )


def test_kernel_receipt_must_bind_replayed_runtime_manifest(
    tmp_path: Path,
    real_evidence: Path,
) -> None:
    copied = tmp_path / "private-evidence"
    shutil.copytree(real_evidence, copied, copy_function=shutil.copy2)
    path = copied / "owner-equity-typed-authorities.json"
    payload = json.loads(path.read_text())
    receipt = payload["kernel_execution_receipt"]
    receipt["runtime_manifest_fingerprint"] = "e" * 64
    _rebind_execution_receipt_id("kernel_execution_receipt", receipt)
    path.chmod(0o600)
    _write_canonical(path, payload)
    with pytest.raises(
        ERROR,
        match="typed valuation execution receipts differ from exact input",
    ):
        NAMESPACE["_load_private_canary_evidence"](
            copied,
            executed_at=datetime.strptime(EXECUTED_AT, "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=UTC
            ),
        )


def test_final_receipt_nonpublic_fields_must_bind_market_objects(
    tmp_path: Path,
    real_evidence: Path,
) -> None:
    copied = tmp_path / "private-evidence"
    shutil.copytree(real_evidence, copied, copy_function=shutil.copy2)
    path = copied / "owner-equity-typed-authorities.json"
    payload = json.loads(path.read_text())
    receipt = payload["final_request_receipt"]
    receipt["market_provider_receipt_id"] = "market-receipt:rebound"
    _rebind_execution_receipt_id("final_request_receipt", receipt)
    path.chmod(0o600)
    _write_canonical(path, payload)
    with pytest.raises(ERROR, match="typed market/provider authorities were rebound"):
        NAMESPACE["_load_private_canary_evidence"](
            copied,
            executed_at=datetime.strptime(EXECUTED_AT, "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=UTC
            ),
        )


def test_final_receipt_rejects_coordinated_market_context_rebind(
    tmp_path: Path,
    real_evidence: Path,
) -> None:
    copied = tmp_path / "private-evidence"
    shutil.copytree(real_evidence, copied, copy_function=shutil.copy2)
    path = copied / "owner-equity-typed-authorities.json"
    payload = json.loads(path.read_text())
    receipt = payload["final_request_receipt"]
    receipt["market_validation_context_fingerprint"] = "e" * 64
    receipt["market_evidence_binding_sha256"] = NAMESPACE["_projection_sha256"](
        {
            "context": [
                receipt["market_validation_context_id"],
                receipt["market_validation_context_fingerprint"],
            ],
            "access_fingerprint": receipt["market_access_result_fingerprint"],
            "provider": [
                receipt["market_provider_id"],
                receipt["market_provider_registration_sha256"],
                receipt["market_provider_receipt_id"],
                receipt["market_provider_receipt_fingerprint"],
            ],
            "current_share_compilation_fingerprint": receipt[
                "current_share_compilation_fingerprint"
            ],
            "source_document": [
                receipt["market_source_document_id"],
                receipt["market_source_document_fingerprint"],
            ],
            "source_ref_fingerprint": receipt["market_source_ref_fingerprint"],
            "raw_response_sha256": receipt["market_raw_response_sha256"],
            "quote_fact": [
                receipt["market_quote_fact_id"],
                receipt["market_quote_fact_fingerprint"],
            ],
            "market_equity_calculation": [
                receipt["market_equity_calculation_id"],
                receipt["market_equity_calculation_fingerprint"],
            ],
        }
    )
    _rebind_execution_receipt_id("final_request_receipt", receipt)
    path.chmod(0o600)
    _write_canonical(path, payload)
    with pytest.raises(ERROR, match="typed market/provider authorities were rebound"):
        NAMESPACE["_load_private_canary_evidence"](
            copied,
            executed_at=datetime.strptime(EXECUTED_AT, "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=UTC
            ),
        )


def test_final_receipt_rejects_coordinated_numeric_witness_rebind(
    tmp_path: Path,
    real_evidence: Path,
) -> None:
    copied = tmp_path / "private-evidence"
    shutil.copytree(real_evidence, copied, copy_function=shutil.copy2)
    path = copied / "owner-equity-typed-authorities.json"
    payload = json.loads(path.read_text())
    evidence = payload["final_request_execution_evidence"]
    projection_witness = evidence["current_share_projection"]["numeric_witnesses"][0]
    duplicate_witness = evidence["numeric_projection"][
        "current_share_numeric_witnesses"
    ][0]
    assert projection_witness == duplicate_witness
    for witness in (projection_witness, duplicate_witness):
        witness["authoritative_decimal"] = format(
            Decimal(witness["authoritative_decimal"]) * Decimal(10),
            "f",
        )
        witness["scale_divisor_decimal"] = format(
            Decimal(witness["scale_divisor_decimal"]) * Decimal(10),
            "f",
        )
    receipt = payload["final_request_receipt"]
    receipt["current_share_projection_sha256"] = NAMESPACE["_projection_sha256"](
        evidence["current_share_projection"]
    )
    receipt["numeric_projection_sha256"] = NAMESPACE["_projection_sha256"](
        evidence["numeric_projection"]
    )
    _rebind_execution_receipt_id("final_request_receipt", receipt)
    path.chmod(0o600)
    _write_canonical(path, payload)
    with pytest.raises(
        ERROR,
        match="typed valuation execution receipts differ from exact input",
    ):
        NAMESPACE["_load_private_canary_evidence"](
            copied,
            executed_at=datetime.strptime(EXECUTED_AT, "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=UTC
            ),
        )


@pytest.mark.parametrize(
    ("gate_name", "field", "value"),
    (
        ("legal", "valid_from", "2026-07-14T01:08:36Z"),
        ("account_entitlement", "valid_until", "2026-07-14T01:08:34Z"),
        ("runtime_isolation", "valid_from", "2026-07-14T01:08:36Z"),
        ("runtime_isolation", "valid_until", "2026-07-14T01:08:34Z"),
    ),
)
def test_authority_windows_must_cover_canary_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    real_evidence: Path,
    gate_name: str,
    field: str,
    value: str,
) -> None:
    kwargs = _case(tmp_path, monkeypatch, real_evidence)
    receipt = json.loads(kwargs["canary_receipt"].read_text())
    receipt["gates"][gate_name][field] = value
    _seal(receipt["gates"][gate_name], "receipt_sha256")
    # A stale signature would fail too; use the original helper inputs to prove the time gate.
    with pytest.raises(ERROR, match="execution|cover"):
        NAMESPACE["_verify_gate_payload"](
            receipt["gates"],
            executed_at=datetime.strptime(EXECUTED_AT, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC),
            verification_time=datetime.strptime(VERIFICATION_TIME, "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=UTC
            ),
        )


def test_trusted_signer_key_must_cover_execution_not_only_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    real_evidence: Path,
) -> None:
    kwargs = _case(tmp_path, monkeypatch, real_evidence)
    key, _ = _trusted_key(
        tmp_path / "late-key",
        not_before="2026-07-14T01:08:36Z",
        not_after="2026-07-15T00:00:00Z",
    )
    kwargs["trusted_signer_key"] = key
    with pytest.raises(ERROR, match="trusted signer key"):
        ASSEMBLE(**kwargs)


def test_trusted_signer_key_rejects_writable_ancestor(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    trust = tmp_path / "trust"
    key, _private = _trusted_key(trust)
    trust.chmod(0o770)
    with pytest.raises(ERROR, match="unsafe writable ancestor"):
        NAMESPACE["_load_trusted_key"](
            key,
            expected_key_id=TEST_ONLY_SIGNER_KEY_ID,
            source_root=source,
            executed_at=datetime.strptime(EXECUTED_AT, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC),
            verification_time=datetime.strptime(VERIFICATION_TIME, "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=UTC
            ),
        )


def test_trusted_signer_key_rejects_symlinked_parent_rebind(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    trust = tmp_path / "trust"
    key, _private = _trusted_key(trust)
    alias = tmp_path / "trust-alias"
    alias.symlink_to(trust, target_is_directory=True)
    with pytest.raises(ERROR, match="unsafe or unavailable"):
        NAMESPACE["_load_trusted_key"](
            alias / key.name,
            expected_key_id=TEST_ONLY_SIGNER_KEY_ID,
            source_root=source,
            executed_at=datetime.strptime(EXECUTED_AT, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC),
            verification_time=datetime.strptime(VERIFICATION_TIME, "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=UTC
            ),
        )


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin fixed root aliases only")
def test_trusted_signer_key_accepts_only_fixed_var_alias(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    trust = tmp_path / "trust"
    key, private = _trusted_key(trust)

    loaded = NAMESPACE["_load_trusted_key"](
        _darwin_logical_var_path(key),
        expected_key_id=TEST_ONLY_SIGNER_KEY_ID,
        source_root=_darwin_logical_var_path(source),
        executed_at=datetime.strptime(EXECUTED_AT, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC),
        verification_time=datetime.strptime(VERIFICATION_TIME, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=UTC
        ),
    )
    assert loaded.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    ) == private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )

    user_alias = tmp_path / "trust-user-alias"
    user_alias.symlink_to(trust, target_is_directory=True)
    with pytest.raises(ERROR, match="unsafe or unavailable"):
        NAMESPACE["_load_trusted_key"](
            _darwin_logical_var_path(user_alias / key.name),
            expected_key_id=TEST_ONLY_SIGNER_KEY_ID,
            source_root=_darwin_logical_var_path(source),
            executed_at=datetime.strptime(EXECUTED_AT, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC),
            verification_time=datetime.strptime(VERIFICATION_TIME, "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=UTC
            ),
        )


@pytest.mark.parametrize("mutation", ("blocked", "revoked", "wrong_hash"))
def test_release_control_policy_rejects_untrusted_signer_state(
    tmp_path: Path,
    mutation: str,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    key, _private = _trusted_key(tmp_path / "trust")
    policy_path = ASSEMBLE.__globals__["RELEASE_TRUST_POLICY_PATH"]
    policy = json.loads(policy_path.read_text())
    if mutation == "blocked":
        policy["status"] = "blocked"
    elif mutation == "revoked":
        policy["keys"][0]["revoked"] = True
    else:
        policy["keys"][0]["public_key_sha256"] = "f" * 64
    policy_path.chmod(0o600)
    _write_canonical(policy_path, policy)
    ASSEMBLE.__globals__["RELEASE_CONTROL_TRUST_POLICY_SHA256"] = hashlib.sha256(
        policy_path.read_bytes()
    ).hexdigest()
    with pytest.raises(ERROR, match="trust policy|active RC signer|release policy"):
        NAMESPACE["_load_trusted_key"](
            key,
            expected_key_id=TEST_ONLY_SIGNER_KEY_ID,
            source_root=source,
            executed_at=datetime.strptime(EXECUTED_AT, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC),
            verification_time=datetime.strptime(VERIFICATION_TIME, "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=UTC
            ),
        )


def test_release_control_bootstrap_pending_blocks_rc_signer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    key, _private = _trusted_key(tmp_path / "trust")
    monkeypatch.setitem(
        ASSEMBLE.__globals__,
        "RELEASE_CONTROL_TRUST_POLICY_SHA256",
        None,
    )
    with pytest.raises(ERROR, match="bootstrap-pending"):
        NAMESPACE["_load_trusted_key"](
            key,
            expected_key_id=TEST_ONLY_SIGNER_KEY_ID,
            source_root=source,
            executed_at=datetime.strptime(EXECUTED_AT, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC),
            verification_time=datetime.strptime(VERIFICATION_TIME, "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=UTC
            ),
        )


@pytest.mark.parametrize(
    "relative",
    (
        "six-file-archive/valuation-result.json",
        "publication/report/report.pdf",
        "futu-private-evidence.json",
        "owner-equity-phase-receipts.json",
    ),
)
def test_private_evidence_deletion_fails_closed(
    tmp_path: Path,
    real_evidence: Path,
    relative: str,
) -> None:
    copied = tmp_path / "private-evidence"
    shutil.copytree(real_evidence, copied, copy_function=shutil.copy2)
    target = copied / relative
    target.parent.chmod(0o700)
    target.chmod(0o600)
    target.unlink()
    with pytest.raises(ERROR, match="strict reload|member set|failed"):
        NAMESPACE["_load_private_canary_evidence"](
            copied,
            executed_at=datetime.strptime(EXECUTED_AT, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC),
        )


def test_private_evidence_capture_resolves_temporary_directory_alias(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "minimal-private-evidence"
    source.mkdir(mode=0o700)
    for name in NAMESPACE["PRIVATE_EVIDENCE_FILES"]:
        member = source / name
        member.write_bytes(b"{}\n")
        member.chmod(0o444)
    for name in NAMESPACE["PRIVATE_EVIDENCE_DIRECTORIES"]:
        member = source / name
        member.mkdir(mode=0o700)
        member.chmod(0o555)
    source.chmod(0o555)

    physical_temp = tmp_path / "physical-temp"
    physical_temp.mkdir(mode=0o700)
    logical_temp = tmp_path / "logical-temp"
    logical_temp.symlink_to(physical_temp, target_is_directory=True)
    monkeypatch.setattr(NAMESPACE["tempfile"], "tempdir", str(logical_temp))

    snapshot = None
    with NAMESPACE["_captured_private_evidence"](source) as capture:
        snapshot = capture["snapshot_root"]
        assert snapshot == snapshot.resolve(strict=True)
        assert snapshot.is_relative_to(physical_temp.resolve(strict=True))
        assert all(not ancestor.is_symlink() for ancestor in (snapshot, *snapshot.parents))
    assert snapshot is not None and not snapshot.exists()


def test_peer_security_rebind_fails_typed_futu_replay(
    tmp_path: Path,
    real_evidence: Path,
) -> None:
    copied = tmp_path / "private-evidence"
    shutil.copytree(real_evidence, copied, copy_function=shutil.copy2)
    path = copied / "futu-private-evidence.json"
    value = json.loads(path.read_text())
    value["executions"][2]["security_identity"] = value["executions"][0]["security_identity"]
    path.chmod(0o600)
    _write_canonical(path, value)
    with pytest.raises(ERROR, match="execution|coordinated"):
        NAMESPACE["_load_private_canary_evidence"](
            copied,
            executed_at=datetime.strptime(EXECUTED_AT, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC),
        )


def test_market_provider_authority_cannot_be_replaced_by_free_hash(
    tmp_path: Path,
    real_evidence: Path,
) -> None:
    copied = tmp_path / "private-evidence"
    shutil.copytree(real_evidence, copied, copy_function=shutil.copy2)
    path = copied / "owner-equity-typed-authorities.json"
    value = json.loads(path.read_text())
    value["market_provider"]["market_execution_evidence_fingerprint"] = "f" * 64
    path.chmod(0o600)
    _write_canonical(path, value)
    with pytest.raises(ERROR, match="typed market/provider authorities were rebound"):
        NAMESPACE["_load_private_canary_evidence"](
            copied,
            executed_at=datetime.strptime(EXECUTED_AT, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC),
        )


def test_five_valuation_input_hashes_must_replay_typed_context(
    tmp_path: Path,
    real_evidence: Path,
) -> None:
    copied = tmp_path / "private-evidence"
    shutil.copytree(real_evidence, copied, copy_function=shutil.copy2)
    path = copied / "valuation-run-input-receipt.json"
    value = json.loads(path.read_text())
    for index, field in enumerate(
        (
            "graph_fingerprint",
            "research_bundle_set_sha256",
            "run_manifest_set_sha256",
            "candidate_compilation_fingerprint",
            "clock_fingerprint",
        ),
        1,
    ):
        value[field] = f"{index:x}" * 64
    identity = dict(value)
    identity.pop("receipt_id")
    value["receipt_id"] = (
        f"valuation-run-input-receipt:{value['issuer_id']}:"
        f"{NAMESPACE['_projection_sha256'](identity)[:24]}"
    )
    path.chmod(0o600)
    _write_canonical(path, value)
    with pytest.raises(ERROR, match="free or rebound hash|typed input authority"):
        NAMESPACE["_load_private_canary_evidence"](
            copied,
            executed_at=datetime.strptime(EXECUTED_AT, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC),
        )


def test_missing_one_required_financial_statement_request_fails_closed(
    tmp_path: Path,
    real_evidence: Path,
) -> None:
    copied = tmp_path / "private-evidence"
    shutil.copytree(real_evidence, copied, copy_function=shutil.copy2)
    path = copied / "futu-private-evidence.json"
    value = json.loads(path.read_text())
    target = next(
        execution
        for execution in value["executions"]
        if execution["bundle"]["stage"] == "valuation_pre_price_verification"
    )
    removed = next(
        request
        for request in target["requests"]
        if request["protocol_id"] == 3227 and request["parameters"]["statement_type"] == 3
    )
    target["requests"].remove(removed)
    path.chmod(0o600)
    _write_canonical(path, value)
    with pytest.raises(ERROR, match="execution|request plan|finalization"):
        NAMESPACE["_load_private_canary_evidence"](
            copied,
            executed_at=datetime.strptime(EXECUTED_AT, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC),
        )


def test_signed_insufficient_3104_quota_is_rejected() -> None:
    from owner_research.fingerprints import FrozenMap, canonical_sha256, to_json_value
    from owner_research.futu_receipts import (
        FUTU_SCHEMA_VERSION,
        FutuHistoricalKlineQuotaReceipt,
        build_futu_runtime_request_plan_item,
        content_identity,
    )

    codes = tuple(f"US.P{index:02d}" for index in range(1, 7))
    daily = FrozenMap(
        {
            "autype": "NONE",
            "end": "2026-06-30",
            "extended_time": False,
            "fields": ["CLOSE", "VOLUME"],
            "ktype": "K_DAY",
            "max_count": 1,
            "session": "RTH",
            "start": "2026-06-30",
        }
    )
    plan = (
        build_futu_runtime_request_plan_item(
            plan_index=0,
            security_code=codes[0],
            protocol_id=3104,
            parameters=FrozenMap({"get_detail": True}),
            maximum_pages=1,
        ),
        *(
            build_futu_runtime_request_plan_item(
                plan_index=index,
                security_code=code,
                protocol_id=3103,
                parameters=daily,
                maximum_pages=1,
            )
            for index, code in enumerate(codes, 1)
        ),
    )
    values = {
        "schema_version": FUTU_SCHEMA_VERSION,
        "run_id": "run:test-only-release-quota",
        "account_scope_sha256": "a" * 64,
        "runtime_authorization_fingerprint": "b" * 64,
        "runtime_request_plan": plan,
        "request_plan_fingerprint": canonical_sha256(to_json_value(plan)),
        "protocol_id": 3104,
        "observed_at": "2026-07-14T00:55:01Z",
        "quota_kind": "historical_candlestick_distinct_security_7d",
        "quota_window_days": 7,
        "used_quota": 0,
        "remaining_quota": 5,
        "detail_records": (),
        "planned_history_security_codes": codes,
        "already_counted_security_codes": (),
        "required_incremental_security_count": 6,
        "sufficient": False,
        "source_request_fingerprint": "c" * 64,
        "source_response_fingerprint": "d" * 64,
    }
    receipt_id, receipt_fingerprint = content_identity(
        "futu-history-quota:",
        values,
        object_id_field="receipt_id",
        fingerprint_field="receipt_fingerprint",
    )
    receipt = FutuHistoricalKlineQuotaReceipt(
        receipt_id=receipt_id,
        receipt_fingerprint=receipt_fingerprint,
        **values,
    )
    with pytest.raises(ERROR, match="3104 quota authority is missing, insufficient"):
        NAMESPACE["_require_sufficient_history_quota"](receipt)


def _unmapped_balance_observation_pair() -> tuple[SimpleNamespace, SimpleNamespace]:
    from owner_research.fingerprints import FrozenMap

    field_id = "9999"
    display_name = "unmapped vendor balance field"
    response_fingerprint = "e" * 64
    observation = SimpleNamespace(
        canonical_concept=None,
        comparison_eligible=False,
        currency="USD",
        data_family="financial_statements",
        field_id=field_id,
        point_in_time_status="current_snapshot",
        period=FrozenMap({"start": None, "end": "2025-12-31"}),
        qualifiers=FrozenMap(
            {
                "accounting_standard": "US_GAAP",
                "auditor_report": "unqualified",
                "financial_period_start_derivation": "not_applicable",
                "financial_period_status": "instant",
                "financial_type": 7,
                "fiscal_year": 2025,
                "futu_api_version": "10.10.7008",
                "normalized_financial_field_display_name": display_name,
                "period_kind": "stock",
                "statement_type": "balance_sheet",
                "vendor_period": "FY",
            }
        ),
        response_fingerprint=response_fingerprint,
        source_role="vendor_secondary",
        unit="currency_millions",
        value="1",
        value_type="number",
    )
    descriptor = SimpleNamespace(
        canonical_concept=None,
        comparison_eligible=False,
        currency=None,
        data_family="financial_statements",
        field_id=f"financial_structure:{field_id}",
        period=FrozenMap({"start": None, "end": None}),
        qualifiers=FrozenMap(
            {
                "financial_field_id": field_id,
                "futu_api_version": "10.10.7008",
                "normalized_display_name": display_name,
                "statement_type": "balance_sheet",
            }
        ),
        response_fingerprint=response_fingerprint,
        unit=None,
        value="Unmapped Vendor Balance Field",
        value_type="text",
    )
    return observation, descriptor


def test_unmapped_noncritical_financial_observation_is_typed_not_comparable() -> None:
    observation, descriptor = _unmapped_balance_observation_pair()
    assert NAMESPACE["_futu_financial_value_is_admissible"](
        observation,
        None,
        descriptor,
        statement_name="balance_sheet",
        futu_api_version="10.10.7008",
    )


@pytest.mark.parametrize(
    ("canonical_concept", "comparison_eligible"),
    (("total_assets", False), ("total_assets", True)),
)
def test_unmapped_financial_observation_cannot_impersonate_critical_comparable(
    canonical_concept: str,
    comparison_eligible: bool,
) -> None:
    observation, descriptor = _unmapped_balance_observation_pair()
    rebound = SimpleNamespace(
        **{
            **vars(observation),
            "canonical_concept": canonical_concept,
            "comparison_eligible": comparison_eligible,
        }
    )
    assert not NAMESPACE["_futu_financial_value_is_admissible"](
        rebound,
        None,
        descriptor,
        statement_name="balance_sheet",
        futu_api_version="10.10.7008",
    )


def test_release_replay_uses_exact_sidecar_runtime_protocol_set() -> None:
    assert FUTU_CLOSED_RUNTIME_PROTOCOL_IDS[:3] == (1001, 1002, 1004)
    assert 3235 not in FUTU_CLOSED_RUNTIME_PROTOCOL_IDS
    assert set(FUTU_CLOSED_RUNTIME_PROTOCOL_IDS[3:]) == {
        3103,
        3104,
        3202,
        3227,
        3228,
        3229,
        3230,
        3232,
        3234,
        3236,
        3243,
        3244,
        3245,
        3246,
    }


def test_release_canary_rejects_requested_us_3235() -> None:
    requests = [
        SimpleNamespace(protocol_id=3104, parameters={"get_detail": True}),
        SimpleNamespace(protocol_id=3202, parameters={}),
        *(
            SimpleNamespace(
                protocol_id=3227,
                parameters={
                    "currency_code": "USD",
                    "financial_type": 7,
                    "num": 10,
                    "statement_type": statement_type,
                },
            )
            for statement_type in (1, 2, 3)
        ),
        SimpleNamespace(
            protocol_id=3228,
            parameters={"currency_code": "USD", "date": 0, "financial_type": 7},
        ),
        SimpleNamespace(protocol_id=3234, parameters={}),
        SimpleNamespace(protocol_id=3236, parameters={}),
        SimpleNamespace(protocol_id=3243, parameters={}),
    ]
    NAMESPACE["_require_closed_us_preprice_request_plan"](tuple(requests))
    requests.append(SimpleNamespace(protocol_id=3235, parameters={}))

    with pytest.raises(ERROR, match="pre-price request plan"):
        NAMESPACE["_require_closed_us_preprice_request_plan"](tuple(requests))


def test_weekend_cutoff_replays_latest_completed_market_session() -> None:
    from datetime import date

    from owner_research.fingerprints import canonical_sha256
    from owner_research.valuation_market_authority import load_market_access_authority
    from owner_research.valuation_market_calendar import select_latest_completed_session
    from owner_research.valuation_market_provider import MarketReferenceRequest

    cutoff = "2026-06-28"  # Sunday
    request_started_at = "2026-07-14T01:00:00Z"
    selection = select_latest_completed_session(
        load_market_access_authority(ROOT / "component-lock.json"),
        mic="XNYS",
        cutoff_date=date.fromisoformat(cutoff),
        observed_at=datetime.fromisoformat(request_started_at.replace("Z", "+00:00")),
    )
    assert selection.session.trading_date == "2026-06-26"
    values = {
        "authorization_handoff_id": "handoff:test-only-weekend",
        "authorization_handoff_fingerprint": "a" * 64,
        "authorization_transitioned_at": "2026-07-14T00:58:00Z",
        "price_blind_input_fingerprint": "b" * 64,
        "issuer_id": "issuer:acme",
        "data_cutoff_date": cutoff,
        "security_id": "security:ACME:XNYS:common",
        "ticker": "ACME",
        "mic": "XNYS",
        "share_class": "common",
        "quote_currency": "USD",
        "expected_trading_date": selection.session.trading_date,
        "request_started_at": request_started_at,
    }
    request = MarketReferenceRequest(
        **values,
        request_fingerprint=canonical_sha256(values),
    )
    replayed = NAMESPACE["_replay_market_calendar_selection"](
        selection.to_dict(),
        request=request,
        component_lock_path=ROOT / "component-lock.json",
    )
    assert replayed.session.trading_date == "2026-06-26"

    rebound_values = {**values, "expected_trading_date": cutoff}
    rebound = MarketReferenceRequest(
        **rebound_values,
        request_fingerprint=canonical_sha256(rebound_values),
    )
    with pytest.raises(ERROR, match="market calendar selection does not replay"):
        NAMESPACE["_replay_market_calendar_selection"](
            selection.to_dict(),
            request=rebound,
            component_lock_path=ROOT / "component-lock.json",
        )


@pytest.mark.parametrize("rebind_kind", ("account", "startup_global_state"))
def test_signed_startup_global_state_or_account_rebind_is_rejected(
    real_evidence: Path,
    rebind_kind: str,
) -> None:
    import test_phase5_v1_futu_data_plane as futu_data

    assert _REAL_FUTU_PRIVATE is not None
    private = _REAL_FUTU_PRIVATE

    def resign(prefix: str, value: dict[str, Any]) -> dict[str, Any]:
        unsigned = dict(value)
        for key in ("receipt_id", "signature_algorithm", "signer_key_id", "signature_hex"):
            unsigned.pop(key, None)
        payload = {
            **unsigned,
            "signature_algorithm": "ed25519",
            "signer_key_id": "test-key",
        }
        payload["receipt_id"] = futu_data.signed_receipt_identity(prefix, payload)
        payload["signature_hex"] = private.sign(
            futu_data.canonical_json(payload).encode("utf-8")
        ).hex()
        return payload

    payload = json.loads((real_evidence / "futu-private-evidence.json").read_text())
    if rebind_kind == "account":
        account = dict(payload["authority_set"]["account"])
        account["global_state_response_fingerprint"] = "f" * 64
        payload["authority_set"]["account"] = resign("futu-account:", account)
    else:
        runtime = dict(payload["authority_set"]["runtime"])
        runtime["checkpoints"] = [dict(item) for item in runtime["checkpoints"]]
        runtime["checkpoints"][0]["global_state_response_fingerprint"] = "f" * 64
        runtime = resign("futu-runtime:", runtime)
        payload["authority_set"]["runtime"] = runtime
        payload["attested_session_finalization"]["runtime_receipt"] = runtime

    with pytest.raises(ERROR, match="authority|finalization|replay"):
        NAMESPACE["_load_private_futu"](
            payload,
            keyring_file=real_evidence / "futu-keyring.json",
            executed_at=datetime.strptime(EXECUTED_AT, "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=UTC
            ),
        )


@pytest.mark.parametrize(
    "missing_kind",
    ("cash_flow", "company_profile", "meaningless_balance"),
)
def test_signed_completed_response_without_actual_observation_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    real_evidence: Path,
    missing_kind: str,
) -> None:
    import test_phase5_v1_futu_data_plane as futu_data

    import owner_research.futu_sidecar as futu_sidecar
    from owner_research.futu_receipts import (
        FutuAuthorityDecision,
        FutuDataRequestReceipt,
        FutuDataResponseReceipt,
        FutuEvidenceBundle,
        FutuHistoricalKlineQuotaReceipt,
        FutuObservation,
        content_identity,
        load_futu_authority_set,
        load_futu_signed_receipt,
    )

    assert _REAL_FUTU_PRIVATE is not None
    private = _REAL_FUTU_PRIVATE

    class RealVerifier:
        def verify(
            self,
            *,
            signer_key_id: str,
            payload: bytes,
            signature_hex: str,
        ) -> bool:
            if signer_key_id != "test-key":
                return False
            try:
                private.public_key().verify(bytes.fromhex(signature_hex), payload)
            except (TypeError, ValueError):
                return False
            return True

    def signed_payload(prefix: str, values: dict[str, Any]) -> dict[str, Any]:
        payload = {
            **values,
            "signature_algorithm": "ed25519",
            "signer_key_id": "test-key",
        }
        payload["receipt_id"] = futu_data.signed_receipt_identity(prefix, payload)
        payload["signature_hex"] = private.sign(futu_data.canonical_json(payload).encode()).hex()
        return payload

    monkeypatch.setattr(futu_data, "DeterministicVerifier", RealVerifier)
    monkeypatch.setattr(futu_data, "_signed_payload", signed_payload)
    monkeypatch.setattr(
        futu_data,
        "HASH_C",
        private.public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex(),
    )
    _install_test_only_financial_registry(monkeypatch)
    payload = json.loads((real_evidence / "futu-private-evidence.json").read_text())
    authority_set = load_futu_authority_set(payload["authority_set"])
    assert authority_set.runtime is not None
    assert authority_set.runtime_authorization is not None
    assert authority_set.supply_chain is not None
    executions = []
    target_index = -1
    for index, record in enumerate(payload["executions"]):
        decision = FutuAuthorityDecision(**record["authority_decision"])
        execution = futu_sidecar.FutuSidecarExecution(
            bundle=FutuEvidenceBundle(**record["bundle"]),
            requests=tuple(FutuDataRequestReceipt(**item) for item in record["requests"]),
            responses=tuple(FutuDataResponseReceipt(**item) for item in record["responses"]),
            observations=tuple(FutuObservation(**item) for item in record["observations"]),
            history_quota=(
                None
                if record["history_quota"] is None
                else FutuHistoricalKlineQuotaReceipt(**record["history_quota"])
            ),
        )
        if execution.bundle.stage == "valuation_pre_price_verification":
            target_index = index
            if missing_kind == "meaningless_balance":
                replaced_ids: set[str] = set()
                rebuilt = []
                for item in execution.observations:
                    if (
                        item.qualifiers.get("statement_type") != "balance_sheet"
                        or item.field_id.startswith("financial_structure:")
                    ):
                        rebuilt.append(item)
                        continue
                    replaced_ids.add(item.observation_id)
                    values = item.to_dict()
                    values.pop("observation_id")
                    values.pop("observation_fingerprint")
                    values.update(
                        {
                            "canonical_concept": None,
                            "comparison_eligible": False,
                            "field_id": f"9{item.field_id}",
                        }
                    )
                    qualifiers = dict(values["qualifiers"])
                    qualifiers["normalized_financial_field_display_name"] = (
                        "test-only unmapped meaningless balance field"
                    )
                    values["qualifiers"] = qualifiers
                    observation_id, observation_fingerprint = content_identity(
                        "futu-observation:",
                        values,
                        object_id_field="observation_id",
                        fingerprint_field="observation_fingerprint",
                    )
                    rebuilt.append(
                        FutuObservation(
                            observation_id=observation_id,
                            observation_fingerprint=observation_fingerprint,
                            **values,
                        )
                    )
                kept = tuple(rebuilt)
            else:
                kept = tuple(
                    item
                    for item in execution.observations
                    if not (
                        (
                            missing_kind == "cash_flow"
                            and item.qualifiers.get("statement_type") == "cash_flow"
                        )
                        or (
                            missing_kind == "company_profile"
                            and item.data_family == "company_profile"
                        )
                    )
                )
                replaced_ids = {
                    item.observation_id
                    for item in execution.observations
                    if item not in kept
                }
            payload["cross_checks"] = [
                item
                for item in payload["cross_checks"]
                if item["vendor_observation_id"] not in replaced_ids
            ]
            execution = futu_sidecar.FutuSidecarExecution(
                bundle=futu_sidecar._make_bundle(
                    authority=decision,
                    run_id=execution.bundle.run_id,
                    issuer_id=execution.bundle.issuer_id,
                    security_id=execution.bundle.security_id,
                    stage=execution.bundle.stage,
                    status=execution.bundle.status,
                    issues=execution.bundle.issues,
                    requests=execution.requests,
                    responses=execution.responses,
                    observations=kept,
                ),
                requests=execution.requests,
                responses=execution.responses,
                observations=kept,
                history_quota=execution.history_quota,
            )
        executions.append(execution)
    assert target_index >= 0
    finalization = futu_data.build_futu_attested_finalization_fixture(
        executions=tuple(executions),
        runtime_receipt=authority_set.runtime,
        supply_chain=authority_set.supply_chain,
        runtime_authorization=authority_set.runtime_authorization,
        verifier=RealVerifier(),
    )
    payload["executions"][target_index]["bundle"] = executions[target_index].bundle.to_dict()
    payload["executions"][target_index]["observations"] = [
        item.to_dict() for item in executions[target_index].observations
    ]
    payload["executions"][target_index]["history_quota"] = (
        None
        if executions[target_index].history_quota is None
        else executions[target_index].history_quota.to_dict()
    )
    payload["attested_session_finalization"] = finalization.to_dict()
    # Security identities remain the original signed receipts and are reconstructed below.
    for record in payload["executions"]:
        load_futu_signed_receipt(
            "futu-security-identity-receipt",
            record["security_identity"],
        )
    expected_error = (
        "financial statement lacks mapped, cross-checked actual data"
        if missing_kind == "cash_flow"
        else "company profile returned no bound actual data"
        if missing_kind == "company_profile"
        else "financial statement lacks mapped, cross-checked actual data"
    )
    with pytest.raises(ERROR, match=expected_error):
        NAMESPACE["_load_private_futu"](
            payload,
            keyring_file=real_evidence / "futu-keyring.json",
            executed_at=datetime.strptime(EXECUTED_AT, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC),
        )


def test_canary_executed_at_cannot_predate_published_futu_finalization(
    real_evidence: Path,
) -> None:
    with pytest.raises(ERROR, match="target, or PDF|chronology|authority"):
        NAMESPACE["_load_private_canary_evidence"](
            real_evidence,
            executed_at=datetime.strptime(
                "2026-07-14T01:08:31Z",
                "%Y-%m-%dT%H:%M:%SZ",
            ).replace(tzinfo=UTC),
        )


@pytest.mark.parametrize("rebind_kind", ("future", "conflict"))
def test_resigned_crosscheck_cannot_escape_chronology_or_hide_conflict(
    real_evidence: Path,
    rebind_kind: str,
) -> None:
    from owner_research.futu_receipts import content_identity

    payload = json.loads((real_evidence / "futu-private-evidence.json").read_text())
    cross_check = payload["cross_checks"][0]
    if rebind_kind == "future":
        cross_check["created_at"] = "2026-07-14T01:08:36Z"
    else:
        cross_check.update(
            {
                "result": "conflict",
                "status": "resolved",
                "resolution": "official_evidence_confirmed_vendor_rejected",
                "reviewer_id": "human:release-canary-reviewer",
            }
        )
    receipt_id, fingerprint = content_identity(
        "futu-crosscheck:",
        cross_check,
        object_id_field="receipt_id",
        fingerprint_field="receipt_fingerprint",
    )
    cross_check["receipt_id"] = receipt_id
    cross_check["receipt_fingerprint"] = fingerprint
    with pytest.raises(ERROR, match="cross-check is conflicting, rebound, or out of chronology"):
        NAMESPACE["_load_private_futu"](
            payload,
            keyring_file=real_evidence / "futu-keyring.json",
            executed_at=datetime.strptime(EXECUTED_AT, "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=UTC
            ),
        )


@pytest.mark.parametrize(
    ("state", "error"),
    ((False, "rebound the observed trading-server state"), ("false", "observed boolean")),
)
def test_resigned_session_gate_must_retain_actual_trading_server_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    real_evidence: Path,
    state: Any,
    error: str,
) -> None:
    kwargs = _case(tmp_path, monkeypatch, real_evidence)
    key, private = _trusted_key(tmp_path / "resigner")
    evidence = NAMESPACE["_load_private_canary_evidence"](
        real_evidence,
        executed_at=datetime.fromisoformat(EXECUTED_AT.replace("Z", "+00:00")),
    )
    assert evidence["session_trd_logined"] is True

    def mutate(gates: dict[str, Any]) -> None:
        gates["session"]["trd_logined"] = state

    kwargs["canary_receipt"] = _signed_receipt(
        tmp_path / "resigned-canary.json",
        private=private,
        commit=kwargs["expected_commit"],
        tree=kwargs["expected_tree"],
        artifacts=_artifact_records({role: kwargs[role] for role in ARTIFACT_ROLES}),
        evidence=evidence,
        mutate_gates=mutate,
    )
    kwargs["trusted_signer_key"] = key
    with pytest.raises(ERROR, match=error):
        ASSEMBLE(**kwargs)


def test_invocation_attestation_cannot_rebind_actual_output_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    real_evidence: Path,
) -> None:
    _stub_verifiers(monkeypatch)
    _install_test_only_financial_registry(monkeypatch)
    source, commit, tree = _source_repository(tmp_path)
    artifacts = _artifacts(tmp_path)
    key, private = _trusted_key(tmp_path)
    evidence = NAMESPACE["_load_private_canary_evidence"](
        real_evidence,
        executed_at=datetime.strptime(EXECUTED_AT, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC),
    )
    receipt = _signed_receipt(
        tmp_path / "canary.json",
        private=private,
        commit=commit,
        tree=tree,
        artifacts=_artifact_records(artifacts),
        evidence=evidence,
        output_root="f" * 64,
    )
    with pytest.raises(ERROR, match="strictly reloaded evidence root"):
        ASSEMBLE(
            mode="rc",
            source_root=source,
            expected_commit=commit,
            expected_tree=tree,
            output_directory=tmp_path / "release",
            assembled_at=VERIFICATION_TIME,
            canary_receipt=receipt,
            canary_evidence_bundle=real_evidence,
            trusted_signer_key=key,
            trusted_signer_key_id=TEST_ONLY_SIGNER_KEY_ID,
            verification_time=VERIFICATION_TIME,
            **artifacts,
        )


def test_resigned_outer_canary_cannot_rebind_sidecar_distribution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    real_evidence: Path,
) -> None:
    _stub_verifiers(monkeypatch)
    _install_test_only_financial_registry(monkeypatch)
    source, commit, tree = _source_repository(tmp_path)
    artifacts = _artifacts(tmp_path)
    key, private = _trusted_key(tmp_path)
    evidence = NAMESPACE["_load_private_canary_evidence"](
        real_evidence,
        executed_at=datetime.strptime(EXECUTED_AT, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC),
    )
    receipt_path = _signed_receipt(
        tmp_path / "canary.json",
        private=private,
        commit=commit,
        tree=tree,
        artifacts=_artifact_records(artifacts),
        evidence=evidence,
    )
    artifacts["sidecar_wheel"].write_bytes(b"replacement candidate sidecar wheel\n")
    changed_artifacts = _artifact_records(artifacts)
    receipt = json.loads(receipt_path.read_text())
    receipt["artifacts"] = changed_artifacts
    root = {
        "artifact_type": "owner-equity-rc-canary-root",
        "artifacts": changed_artifacts,
        "candidate_commit": commit,
        "candidate_tree": tree,
        "evidence_root_sha256": evidence["evidence_root_sha256"],
        "executed_at": EXECUTED_AT,
        "gate_receipt_sha256": {
            name: receipt["gates"][name]["receipt_sha256"] for name in NAMESPACE["GATE_NAMES"]
        },
        "invocation_attestation_fingerprint": receipt["invocation_attestation"][
            "invocation_attestation_fingerprint"
        ],
        "schema_version": "2.0.0",
    }
    receipt["canary_root_sha256"] = NAMESPACE["_projection_sha256"](root)
    receipt.pop("signature")
    receipt["signature"] = {
        "algorithm": "Ed25519",
        "key_id": TEST_ONLY_SIGNER_KEY_ID,
        "value_base64": base64.b64encode(private.sign(CANONICAL(receipt, newline=False))).decode(),
    }
    receipt_path.chmod(0o600)
    _write_canonical(receipt_path, receipt)
    with pytest.raises(ERROR, match="canary invocation"):
        ASSEMBLE(
            mode="rc",
            source_root=source,
            expected_commit=commit,
            expected_tree=tree,
            output_directory=tmp_path / "release",
            assembled_at=VERIFICATION_TIME,
            canary_receipt=receipt_path,
            canary_evidence_bundle=real_evidence,
            trusted_signer_key=key,
            trusted_signer_key_id=TEST_ONLY_SIGNER_KEY_ID,
            verification_time=VERIFICATION_TIME,
            **artifacts,
        )


def test_arbitrary_external_self_key_cannot_authorize_resigned_canary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    real_evidence: Path,
) -> None:
    kwargs = _case(tmp_path, monkeypatch, real_evidence)
    rogue_private = Ed25519PrivateKey.generate()
    rogue_public_hex = (
        rogue_private.public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex()
    )
    rogue_key = _write_canonical(
        tmp_path / "rogue-external-key.json",
        {
            "algorithm": "Ed25519",
            "artifact_type": "owner-equity-rc-canary-trusted-signer-key",
            "key_id": TEST_ONLY_SIGNER_KEY_ID,
            "not_after": "2026-07-15T00:00:00Z",
            "not_before": "2026-07-13T00:00:00Z",
            "public_key_hex": rogue_public_hex,
            "revoked": False,
            "schema_version": "1.0.0",
            "usages": ["owner_equity_rc_canary"],
        },
    )
    receipt_path = kwargs["canary_receipt"]
    receipt = json.loads(receipt_path.read_text())
    receipt.pop("signature")
    receipt["signature"] = {
        "algorithm": "Ed25519",
        "key_id": TEST_ONLY_SIGNER_KEY_ID,
        "value_base64": base64.b64encode(
            rogue_private.sign(CANONICAL(receipt, newline=False))
        ).decode(),
    }
    receipt_path.chmod(0o600)
    _write_canonical(receipt_path, receipt)
    kwargs["trusted_signer_key"] = rogue_key
    with pytest.raises(ERROR, match="absent from release policy"):
        ASSEMBLE(**kwargs)


def test_preview_requires_no_canary_and_never_publishes_sidecar(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_verifiers(monkeypatch)
    source, commit, tree = _source_repository(tmp_path)
    artifacts = _artifacts(tmp_path)
    output = ASSEMBLE(
        mode="preview",
        source_root=source,
        expected_commit=commit,
        expected_tree=tree,
        output_directory=tmp_path / "preview",
        assembled_at=VERIFICATION_TIME,
        **artifacts,
    )
    assert not any("futu_sidecar" in path.name for path in output.iterdir())
    manifest = json.loads((output / "release-manifest.json").read_text())
    assert {item["role"] for item in manifest["artifacts"] if "role" in item} == {
        *PUBLIC_ARTIFACT_ROLES,
        "public_sbom",
    }
    assert all("name" not in item for item in manifest["private_canary_inputs"])
    assert manifest["release_status"] == "code_complete_preview"
    assert manifest["rc_tag_permitted"] is False
    assert manifest["rc_blockers"] == [
        "release_control_root_not_deployed",
        "reviewed_futu_balance_cash_field_registry_not_deployed",
    ]


def test_rc_cannot_enable_without_reviewed_balance_and_cash_registry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_verifiers(monkeypatch)
    source, commit, tree = _source_repository(tmp_path)
    artifacts = _artifacts(tmp_path)
    key, _private = _trusted_key(tmp_path / "test-only-trust")
    with pytest.raises(
        ERROR,
        match="reviewed_futu_balance_cash_field_registry_not_deployed",
    ):
        ASSEMBLE(
            mode="rc",
            source_root=source,
            expected_commit=commit,
            expected_tree=tree,
            output_directory=tmp_path / "release",
            assembled_at=VERIFICATION_TIME,
            canary_receipt=key,
            canary_evidence_bundle=tmp_path,
            trusted_signer_key=key,
            trusted_signer_key_id=TEST_ONLY_SIGNER_KEY_ID,
            verification_time=VERIFICATION_TIME,
            **artifacts,
        )


def test_verifier_and_publication_consume_one_captured_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_verifiers(monkeypatch)
    source, commit, tree = _source_repository(tmp_path)
    artifacts = _artifacts(tmp_path)
    verified_bytes = artifacts["owner_wheel"].read_bytes()
    replacement = b"unverified replacement after verifier entry\n"

    def replace_original(snapshot: Path, **_kwargs: Any) -> tuple[()]:
        assert snapshot != artifacts["owner_wheel"]
        assert snapshot.read_bytes() == verified_bytes
        artifacts["owner_wheel"].write_bytes(replacement)
        return ()

    monkeypatch.setitem(ASSEMBLE.__globals__, "ROOT_WHEEL_VERIFY", replace_original)
    output = ASSEMBLE(
        mode="preview",
        source_root=source,
        expected_commit=commit,
        expected_tree=tree,
        output_directory=tmp_path / "preview",
        assembled_at=VERIFICATION_TIME,
        **artifacts,
    )
    assert artifacts["owner_wheel"].read_bytes() == replacement
    assert (output / artifacts["owner_wheel"].name).read_bytes() == verified_bytes


def test_rc_requires_closed_private_evidence_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_verifiers(monkeypatch)
    _install_test_only_financial_registry(monkeypatch)
    source, commit, tree = _source_repository(tmp_path)
    artifacts = _artifacts(tmp_path)
    with pytest.raises(ERROR, match="RC mode requires"):
        ASSEMBLE(
            mode="rc",
            source_root=source,
            expected_commit=commit,
            expected_tree=tree,
            output_directory=tmp_path / "release",
            assembled_at=VERIFICATION_TIME,
            **artifacts,
        )
