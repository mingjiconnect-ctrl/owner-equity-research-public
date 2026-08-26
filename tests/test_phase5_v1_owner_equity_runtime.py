from __future__ import annotations

import json
import os
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from phase4e2_support import complete_phase4e_graph
from phase5_v1_scope_support import formal_scope_graph, typed_research_inputs_for_graph
from test_phase4e1_research_bundle_builder import _input_graph
from test_phase5_v1_report_publisher import DeterministicRenderer, _typed_report_inputs
from test_phase5_v1_run_context import _context_inputs

from owner_research import cli as validate_cli
from owner_research import owner_equity_research as research_module
from owner_research import owner_equity_runtime as runtime_module
from owner_research import research_report as report_module
from owner_research.fingerprints import canonical_json, canonical_sha256
from owner_research.owner_equity_research import (
    MarketExpectationsInput,
    MarketReferenceInput,
    NonPriceVerificationInput,
    OwnerEquityResearchError,
    OwnerEquityResearchRequest,
    PhaseStatus,
    PublicationProfile,
    ResearchIntent,
    SynthesisInput,
    run_owner_equity_research,
)
from owner_research.owner_equity_runtime import (
    Ed25519PublicKeyring,
    OwnerEquityRuntimeError,
    build_runtime_dependencies,
    load_owner_equity_runtime,
    write_research_runtime_context,
)
from owner_research.research_publisher import (
    load_owner_research_package as load_package_allowing_test_renderer,
)
from owner_research.research_publisher import (
    publish_owner_research as publish_package_allowing_test_renderer,
)
from owner_research.research_publisher import (
    republish_owner_research_package as republish_package_allowing_test_renderer,
)
from owner_research.valuation_market_execution_policies import (
    PINNED_KERNEL_WHEEL_SHA256,
)
from owner_research.valuation_run_context import (
    VALUATION_RUN_INPUT_FILENAME,
    write_valuation_run_input_context,
)
from owner_research.workflow_cli import main


def _write_canonical(path: Path, payload: dict[str, object], *, mode: int = 0o600) -> Path:
    path.write_bytes((canonical_json(payload) + "\n").encode("utf-8"))
    path.chmod(mode)
    return path


def _runtime_fixture(sample_payloads, monkeypatch, tmp_path: Path):
    graph, freeze, price_blind, security, bundle_directory, clock = _context_inputs(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    run_input = price_blind.parent / VALUATION_RUN_INPUT_FILENAME
    write_valuation_run_input_context(
        graph=graph,
        bundle_artifact_directory=bundle_directory,
        expected_freeze=freeze,
        security_proposal=security.proposal,
        assumption_proposals=(),
        assumption_reviews=(),
        clock=clock,
        output_file=run_input,
    )
    research_graph = write_research_runtime_context(
        graph=graph,
        output_file=tmp_path / "research-graph-context.json",
    )
    research = {
        "research_graph_file": str(research_graph),
        "research_bundle_directory": str(bundle_directory),
    }
    return graph, research, run_input, price_blind


def _missing_valuation(run_input: Path, price_blind: Path) -> dict[str, object]:
    fields = (
        "keyring_file",
        "legal_receipt_file",
        "account_receipt_file",
        "supply_chain_receipt_file",
        "runtime_authorization_file",
        "runtime_receipt_file",
        "security_identity_receipt_file",
        "sidecar_socket",
        "sidecar_expected_uid",
        "sidecar_timeout_seconds",
        "sidecar_signer_key_id",
        "kernel_wheel",
        "kernel_repository",
        "kernel_runtime_manifest",
        "kernel_cas_root",
        "valuation_output_directory",
        "stage_plan_file",
        "futu_data_review_file",
        "peer_review_file",
        "synthesis_review_file",
        "score_review_file",
        "run_input_file",
        "price_blind_artifact_directory",
    )
    values: dict[str, object] = {name: None for name in fields}
    values["run_input_file"] = str(run_input)
    values["price_blind_artifact_directory"] = str(price_blind)
    return values


def _config(
    research: dict[str, object] | None,
    *,
    report: dict[str, object] | None = None,
    publication: dict[str, object] | None = None,
    audit: dict[str, object] | None = None,
    valuation: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "artifact_type": "owner-equity-runtime-config",
        "research": research,
        "report": report,
        "publication": publication,
        "audit": audit,
        "valuation": valuation,
    }


def _request_args(graph, runtime_config: Path, command: str) -> list[str]:
    bundle = graph.research_bundles[0]
    return [
        command,
        "--runtime-config",
        str(runtime_config),
        "--issuer-id",
        bundle.issuer_id,
        "--data-cutoff-date",
        bundle.data_cutoff_date,
        "--requested-by",
        "human:runtime-reviewer",
        "--requested-at",
        "2026-08-15T09:00:00+08:00",
    ]


def _guard_test_dependencies(sample_payloads, monkeypatch, tmp_path: Path):
    graph = formal_scope_graph(sample_payloads)
    research_input, source_index = typed_research_inputs_for_graph(
        graph,
        tmp_path / "guard-research-input",
    )
    graph = source_index.graph
    graph_file = write_research_runtime_context(
        graph=graph,
        output_file=tmp_path / "guard-research-graph.json",
    )
    config_file = _write_canonical(
        tmp_path / "guard-runtime.json",
        _config(
            {
                "research_graph_file": str(graph_file),
                "research_bundle_directory": str(research_input.source_directory),
            }
        ),
    )
    runtime = load_owner_equity_runtime(
        config_file,
        intent=ResearchIntent.RESEARCH,
        profile=None,
    )
    runtime = replace(
        runtime,
        intent=ResearchIntent.VALUATION,
        profile=PublicationProfile.FULL_VALUATION,
    )
    return graph, build_runtime_dependencies(runtime)


def _incomplete_research_graph(sample_payloads, status: str):
    if status == "blocked":
        return _input_graph(sample_payloads)
    graph = complete_phase4e_graph(sample_payloads)
    newer_source = replace(
        graph.documents[0],
        document_id="doc:acme:2026-q1-10q-publication-outcome",
        document_type="10-Q",
        period={"start": "2026-01-01", "end": "2026-03-31"},
        published_date="2026-04-30",
        source_url="https://www.sec.gov/Archives/acme-2026-q1-publication-outcome",
        content_sha256="9" * 64,
    )
    manifest = replace(
        graph.manifests[0],
        input_document_hashes={
            **dict(graph.manifests[0].input_document_hashes),
            newer_source.document_id: newer_source.content_sha256,
        },
    )
    return replace(
        graph,
        documents=(*graph.documents, newer_source),
        manifests=(manifest,),
    )


def test_ed25519_keyring_verifies_only_exact_named_public_key(tmp_path: Path) -> None:
    private = Ed25519PrivateKey.generate()
    public_hex = (
        private.public_key()
        .public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        .hex()
    )
    identity = {
        "keyring_id": "keyring:runtime-test",
        "algorithm": "ed25519",
        "keys": {"legal-review-key": public_hex},
    }
    payload = {
        "schema_version": "1.0.0",
        "artifact_type": "owner-research-public-keyring",
        "keyring_id": identity["keyring_id"],
        "algorithm": "ed25519",
        "keys": [
            {"key_id": "legal-review-key", "public_key_hex": public_hex},
        ],
        "keyring_fingerprint": canonical_sha256(identity),
    }
    keyring = Ed25519PublicKeyring.from_file(_write_canonical(tmp_path / "keyring.json", payload))
    message = b"exact signed receipt payload"
    signature = private.sign(message).hex()

    assert keyring.verify(
        signer_key_id="legal-review-key",
        payload=message,
        signature_hex=signature,
    )
    assert not keyring.verify(
        signer_key_id="unknown-key",
        payload=message,
        signature_hex=signature,
    )
    assert not keyring.verify(
        signer_key_id="legal-review-key",
        payload=message + b"tampered",
        signature_hex=signature,
    )


def test_live_pre_price_plan_requests_all_three_primary_financial_statements() -> None:
    specs = runtime_module._pre_price_specs("XNAS")
    assert [item.protocol_id for item in specs] == [
        3104,
        3202,
        3227,
        3227,
        3227,
        3228,
        3234,
        3236,
        3243,
    ]
    assert specs[0].stage == "runtime_authority"
    assert specs[0].parameters == {"get_detail": True}
    financials = tuple(item for item in specs if item.protocol_id == 3227)
    assert [item.parameters["statement_type"] for item in financials] == [1, 2, 3]
    assert all(
        item.parameters
        == {
            "statement_type": statement_type,
            "financial_type": 7,
            "currency_code": "USD",
            "num": 10,
        }
        for statement_type, item in zip((1, 2, 3), financials, strict=True)
    )
    assert all(
        runtime_module._REQUEST_PAGE_CAPS[str(item.protocol_id)] == 10
        for item in financials
    )


def test_keyring_rejects_writable_authority_file(tmp_path: Path) -> None:
    path = tmp_path / "keyring.json"
    path.write_text("{}\n", encoding="utf-8")
    os.chmod(path, 0o666)

    with pytest.raises(OwnerEquityRuntimeError, match="protected"):
        Ed25519PublicKeyring.from_file(path)


def test_real_cli_research_strictly_reloads_and_makes_zero_futu_calls(
    sample_payloads,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys,
) -> None:
    fixture_directory = tmp_path / "complete-research-fixture"
    fixture_directory.mkdir()
    research_input, source_index, _, _ = _typed_report_inputs(
        sample_payloads,
        fixture_directory,
    )
    graph = source_index.graph
    graph_file = write_research_runtime_context(
        graph=graph,
        output_file=tmp_path / "complete-research-graph.json",
    )
    research = {
        "research_graph_file": str(graph_file),
        "research_bundle_directory": str(research_input.source_directory),
    }
    config_file = _write_canonical(tmp_path / "research-runtime.json", _config(research))
    transport_constructed = False

    def forbidden_transport(*args, **kwargs):
        nonlocal transport_constructed
        transport_constructed = True
        raise AssertionError("price-blind research constructed the Futu transport")

    monkeypatch.setattr(
        "owner_research.futu_sidecar.UnixSocketFutuSidecarTransport.__post_init__",
        forbidden_transport,
    )

    exit_code = main(_request_args(graph, config_file, "research"))
    output = json.loads(capsys.readouterr().out)

    assert exit_code == 6
    assert output["status"] == "partial"
    assert output["issue_codes"] == [
        "official_research_partial:security_scope_unresolved"
    ]
    assert output["phases"] == [
        {"phase": "official_research_freeze", "sequence": 1, "status": "partial"}
    ]
    assert transport_constructed is False


def test_real_cli_valuation_with_incomplete_official_research_stops_before_futu(
    sample_payloads,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys,
) -> None:
    graph, research, run_input, price_blind = _runtime_fixture(
        sample_payloads, monkeypatch, tmp_path
    )
    report_spec = dict(sample_payloads["report-spec"])
    report_spec["output_formats"] = ["latex_pdf"]
    report_file = _write_canonical(tmp_path / "report-spec.json", report_spec)
    config_file = _write_canonical(
        tmp_path / "valuation-runtime.json",
        _config(
            research,
            report={"report_spec_file": str(report_file)},
            publication={"output_directory": str(tmp_path / "published-valuation")},
            valuation=_missing_valuation(run_input, price_blind),
        ),
    )
    transport_constructed = False

    def forbidden_transport(*args, **kwargs):
        nonlocal transport_constructed
        transport_constructed = True
        raise AssertionError("missing authority constructed the Futu transport")

    monkeypatch.setattr(
        "owner_research.futu_sidecar.UnixSocketFutuSidecarTransport.__post_init__",
        forbidden_transport,
    )

    exit_code = main(_request_args(graph, config_file, "valuation"))
    output = json.loads(capsys.readouterr().out)

    assert exit_code == 5
    assert output["status"] == "blocked"
    assert output["phases"] == [{
        "phase": "official_research_freeze",
        "sequence": 1,
        "status": "blocked",
    }]
    assert "official_research_blocked:bundle_status" in output["issue_codes"]
    assert transport_constructed is False


def test_runtime_dependencies_cannot_be_reused_for_another_request_route(
    sample_payloads,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    graph, research, run_input, price_blind = _runtime_fixture(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    report_spec = dict(sample_payloads["report-spec"])
    report_spec["output_formats"] = ["latex_pdf"]
    report_file = _write_canonical(tmp_path / "route-report-spec.json", report_spec)
    config_file = _write_canonical(
        tmp_path / "route-bound-runtime.json",
        _config(
            research,
            report={"report_spec_file": str(report_file)},
            publication={"output_directory": str(tmp_path / "route-publication")},
            valuation=_missing_valuation(run_input, price_blind),
        ),
    )
    runtime = load_owner_equity_runtime(
        config_file,
        intent=ResearchIntent.VALUATION,
        profile=PublicationProfile.FULL_VALUATION,
    )
    bundle = graph.research_bundles[0]
    research_request = OwnerEquityResearchRequest(
        issuer_id=bundle.issuer_id,
        data_cutoff_date=bundle.data_cutoff_date,
        intent=ResearchIntent.RESEARCH,
        profile=None,
        requested_by="human:route-binding-reviewer",
        requested_at="2026-08-15T09:00:00+08:00",
    )

    with pytest.raises(OwnerEquityResearchError, match="dependency route differs"):
        run_owner_equity_research(
            request=research_request,
            dependencies=build_runtime_dependencies(runtime),
        )


def test_direct_futu_phase_adapters_reject_nonvaluation_intent_before_live_calls(
    sample_payloads,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    graph, dependencies = _guard_test_dependencies(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    bundle = graph.research_bundles[0]
    request = OwnerEquityResearchRequest(
        issuer_id=bundle.issuer_id,
        data_cutoff_date=bundle.data_cutoff_date,
        intent=ResearchIntent.RESEARCH,
        profile=None,
        requested_by="human:direct-futu-route-reviewer",
        requested_at="2026-08-15T09:00:00+08:00",
    )
    live_calls: list[str] = []

    def forbidden_live_call(*_args, **_kwargs):
        live_calls.append("called")
        raise AssertionError("a route guard allowed a direct live Futu call")

    monkeypatch.setattr(runtime_module._LiveRuntimeState, "run_pre_price", forbidden_live_call)
    monkeypatch.setattr(
        runtime_module._LiveRuntimeState,
        "run_market_reference",
        forbidden_live_call,
    )
    monkeypatch.setattr(
        runtime_module._LiveRuntimeState,
        "run_market_expectations",
        forbidden_live_call,
    )
    monkeypatch.setattr(
        runtime_module._LiveRuntimeState,
        "run_synthesis",
        forbidden_live_call,
    )
    with pytest.raises(OwnerEquityRuntimeError, match="exact typed phase input"):
        dependencies.synthesize(object())
    with pytest.raises(OwnerEquityRuntimeError, match="exact typed request"):
        dependencies.synthesize(
            SynthesisInput(
                request=object(),
                price_blind=None,
                market_reference=None,
                kernel=None,
            )
        )
    direct_calls = (
        lambda: dependencies.futu_nonprice(
            NonPriceVerificationInput(request=request, official_research=None)
        ),
        lambda: dependencies.futu_market_reference(
            MarketReferenceInput(
                request=request,
                price_blind=None,
                futu_nonprice=None,
            )
        ),
        lambda: dependencies.futu_market_expectations(
            MarketExpectationsInput(
                request=request,
                price_blind=None,
                market_reference=None,
                synthesis=None,
                score=None,
            )
        ),
        lambda: dependencies.synthesize(
            SynthesisInput(
                request=request,
                price_blind=None,
                market_reference=None,
                kernel=None,
            )
        ),
    )

    for direct_call in direct_calls:
        with pytest.raises(OwnerEquityRuntimeError, match="full_valuation route"):
            direct_call()
    assert live_calls == []


def test_direct_futu_phase_adapters_reject_missing_predecessors_before_live_calls(
    sample_payloads,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    graph, dependencies = _guard_test_dependencies(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    bundle = graph.research_bundles[0]
    request = OwnerEquityResearchRequest(
        issuer_id=bundle.issuer_id,
        data_cutoff_date=bundle.data_cutoff_date,
        intent=ResearchIntent.VALUATION,
        profile=PublicationProfile.FULL_VALUATION,
        requested_by="human:direct-futu-sequence-reviewer",
        requested_at="2026-08-15T09:00:00+08:00",
    )
    live_calls: list[str] = []

    def forbidden_live_call(*_args, **_kwargs):
        live_calls.append("called")
        raise AssertionError("a predecessor guard allowed a direct live Futu call")

    monkeypatch.setattr(runtime_module._LiveRuntimeState, "run_pre_price", forbidden_live_call)
    monkeypatch.setattr(
        runtime_module._LiveRuntimeState,
        "run_market_reference",
        forbidden_live_call,
    )
    monkeypatch.setattr(
        runtime_module._LiveRuntimeState,
        "run_market_expectations",
        forbidden_live_call,
    )
    monkeypatch.setattr(
        runtime_module._LiveRuntimeState,
        "run_synthesis",
        forbidden_live_call,
    )

    with pytest.raises(OwnerEquityRuntimeError, match="exact admitted predecessor"):
        dependencies.futu_nonprice(
            NonPriceVerificationInput(request=request, official_research=None)
        )
    with pytest.raises(OwnerEquityRuntimeError, match="preceded the bound Futu nonprice phase"):
        dependencies.futu_market_reference(
            MarketReferenceInput(
                request=request,
                price_blind=None,
                futu_nonprice=None,
            )
        )
    with pytest.raises(OwnerEquityRuntimeError, match="preceded the bound Futu nonprice phase"):
        dependencies.futu_market_expectations(
            MarketExpectationsInput(
                request=request,
                price_blind=None,
                market_reference=None,
                synthesis=None,
                score=None,
            )
        )
    with pytest.raises(OwnerEquityRuntimeError, match="preceded the bound Futu nonprice phase"):
        dependencies.synthesize(
            SynthesisInput(
                request=request,
                price_blind=None,
                market_reference=None,
                kernel=None,
            )
        )
    assert live_calls == []


def test_direct_futu_phases_cannot_rebind_a_live_session_request(
    sample_payloads,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    graph, dependencies = _guard_test_dependencies(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    bundle = graph.research_bundles[0]
    request = OwnerEquityResearchRequest(
        issuer_id=bundle.issuer_id,
        data_cutoff_date=bundle.data_cutoff_date,
        intent=ResearchIntent.VALUATION,
        profile=PublicationProfile.FULL_VALUATION,
        requested_by="human:bound-futu-request-reviewer",
        requested_at="2026-08-15T09:00:00+08:00",
    )
    official = dependencies.official_research(request)
    assert official.status is PhaseStatus.COMPLETED
    first = dependencies.futu_nonprice(
        NonPriceVerificationInput(
            request=request,
            official_research=official,
        )
    )
    assert first.status is PhaseStatus.BLOCKED

    rebound = replace(
        request,
        requested_by="human:rebound-futu-request-reviewer",
    )
    with pytest.raises(OwnerEquityRuntimeError, match="another request"):
        dependencies.futu_market_reference(
            MarketReferenceInput(
                request=rebound,
                price_blind=None,
                futu_nonprice=None,
            )
        )
    with pytest.raises(OwnerEquityRuntimeError, match="another request"):
        dependencies.synthesize(
            SynthesisInput(
                request=rebound,
                price_blind=None,
                market_reference=None,
                kernel=None,
            )
        )

    clone = replace(request)
    assert clone == request
    assert clone is not request
    clone_official = dependencies.official_research(clone)
    clone_live_calls: list[str] = []

    def forbidden_clone_live_call(*_args, **_kwargs):
        clone_live_calls.append("called")
        raise AssertionError("an equal-value request clone entered live Futu")

    monkeypatch.setattr(
        runtime_module._LiveRuntimeState,
        "run_pre_price",
        forbidden_clone_live_call,
    )
    with pytest.raises(OwnerEquityRuntimeError, match="another request"):
        dependencies.futu_nonprice(
            NonPriceVerificationInput(
                request=clone,
                official_research=clone_official,
            )
        )
    with pytest.raises(OwnerEquityRuntimeError, match="another request"):
        dependencies.futu_market_reference(
            MarketReferenceInput(
                request=clone,
                price_blind=None,
                futu_nonprice=None,
            )
        )
    with pytest.raises(OwnerEquityRuntimeError, match="another request"):
        dependencies.synthesize(
            SynthesisInput(
                request=clone,
                price_blind=None,
                market_reference=None,
                kernel=None,
            )
        )
    with pytest.raises(OwnerEquityRuntimeError, match="another request"):
        dependencies.futu_market_expectations(
            MarketExpectationsInput(
                request=clone,
                price_blind=None,
                market_reference=None,
                synthesis=None,
                score=None,
            )
        )
    assert clone_live_calls == []


def test_full_runtime_checks_kernel_supply_before_opening_futu(
    sample_payloads,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    graph, research, run_input, price_blind = _runtime_fixture(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    report_spec = dict(sample_payloads["report-spec"])
    report_spec["output_formats"] = ["latex_pdf"]
    report_file = _write_canonical(tmp_path / "report-spec.json", report_spec)
    valuation = _missing_valuation(run_input, price_blind)
    cas_root = tmp_path / "kernel-cas"
    runtime_manifest = _write_canonical(
        tmp_path / "kernel-runtime-manifest.json",
        {"status": "fixture-only"},
    )
    for field in (
        "keyring_file",
        "legal_receipt_file",
        "account_receipt_file",
        "supply_chain_receipt_file",
        "runtime_authorization_file",
        "security_identity_receipt_file",
        "sidecar_socket",
        "kernel_repository",
        "stage_plan_file",
        "futu_data_review_file",
        "peer_review_file",
        "synthesis_review_file",
        "score_review_file",
    ):
        valuation[field] = str(tmp_path / field)
    valuation.update(
        {
            "sidecar_expected_uid": os.getuid(),
            "sidecar_timeout_seconds": 1,
            "sidecar_signer_key_id": "sidecar:fixture",
            "kernel_wheel": str(
                cas_root / "sha256" / PINNED_KERNEL_WHEEL_SHA256
            ),
            "kernel_runtime_manifest": str(runtime_manifest),
            "kernel_cas_root": str(cas_root),
            "valuation_output_directory": str(tmp_path / "valuation-output"),
        }
    )
    config_file = _write_canonical(
        tmp_path / "supply-preflight-runtime.json",
        _config(
            research,
            report={"report_spec_file": str(report_file)},
            publication={"output_directory": str(tmp_path / "published-valuation")},
            valuation=valuation,
        ),
    )
    runtime = load_owner_equity_runtime(
        config_file,
        intent=ResearchIntent.VALUATION,
        profile=PublicationProfile.FULL_VALUATION,
    )
    bundle = graph.research_bundles[0]
    request = OwnerEquityResearchRequest(
        issuer_id=bundle.issuer_id,
        data_cutoff_date=bundle.data_cutoff_date,
        intent=ResearchIntent.VALUATION,
        profile=PublicationProfile.FULL_VALUATION,
        requested_by="human:runtime-supply-reviewer",
        requested_at="2026-08-15T09:00:00+08:00",
    )
    transport_opened = False

    def forbidden_transport(*args, **kwargs):
        nonlocal transport_opened
        transport_opened = True
        raise AssertionError("Futu transport opened before kernel supply preflight")

    monkeypatch.setattr(
        runtime_module.AttestedFutuSidecarSession,
        "open",
        forbidden_transport,
    )
    state = runtime_module._LiveRuntimeState(runtime)
    with pytest.raises(runtime_module._LiveBlocked) as blocked:
        state.run_pre_price(request)

    assert blocked.value.issue_codes == ("runtime_supply_blocked:ValuationRunError",)
    assert transport_opened is False


def test_price_blind_runtime_rejects_dormant_valuation_capability(
    sample_payloads,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _, research, _, _ = _runtime_fixture(sample_payloads, monkeypatch, tmp_path)
    valuation = {
        name: None
        for name in (
            "keyring_file",
            "legal_receipt_file",
            "account_receipt_file",
            "supply_chain_receipt_file",
            "runtime_authorization_file",
            "runtime_receipt_file",
            "security_identity_receipt_file",
            "sidecar_socket",
            "sidecar_expected_uid",
            "sidecar_timeout_seconds",
            "sidecar_signer_key_id",
            "kernel_wheel",
            "kernel_repository",
            "kernel_runtime_manifest",
            "kernel_cas_root",
            "valuation_output_directory",
            "stage_plan_file",
            "futu_data_review_file",
            "peer_review_file",
            "synthesis_review_file",
            "score_review_file",
            "run_input_file",
            "price_blind_artifact_directory",
        )
    }
    config_file = _write_canonical(
        tmp_path / "invalid-runtime.json",
        _config(research, valuation=valuation),
    )

    with pytest.raises(OwnerEquityRuntimeError, match="forbids valuation capability"):
        load_owner_equity_runtime(
            config_file,
            intent=ResearchIntent.RESEARCH,
            profile=None,
        )


def test_runtime_config_rejects_noncanonical_json(tmp_path: Path) -> None:
    path = tmp_path / "runtime.json"
    path.write_text('{"schema_version": "1.0.0"}\n', encoding="utf-8")
    path.chmod(0o600)

    with pytest.raises(OwnerEquityRuntimeError, match="canonically serialized"):
        load_owner_equity_runtime(
            path,
            intent=ResearchIntent.VALUATION,
            profile=PublicationProfile.FULL_VALUATION,
        )


def test_validate_schema_cli_reads_descriptor_first_with_a_16_mib_cap(
    sample_payloads,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys,
) -> None:
    valid = _write_canonical(tmp_path / "fact.json", sample_payloads["fact"])
    assert validate_cli.main(["schema", "fact", str(valid)]) == 0

    symlink = tmp_path / "fact-link.json"
    symlink.symlink_to(valid)
    assert validate_cli.main(["schema", "fact", str(symlink)]) == 2
    assert capsys.readouterr().err.strip() == (
        "owner-research-validate: schema input is unavailable"
    )

    monkeypatch.setattr(validate_cli, "_SCHEMA_INPUT_MAX_BYTES", 4)
    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"12345")
    assert validate_cli.main(["schema", "fact", str(oversized)]) == 2
    assert capsys.readouterr().err.strip() == (
        "owner-research-validate: schema input exceeds the 16 MiB byte limit"
    )


def test_valuation_runtime_requires_a_local_publication_destination(
    sample_payloads,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _, research, run_input, price_blind = _runtime_fixture(
        sample_payloads, monkeypatch, tmp_path
    )
    report_payload = {**sample_payloads["report-spec"], "output_formats": ["latex_pdf"]}
    report_file = _write_canonical(tmp_path / "report-spec.json", report_payload)
    config_file = _write_canonical(
        tmp_path / "valuation-without-publication.json",
        _config(
            research,
            report={"report_spec_file": str(report_file)},
            valuation=_missing_valuation(run_input, price_blind),
        ),
    )

    with pytest.raises(OwnerEquityRuntimeError, match="publication config fields"):
        load_owner_equity_runtime(
            config_file,
            intent=ResearchIntent.VALUATION,
            profile=PublicationProfile.FULL_VALUATION,
        )


def test_runtime_enforces_one_256_mib_budget_across_unique_research_inputs(
    sample_payloads,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _, research, _, _ = _runtime_fixture(sample_payloads, monkeypatch, tmp_path)
    config_file = _write_canonical(
        tmp_path / "research-budget-runtime.json",
        _config(research),
    )
    graph_file = Path(str(research["research_graph_file"]))
    bundle_directory = Path(str(research["research_bundle_directory"]))
    unique_files = (
        graph_file,
        bundle_directory / "research-bundle.json",
        bundle_directory / "run-manifest.json",
    )
    unique_total = sum(path.stat().st_size for path in unique_files)
    monkeypatch.setattr(
        runtime_module,
        "_RESEARCH_INPUT_TOTAL_MAX_BYTES",
        unique_total - 1,
    )
    with pytest.raises(OwnerEquityRuntimeError, match="256 MiB cumulative"):
        load_owner_equity_runtime(
            config_file,
            intent=ResearchIntent.RESEARCH,
            profile=None,
        )

    monkeypatch.setattr(
        runtime_module,
        "_RESEARCH_INPUT_TOTAL_MAX_BYTES",
        unique_total,
    )
    runtime = load_owner_equity_runtime(
        config_file,
        intent=ResearchIntent.RESEARCH,
        profile=None,
    )
    assert runtime.research_read_budget.consumed == unique_total
    assert set(runtime.research_read_budget.snapshots or {}) == {
        path.absolute() for path in unique_files
    }


def test_research_budget_rejects_two_byte_member_before_read_with_one_byte_left(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    budget = runtime_module._ResearchReadBudget(3)
    first = tmp_path / "first.json"
    budget.capture(first, b"aa", "first research input")
    second = tmp_path / "second.json"
    second.write_bytes(b"bb")

    monkeypatch.setattr(
        runtime_module.os,
        "read",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("research bytes were read before the cumulative gate")
        ),
    )
    with pytest.raises(OwnerEquityRuntimeError, match="256 MiB cumulative"):
        budget.read(second, "second research input", 64 * 1024 * 1024)

    reader_called = False

    def forbidden_reader() -> bytes:
        nonlocal reader_called
        reader_called = True
        return b"bb"

    with pytest.raises(OwnerEquityRuntimeError, match="256 MiB cumulative"):
        budget.read_artifact_member(second, 2, forbidden_reader)
    assert reader_called is False


def test_daily_close_request_is_unadjusted_rth_without_extended_hours() -> None:
    parameters = runtime_module._unadjusted_rth_daily_close_parameters("2026-08-14")
    assert parameters["start"] == parameters["end"] == "2026-08-14"
    assert parameters["ktype"] == "K_DAY"
    assert parameters["autype"] == "NONE"
    assert parameters["session"] == "RTH"
    assert parameters["extended_time"] is False
    assert parameters["max_count"] == 1
    peer_daily = runtime_module._peer_specs(
        expected_trading_date="2026-08-14",
        price_blind_freeze_fingerprint="f" * 64,
    )[1]
    assert peer_daily.protocol_id == 3103
    assert peer_daily.parameters == parameters


def test_interface_authority_freezes_rth_request_but_not_close_attestation() -> None:
    registry_path = (
        Path(__file__).parents[1]
        / "src/owner_research/resources/futu/interface-authority-registry-v1.json"
    )
    registry = json.loads(registry_path.read_bytes())
    history = next(
        item for item in registry["sources"] if item["protocol_id"] == 3103
    )
    assert history["semantic_constraints"] == [
        "request K_DAY with AuType.NONE, Session.RTH, and extended=false; only separately "
        "signed daily_close_semantics_evidence may attest regular-session close semantics"
    ]


@pytest.mark.parametrize("bundle_status", ("partial", "blocked"))
def test_existing_research_only_publication_preserves_incomplete_report_outcome(
    sample_payloads,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    bundle_status: str,
) -> None:
    graph = _incomplete_research_graph(sample_payloads, bundle_status)
    research, source_index, report_spec, scores = _typed_report_inputs(
        sample_payloads,
        tmp_path / bundle_status,
        graph=graph,
    )
    report = report_module.build_research_report(
        profile="research_only",
        research=research,
        report_spec=report_spec,
        research_source_index=source_index,
        scores=scores,
        renderer=DeterministicRenderer(
            tuple(str(section["title"]) for section in report_spec.sections)
        ),
    )
    assert report.content["status"] == bundle_status
    source_directory = tmp_path / f"source-{bundle_status}"
    source = publish_package_allowing_test_renderer(
        report,
        research,
        output_directory=source_directory,
        allow_injected_test_renderer=True,
    )

    def load_with_test_renderer(*args, **kwargs):
        kwargs["allow_injected_test_renderer"] = True
        return load_package_allowing_test_renderer(*args, **kwargs)

    def republish_with_test_renderer(*args, **kwargs):
        kwargs["allow_injected_test_renderer"] = True
        return republish_package_allowing_test_renderer(*args, **kwargs)

    monkeypatch.setattr(runtime_module, "load_owner_research_package", load_with_test_renderer)
    monkeypatch.setattr(
        runtime_module,
        "republish_owner_research_package",
        republish_with_test_renderer,
    )
    output_directory = tmp_path / f"republished-{bundle_status}"
    config = _write_canonical(
        tmp_path / f"publish-{bundle_status}.json",
        _config(
            None,
            publication={
                "input_package_directory": str(source_directory),
                "output_directory": str(output_directory),
            },
        ),
    )
    runtime = load_owner_equity_runtime(
        config,
        intent=ResearchIntent.PUBLISH,
        profile=PublicationProfile.RESEARCH_ONLY,
    )
    request = OwnerEquityResearchRequest(
        issuer_id=source.report.issuer_id,
        data_cutoff_date=source.report.data_cutoff_date,
        intent=ResearchIntent.PUBLISH,
        profile=PublicationProfile.RESEARCH_ONLY,
        requested_by="human:publication-outcome-reviewer",
        requested_at="2026-08-15T09:00:00+08:00",
    )

    result = run_owner_equity_research(
        request=request,
        dependencies=build_runtime_dependencies(runtime),
    )

    assert result.status is PhaseStatus.PARTIAL
    assert result.issue_codes == ("research_report_partial",)
    assert result.publication is not None
    assert result.publication.status is PhaseStatus.PARTIAL
    assert result.publication.issue_codes == ("research_report_partial",)
    assert result.publication.published_package is not None
    assert result.publication.published_package.report.content["status"] == bundle_status
    assert result.publication.published_package.file_bytes == source.file_bytes
    assert tuple(
        (step.phase, step.status) for step in result.trace
    ) == (("publication", PhaseStatus.PARTIAL),)


def test_all_price_blind_runtime_routes_make_zero_futu_calls_and_audit_binds_identity(
    sample_payloads,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    report_fixture = tmp_path / "report-route-fixture"
    report_fixture.mkdir()
    report_research_input, report_source_index = typed_research_inputs_for_graph(
        formal_scope_graph(sample_payloads),
        report_fixture / "strict-research-input",
    )
    graph = report_source_index.graph
    graph_file = write_research_runtime_context(
        graph=graph,
        output_file=tmp_path / "price-blind-route-graph.json",
    )
    research = {
        "research_graph_file": str(graph_file),
        "research_bundle_directory": str(report_research_input.source_directory),
    }
    bundle = graph.research_bundles[0]
    futu_calls: list[str] = []

    def forbidden_futu(*args, **kwargs):
        futu_calls.append("called")
        raise AssertionError("price-blind route crossed the Futu boundary")

    monkeypatch.setattr(
        "owner_research.futu_sidecar.AttestedFutuSidecarSession.open",
        forbidden_futu,
    )
    report_payload = {
        **sample_payloads["report-spec"],
        "output_formats": ["json", "markdown", "latex_pdf"],
    }
    report_file = _write_canonical(tmp_path / "price-blind-report-spec.json", report_payload)
    titles = tuple(str(section["title"]) for section in report_payload["sections"])
    monkeypatch.setattr(
        runtime_module,
        "LatexReportRenderer",
        lambda: DeterministicRenderer(titles),
    )
    # This route test intentionally isolates orchestration from concurrent report-asset
    # supply freezing; the report/PDF suite verifies the on-disk assets themselves.
    monkeypatch.setattr(
        report_module,
        "_asset_contents",
        lambda: (
            report_module._DEFAULT_TEMPLATE,
            dict(report_module._DEFAULT_FONT_MANIFEST),
        ),
    )

    def publish_with_test_renderer(*args, **kwargs):
        kwargs["allow_injected_test_renderer"] = True
        return publish_package_allowing_test_renderer(*args, **kwargs)

    def republish_with_test_renderer(*args, **kwargs):
        kwargs["allow_injected_test_renderer"] = True
        return republish_package_allowing_test_renderer(*args, **kwargs)

    package_adapter_loads = 0

    def load_with_test_renderer(*args, **kwargs):
        nonlocal package_adapter_loads
        package_adapter_loads += 1
        kwargs["allow_injected_test_renderer"] = True
        return load_package_allowing_test_renderer(*args, **kwargs)

    def forbidden_phase_reload(*_args, **_kwargs):
        raise AssertionError("high-level phase reopened the already loaded package")

    monkeypatch.setattr(runtime_module, "publish_owner_research", publish_with_test_renderer)
    monkeypatch.setattr(
        runtime_module,
        "republish_owner_research_package",
        republish_with_test_renderer,
    )
    monkeypatch.setattr(runtime_module, "load_owner_research_package", load_with_test_renderer)
    monkeypatch.setattr(research_module, "load_owner_research_package", forbidden_phase_reload)

    def request(intent: ResearchIntent, profile: PublicationProfile | None = None):
        return OwnerEquityResearchRequest(
            issuer_id=bundle.issuer_id,
            data_cutoff_date=bundle.data_cutoff_date,
            intent=intent,
            profile=profile,
            requested_by="human:zero-futu-reviewer",
            requested_at="2026-08-15T09:00:00+08:00",
        )

    quarterly_config = _write_canonical(
        tmp_path / "quarterly-runtime.json",
        _config(research),
    )
    quarterly_runtime = load_owner_equity_runtime(
        quarterly_config,
        intent=ResearchIntent.QUARTERLY,
        profile=None,
    )
    quarterly = run_owner_equity_research(
        request=request(ResearchIntent.QUARTERLY),
        dependencies=build_runtime_dependencies(quarterly_runtime),
    )
    assert quarterly.status is PhaseStatus.COMPLETED
    assert quarterly.issue_codes == ()
    assert tuple(item.phase for item in quarterly.trace) == (
        "official_research_freeze",
        "quarterly",
    )

    report_research = {
        "research_graph_file": str(graph_file),
        "research_bundle_directory": str(report_research_input.source_directory),
    }

    report_config = _write_canonical(
        tmp_path / "report-runtime.json",
        _config(report_research, report={"report_spec_file": str(report_file)}),
    )
    report_runtime = load_owner_equity_runtime(
        report_config,
        intent=ResearchIntent.REPORT,
        profile=PublicationProfile.RESEARCH_ONLY,
    )
    report = run_owner_equity_research(
        request=request(ResearchIntent.REPORT, PublicationProfile.RESEARCH_ONLY),
        dependencies=build_runtime_dependencies(report_runtime),
    )
    assert report.status is PhaseStatus.COMPLETED
    assert report.report_build is not None
    assert report.report_build.receipt["qa"]["page_count"] == 30

    source_publication_directory = tmp_path / "source-research-only"
    assert report_runtime.research_authority is not None
    source_package = publish_package_allowing_test_renderer(
        report.report_build,
        report_runtime.research_authority.research,
        output_directory=source_publication_directory,
        allow_injected_test_renderer=True,
    )
    publication_directory = tmp_path / "published-research-only"
    publish_config = _write_canonical(
        tmp_path / "publish-runtime.json",
        _config(
            None,
            publication={
                "input_package_directory": str(source_publication_directory),
                "output_directory": str(publication_directory),
            },
        ),
    )
    publish_runtime = load_owner_equity_runtime(
        publish_config,
        intent=ResearchIntent.PUBLISH,
        profile=PublicationProfile.RESEARCH_ONLY,
    )
    with pytest.raises(OwnerEquityRuntimeError, match="publication output"):
        replace(publish_runtime, publication_output=str(publication_directory))
    for invalid_fingerprint in ("A" * 64, "g" * 64, 1):
        with pytest.raises(OwnerEquityRuntimeError, match="config fingerprint"):
            replace(publish_runtime, config_fingerprint=invalid_fingerprint)
    published = run_owner_equity_research(
        request=request(ResearchIntent.PUBLISH, PublicationProfile.RESEARCH_ONLY),
        dependencies=build_runtime_dependencies(publish_runtime),
    )
    assert published.status is PhaseStatus.COMPLETED
    assert published.publication_manifest is not None
    assert published.published_package is not None
    assert published.published_package.file_bytes == source_package.file_bytes
    assert tuple(item.phase for item in published.trace) == ("publication",)
    assert published.official_research is None
    assert published.report is None

    audit_config = _write_canonical(
        tmp_path / "audit-runtime.json",
        _config(
            None,
            audit={"package_directory": str(publication_directory)},
        ),
    )
    audit_runtime = load_owner_equity_runtime(
        audit_config,
        intent=ResearchIntent.AUDIT,
        profile=None,
    )
    audit = run_owner_equity_research(
        request=request(ResearchIntent.AUDIT),
        dependencies=build_runtime_dependencies(audit_runtime),
    )
    assert audit.status is PhaseStatus.COMPLETED
    assert audit.audit is not None and audit.audit.read_only is True

    foreign_request = OwnerEquityResearchRequest(
        issuer_id="issuer:us:foreign",
        data_cutoff_date=bundle.data_cutoff_date,
        intent=ResearchIntent.AUDIT,
        profile=None,
        requested_by="human:zero-futu-reviewer",
        requested_at="2026-08-15T09:00:00+08:00",
    )
    foreign = run_owner_equity_research(
        request=foreign_request,
        dependencies=build_runtime_dependencies(audit_runtime),
    )
    assert foreign.status is PhaseStatus.BLOCKED
    assert foreign.audit is not None
    assert foreign.audit.audit_result is None
    assert foreign.issue_codes == ("audit_blocked:identity_mismatch",)
    assert package_adapter_loads == 2
    assert futu_calls == []
