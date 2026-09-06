from __future__ import annotations

import hashlib
import os
import sys
import tempfile
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from test_phase5_v1_market_slice import _unacquired_inputs
from test_phase5_v1_owner_execution import (
    TEST_RUNTIME_MANIFEST,
    TEST_RUNTIME_MANIFEST_FILE_SHA256,
    _clock,
    _compiled,
    _noncompiled,
    _prepared_inputs,
)

import owner_research.valuation_cli as valuation_cli_module
import owner_research.valuation_market_provider as market_provider_module
import owner_research.valuation_owner_execution as owner_execution_module
import owner_research.valuation_run as run_module
from owner_research.fingerprints import to_json_value
from owner_research.valuation_assumption_types import AssumptionCandidateCompilationResult
from owner_research.valuation_kernel_materializer import KernelMaterializationError
from owner_research.valuation_market_execution_policies import PINNED_KERNEL_WHEEL_SHA256
from owner_research.valuation_market_provider import ReviewedFileMarketProvider, RunClock
from owner_research.valuation_owner_execution import (
    OwnerValuationExecutionClock,
    OwnerValuationExecutionError,
    execute_owner_valuation,
)
from owner_research.valuation_run import (
    RuntimeManifestInputAuthority,
    ValuationRunAuthority,
    ValuationRunClock,
    run_owner_valuation,
)


def _authority(preparation: Any, freeze: Any, tmp_path: Path) -> ValuationRunAuthority:
    prepared = preparation.prepared_market_reference
    assert prepared is not None
    context = prepared.graph.market_reference_validation_contexts[0]
    return ValuationRunAuthority(
        price_blind_artifact_directory=tmp_path / "price-blind",
        expected_freeze=freeze,
        expected_security=context.security_compilation_result,
        kernel_repository=Path("/read-only/kernel"),
        runtime_manifest=Path("/runtime/manifest.json"),
        runtime_manifest_file_sha256=TEST_RUNTIME_MANIFEST_FILE_SHA256,
        cas_root=Path("/runtime/cas"),
    )


def _run_clock(preparation: Any) -> ValuationRunClock:
    prepared = preparation.prepared_market_reference
    assert prepared is not None
    access = prepared.graph.market_reference_validation_contexts[0].market_access_result
    assert access.request is not None and access.receipt is not None
    return ValuationRunClock(
        market=RunClock(
            access.request.request_started_at,
            access.receipt.receipt.retrieved_at,
        ),
        execution=_clock(preparation),
    )


def _candidate_compilation(freeze: Any) -> AssumptionCandidateCompilationResult:
    payload = to_json_value(freeze.artifact.payload["assumption_candidates"])
    return AssumptionCandidateCompilationResult(
        **{key: value for key, value in payload.items() if key != "candidates"},
        candidates=freeze.candidates,
    )


def _typed_runtime_authority() -> RuntimeManifestInputAuthority:
    return RuntimeManifestInputAuthority.verified(TEST_RUNTIME_MANIFEST)


def test_explicit_run_archives_one_completed_execution(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from test_phase5_v1_valuation_synthesis import _completed_run

    fixture_root = tmp_path / "schema-valid-completion"
    fixture_root.mkdir()
    fixture_run, *_ = _completed_run(
        sample_payloads,
        monkeypatch,
        fixture_root,
    )
    completed = fixture_run.execution
    assert completed is not None
    preparation = completed.preparation
    freeze = completed.expected_freeze
    assert freeze is not None
    authority = _authority(preparation, freeze, tmp_path)
    monkeypatch.setattr(
        run_module,
        "_replay_assumption_inputs",
        lambda **_kwargs: _candidate_compilation(freeze),
    )
    monkeypatch.setattr(run_module, "prepare_owner_valuation", lambda **_kwargs: preparation)
    monkeypatch.setattr(
        run_module,
        "_verify_runtime_supply",
        lambda **_kwargs: _typed_runtime_authority(),
    )
    execution_calls: list[dict[str, Any]] = []

    def execute(**kwargs: Any) -> Any:
        execution_calls.append(kwargs)
        return completed

    monkeypatch.setattr(run_module, "execute_owner_valuation", execute)
    result = run_owner_valuation(
        graph=preparation.prepared_market_reference.graph,
        bundle_artifact_directory=tmp_path / "bundle",
        assumption_proposals=(),
        assumption_reviews=(),
        market_provider=object(),
        kernel_wheel=Path("/runtime/cas/sha256") / ("f" * 64),
        output_directory=tmp_path / "archive",
        clock=_run_clock(preparation),
        authority=authority,
        timeout_seconds=31,
    )

    assert result.status == "completed"
    assert result.execution is completed
    assert result.archive is not None
    assert result.archive.output_directory == tmp_path / "archive"
    assert len(execution_calls) == 1
    assert execution_calls[0]["timeout_seconds"] == 31
    assert len(result.fingerprint) == 64
    assert result.fingerprint == result._integrity_binding
    assert result.input_receipt.runtime_manifest_authority.status == "verified"
    assert "runtime_manifest_file_sha256" not in result.input_receipt.to_dict()
    assert (
        result.input_receipt.runtime_manifest_authority.runtime_manifest_file_sha256
        == completed.kernel_execution_receipt.runtime_manifest_file_sha256
    )
    summary = valuation_cli_module._summary(result)
    assert summary["valuation_result_sha256"] == hashlib.sha256(completed.result_bytes).hexdigest()
    assert summary["valuation_result_sha256"] == (completed.kernel_execution_receipt.result_sha256)


@pytest.mark.parametrize(
    ("runtime_error", "expected_issue"),
    (
        (None, "runtime_supply_blocked:ValuationRunError"),
        (
            KernelMaterializationError("runtime manifest drifted"),
            "runtime_supply_blocked:KernelMaterializationError",
        ),
    ),
)
def test_invalid_runtime_supply_blocks_before_reviewed_market_acquisition(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    runtime_error: KernelMaterializationError | None,
    expected_issue: str,
) -> None:
    monkeypatch.setattr(
        market_provider_module,
        "_AUTHORIZATION_STATE_BASE",
        tmp_path / "owner-research-state",
    )
    graph, freeze, directory, security, review, raw = _unacquired_inputs(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    monkeypatch.setattr(
        run_module,
        "_replay_assumption_inputs",
        lambda **_kwargs: _candidate_compilation(freeze),
    )
    runtime_checks: list[dict[str, Any]] = []
    original_verify = run_module._verify_runtime_supply

    def verify_runtime(**kwargs: Any) -> RuntimeManifestInputAuthority:
        runtime_checks.append(kwargs)
        if runtime_error is not None:
            raise runtime_error
        return original_verify(**kwargs)

    monkeypatch.setattr(run_module, "_verify_runtime_supply", verify_runtime)
    market_calls: list[object] = []
    original_acquire = ReviewedFileMarketProvider.acquire

    def acquire_market(self: ReviewedFileMarketProvider, request: object) -> Any:
        market_calls.append(request)
        return original_acquire(self, request)  # type: ignore[arg-type]

    monkeypatch.setattr(ReviewedFileMarketProvider, "acquire", acquire_market)
    cas_root = tmp_path / "runtime" / "cas"
    authority = ValuationRunAuthority(
        price_blind_artifact_directory=directory,
        expected_freeze=freeze,
        expected_security=security,
        kernel_repository=tmp_path / "kernel",
        runtime_manifest=tmp_path / "runtime" / "manifest.json",
        runtime_manifest_file_sha256="d" * 64,
        cas_root=cas_root,
    )
    output = tmp_path / "archive"

    result = run_owner_valuation(
        graph=graph,
        bundle_artifact_directory=tmp_path / "bundle",
        assumption_proposals=(),
        assumption_reviews=(),
        market_provider=ReviewedFileMarketProvider(review, raw),
        kernel_wheel=cas_root / "sha256" / PINNED_KERNEL_WHEEL_SHA256,
        output_directory=output,
        clock=ValuationRunClock(
            market=RunClock("2026-07-14T01:00:00Z", "2026-07-14T01:00:01Z"),
            execution=OwnerValuationExecutionClock(
                "2026-07-14T01:00:02Z",
                "2026-07-14T01:00:03Z",
            ),
        ),
        authority=authority,
    )

    assert result.status == "blocked"
    assert result.issue_codes == (expected_issue,)
    assert result.preparation is None
    assert result.execution is None
    assert result.archive is None
    assert result.input_receipt.runtime_manifest_authority.status == "not_exercised"
    assert len(runtime_checks) == 1
    assert market_calls == []
    assert not output.exists()


def test_specialist_route_never_checks_runtime_or_invokes_kernel(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    prepared, freeze = _prepared_inputs(sample_payloads, monkeypatch, tmp_path)
    authority = _authority(prepared, freeze, tmp_path)
    eligible_decision = authority.expected_security.decision
    assert eligible_decision is not None
    issue = "dual_class_security_unsupported"
    specialist_security = replace(
        authority.expected_security,
        status="specialist_required",
        decision=replace(
            eligible_decision,
            security_structure="dual_or_multi_class_different_prices",
            disposition="specialist_required",
            reason_codes=(issue,),
        ),
        issue_codes=(issue,),
    )
    authority = replace(authority, expected_security=specialist_security)
    specialist = replace(
        prepared,
        status="specialist_required",
        prepared_market_reference=None,
        issue_codes=(issue,),
    )
    compiled = _noncompiled(specialist)
    monkeypatch.setattr(
        owner_execution_module,
        "compile_final_valuation_request",
        lambda **_kwargs: compiled,
    )
    run_clock = _run_clock(prepared)
    stopped = execute_owner_valuation(
        preparation=specialist,
        expected_freeze=freeze,
        kernel_repository=Path("/unused/kernel"),
        runtime_manifest=Path("/unused/manifest"),
        runtime_manifest_file_sha256="d" * 64,
        cas_root=Path("/unused/cas"),
        clock=run_clock.execution,
    )
    monkeypatch.setattr(
        run_module,
        "_replay_assumption_inputs",
        lambda **_kwargs: _candidate_compilation(freeze),
    )
    monkeypatch.setattr(run_module, "prepare_owner_valuation", lambda **_kwargs: specialist)
    monkeypatch.setattr(run_module, "execute_owner_valuation", lambda **_kwargs: stopped)
    runtime_checks: list[object] = []
    monkeypatch.setattr(
        run_module,
        "_verify_runtime_supply",
        lambda **kwargs: runtime_checks.append(kwargs),
    )

    result = run_owner_valuation(
        graph=prepared.prepared_market_reference.graph,
        bundle_artifact_directory=tmp_path / "bundle",
        assumption_proposals=(),
        assumption_reviews=(),
        market_provider=object(),
        kernel_wheel=Path("/unavailable/wheel"),
        output_directory=tmp_path / "archive",
        clock=run_clock,
        authority=authority,
    )

    assert result.status == "specialist_required"
    assert result.archive is None
    assert result.execution is stopped
    assert stopped.kernel_execution_result is None
    assert runtime_checks == []
    assert result.input_receipt.runtime_manifest_authority.to_dict() == {
        "status": "not_exercised",
        "manifest_payload": None,
    }

    with pytest.raises(ValueError):
        replace(result, preparation=None)
    with pytest.raises(ValueError):
        replace(result, issue_codes=("specialist_required:rebound",))

    alternate = execute_owner_valuation(
        preparation=specialist,
        expected_freeze=freeze,
        kernel_repository=Path("/unused/kernel"),
        runtime_manifest=Path("/unused/manifest"),
        runtime_manifest_file_sha256="d" * 64,
        cas_root=Path("/unused/cas"),
        clock=OwnerValuationExecutionClock(
            "2026-07-14T01:00:04Z",
            "2026-07-14T01:00:05Z",
        ),
    )
    assert alternate.stopped_envelope_fingerprint != stopped.stopped_envelope_fingerprint
    with pytest.raises(ValueError, match="execution binding"):
        replace(result, execution=alternate)


def test_missing_reviewed_market_evidence_returns_honest_blocked_result(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    preparation, freeze = _prepared_inputs(sample_payloads, monkeypatch, tmp_path)
    authority = _authority(preparation, freeze, tmp_path)
    monkeypatch.setattr(
        run_module,
        "_replay_assumption_inputs",
        lambda **_kwargs: _candidate_compilation(freeze),
    )
    monkeypatch.setattr(
        run_module,
        "_verify_runtime_supply",
        lambda **_kwargs: _typed_runtime_authority(),
    )
    monkeypatch.setattr(
        run_module,
        "prepare_owner_valuation",
        lambda **_kwargs: (_ for _ in ()).throw(FileNotFoundError("review receipt missing")),
    )
    execution_calls: list[object] = []
    monkeypatch.setattr(
        run_module,
        "execute_owner_valuation",
        lambda **kwargs: execution_calls.append(kwargs),
    )

    result = run_owner_valuation(
        graph=preparation.prepared_market_reference.graph,
        bundle_artifact_directory=tmp_path / "bundle",
        assumption_proposals=(),
        assumption_reviews=(),
        market_provider=object(),
        kernel_wheel=Path("/unavailable/wheel"),
        output_directory=tmp_path / "archive",
        clock=_run_clock(preparation),
        authority=authority,
    )

    assert result.status == "blocked"
    assert result.issue_codes == ("market_preparation_blocked:FileNotFoundError",)
    assert result.preparation is None
    assert result.execution is None
    assert result.archive is None
    assert execution_calls == []
    assert result.input_receipt.runtime_manifest_authority.status == "not_exercised"


def test_execution_preflight_block_returns_typed_result_with_prepared_input(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    preparation, freeze = _prepared_inputs(sample_payloads, monkeypatch, tmp_path)
    authority = _authority(preparation, freeze, tmp_path)
    compiled = _compiled(preparation)
    monkeypatch.setattr(
        owner_execution_module,
        "compile_final_valuation_request",
        lambda **_kwargs: compiled,
    )

    def block_preflight(**_kwargs: Any) -> Any:
        raise OwnerValuationExecutionError("deterministic preflight rejection")

    monkeypatch.setattr(owner_execution_module, "_compiled_context", block_preflight)
    stopped = execute_owner_valuation(
        preparation=preparation,
        expected_freeze=freeze,
        kernel_repository=Path("/read-only/kernel"),
        runtime_manifest=Path("/runtime/manifest.json"),
        runtime_manifest_file_sha256=TEST_RUNTIME_MANIFEST_FILE_SHA256,
        cas_root=Path("/runtime/cas"),
        clock=_clock(preparation),
    )
    assert stopped.status == "blocked"
    assert stopped.preparation.status == "blocked"
    assert stopped.preparation.prepared_market_reference is None
    assert stopped.final_request_result.status == "blocked"

    monkeypatch.setattr(
        run_module,
        "_replay_assumption_inputs",
        lambda **_kwargs: _candidate_compilation(freeze),
    )
    monkeypatch.setattr(run_module, "prepare_owner_valuation", lambda **_kwargs: preparation)
    monkeypatch.setattr(
        run_module,
        "_verify_runtime_supply",
        lambda **_kwargs: _typed_runtime_authority(),
    )
    monkeypatch.setattr(run_module, "execute_owner_valuation", lambda **_kwargs: stopped)

    result = run_owner_valuation(
        graph=preparation.prepared_market_reference.graph,
        bundle_artifact_directory=tmp_path / "bundle",
        assumption_proposals=(),
        assumption_reviews=(),
        market_provider=object(),
        kernel_wheel=Path("/runtime/cas/sha256") / ("f" * 64),
        output_directory=tmp_path / "archive",
        clock=_run_clock(preparation),
        authority=authority,
    )

    assert result.status == "blocked"
    assert result.preparation is preparation
    assert result.execution is stopped
    assert result.archive is None
    assert result.input_receipt.runtime_manifest_authority.status == "verified"
    assert result.issue_codes == (
        "owner_execution_preflight_blocked:OwnerValuationExecutionError",
    )
    with pytest.raises(ValueError):
        replace(result, preparation=stopped.preparation)

    prepared = preparation.prepared_market_reference
    assert prepared is not None
    rebound_graph = replace(
        prepared.graph,
        documents=prepared.graph.documents + (prepared.market_source,),
        facts=prepared.graph.facts + (prepared.quote_fact,),
        calculations=(
            prepared.graph.calculations + (prepared.market_equity_calculation,)
        ),
        market_reference_snapshots=(
            prepared.graph.market_reference_snapshots + (prepared.snapshot,)
        ),
    )
    rebound_prepared = replace(prepared, graph=rebound_graph)
    rebound_preparation = replace(
        preparation,
        prepared_market_reference=rebound_prepared,
    )

    # PreparedMarketReference advertises the same fingerprint because its graph is
    # deliberately outside that projection.  The retained run must still replay the
    # graph and reject duplicate additions instead of accepting the old run fingerprint.
    assert rebound_prepared.fingerprint == prepared.fingerprint
    advertised_fingerprint = result.fingerprint
    with pytest.raises(ValueError, match="Duplicate identifier"):
        replace(
            result,
            preparation=rebound_preparation,
            _integrity_binding=advertised_fingerprint,
        )


def test_generic_run_reads_are_descriptor_first_nofollow_and_bounded(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.json"
    source.write_bytes(b'{"ok":true}')
    original_lstat = Path.lstat
    original_open = Path.open

    def forbidden_lstat(path: Path, *_args: Any, **_kwargs: Any) -> Any:
        if path == source:
            raise AssertionError("generic reader used path lstat before opening")
        return original_lstat(path)

    def forbidden_open(path: Path, *_args: Any, **_kwargs: Any) -> Any:
        if path == source:
            raise AssertionError("generic reader used Path.open")
        return original_open(path, *_args, **_kwargs)

    monkeypatch.setattr(Path, "lstat", forbidden_lstat)
    monkeypatch.setattr(Path, "open", forbidden_open)
    assert run_module._read_regular_file(source, "fixture", maximum=64) == b'{"ok":true}'

    if hasattr(os, "O_PATH"):
        traversal = tmp_path / "execute-only"
        protected = traversal / "protected"
        protected.mkdir(parents=True)
        protected_source = protected / "authority.json"
        protected_source.write_bytes(b'{"ok":true}')
        protected_source.chmod(0o444)
        protected.chmod(0o555)
        traversal.chmod(0o111)
        try:
            assert run_module._read_regular_file(
                protected_source,
                "fixture",
                maximum=64,
            ) == b'{"ok":true}'
        finally:
            traversal.chmod(0o700)

    link = tmp_path / "link.json"
    link.symlink_to(source)
    with pytest.raises(run_module.ValuationRunError, match="unavailable"):
        run_module._read_regular_file(link, "fixture", maximum=64)
    with pytest.raises(run_module.ValuationRunError, match="bounded"):
        run_module._read_regular_file(source, "fixture", maximum=4)
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    nested = real_parent / "authority.json"
    nested.write_bytes(b'{"ok":true}')
    parent_alias = tmp_path / "parent-alias"
    parent_alias.symlink_to(real_parent, target_is_directory=True)
    with pytest.raises(run_module.ValuationRunError, match="symlinked component"):
        run_module._read_regular_file(
            parent_alias / nested.name,
            "fixture",
            maximum=64,
        )
    source.chmod(0o666)
    with pytest.raises(run_module.ValuationRunError, match="bounded regular"):
        run_module._read_regular_file(source, "fixture", maximum=64)


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin fixed root alias")
@pytest.mark.parametrize("temporary_root", ("/tmp", "/var/tmp"))
def test_generic_run_read_accepts_platform_tmp_root_alias(temporary_root: str) -> None:
    with tempfile.TemporaryDirectory(dir=temporary_root) as directory:
        source = Path(directory) / "authority.json"
        source.write_bytes(b'{"ok":true}')

        assert run_module._read_regular_file(
            source,
            "fixture",
            maximum=64,
        ) == b'{"ok":true}'
