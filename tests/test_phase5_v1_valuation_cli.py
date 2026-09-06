from __future__ import annotations

import argparse
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_phase5_v1_run_context import _context_inputs

import owner_research.valuation_cli as valuation_cli_module
from owner_research.valuation_cli import build_parser, main
from owner_research.valuation_run_context import write_valuation_run_input_context


def test_cli_has_one_explicit_command_and_no_price_network_or_account_flag() -> None:
    parser = build_parser()
    subparsers = next(
        action for action in parser._actions if isinstance(action, argparse._SubParsersAction)
    )
    assert set(subparsers.choices) == {"complete"}
    complete = subparsers.choices["complete"]
    options = {
        option
        for action in complete._actions
        for option in action.option_strings
        if option.startswith("--")
    }
    assert options == {
        "--help",
        "--kernel-repository",
        "--kernel-wheel",
        "--market-receipt",
        "--output",
        "--price-blind-dir",
        "--raw-market-evidence",
        "--run-input",
        "--timeout-seconds",
    }
    assert "--price" not in options
    assert "--ticker" not in options
    assert "--account" not in options


def _write_context(sample_payloads, monkeypatch, tmp_path: Path):
    graph, freeze, price_blind, security, bundle_directory, clock = _context_inputs(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    context = price_blind.parent / "valuation-run-input.json"
    write_valuation_run_input_context(
        graph=graph,
        bundle_artifact_directory=bundle_directory,
        expected_freeze=freeze,
        security_proposal=security.proposal,
        assumption_proposals=(),
        assumption_reviews=(),
        clock=clock,
        output_file=context,
    )
    return price_blind, context


def test_complete_cli_uses_default_context_and_emits_canonical_summary(
    sample_payloads,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    price_blind, _ = _write_context(sample_payloads, monkeypatch, tmp_path)
    repository = tmp_path / "kernel"
    repository.mkdir()
    cas_root = tmp_path / "cas"
    manifest = cas_root / "manifests" / ("a" * 64 + ".json")
    manifest.parent.mkdir(parents=True)
    manifest.write_text("{}\n", encoding="utf-8")
    wheel = cas_root / "sha256" / "kernel-wheel"
    wheel.parent.mkdir()
    wheel.write_bytes(b"kernel")
    market_receipt = tmp_path / "market-receipt.json"
    raw_evidence = tmp_path / "market-raw.txt"
    market_receipt.write_text("{}\n", encoding="utf-8")
    raw_evidence.write_text("raw", encoding="utf-8")
    output = tmp_path / "archive"
    captured: dict[str, object] = {}

    monkeypatch.setattr(
        "owner_research.valuation_cli._runtime_supply",
        lambda _wheel: (cas_root, manifest, "a" * 64),
    )

    def fake_run(**kwargs):
        captured.update(kwargs)
        bundle_directory = kwargs["bundle_artifact_directory"]
        assert sorted(path.name for path in bundle_directory.iterdir()) == [
            "research-bundle.json",
            "run-manifest.json",
        ]
        return SimpleNamespace(
            status="completed",
            issuer_id="issuer:acme",
            data_cutoff_date="2026-07-10",
            run_input_fingerprint="b" * 64,
            issue_codes=(),
            archive=SimpleNamespace(
                output_directory=output,
                fingerprint="c" * 64,
            ),
            execution=SimpleNamespace(
                status="completed",
                final_request_result=SimpleNamespace(request_sha256="d" * 64),
                kernel_execution_receipt=SimpleNamespace(result_sha256="e" * 64),
            ),
        )

    monkeypatch.setattr("owner_research.valuation_cli.run_owner_valuation", fake_run)
    status = main(
        [
            "complete",
            "--price-blind-dir",
            str(price_blind),
            "--market-receipt",
            str(market_receipt),
            "--raw-market-evidence",
            str(raw_evidence),
            "--kernel-wheel",
            str(wheel),
            "--kernel-repository",
            str(repository),
            "--output",
            str(output),
        ]
    )

    assert status == 0
    assert captured["output_directory"] == output
    assert captured["kernel_wheel"] == wheel
    assert captured["market_provider"].review_file == market_receipt
    summary = json.loads(capsys.readouterr().out)
    assert summary == {
        "archive_directory": str(output),
        "archive_fingerprint": "c" * 64,
        "data_cutoff_date": "2026-07-10",
        "issuer_id": "issuer:acme",
        "issue_codes": [],
        "run_input_fingerprint": "b" * 64,
        "status": "completed",
        "valuation_request_sha256": "d" * 64,
        "valuation_result_sha256": "e" * 64,
    }


def test_cli_fails_before_orchestration_without_explicit_kernel_repository(
    sample_payloads,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    price_blind, _ = _write_context(sample_payloads, monkeypatch, tmp_path)
    monkeypatch.delenv("OWNER_VALUATION_REPO", raising=False)
    monkeypatch.setattr(
        "owner_research.valuation_cli._runtime_supply",
        lambda _wheel: (tmp_path / "cas", tmp_path / "manifest", "a" * 64),
    )
    called = False

    def fail_run(**_kwargs):
        nonlocal called
        called = True
        raise AssertionError("orchestration must not run")

    monkeypatch.setattr("owner_research.valuation_cli.run_owner_valuation", fail_run)
    status = main(
        [
            "complete",
            "--price-blind-dir",
            str(price_blind),
            "--market-receipt",
            str(tmp_path / "missing-receipt"),
            "--raw-market-evidence",
            str(tmp_path / "missing-raw"),
            "--kernel-wheel",
            str(tmp_path / "wheel"),
            "--output",
            str(tmp_path / "archive"),
        ]
    )

    assert status == 2
    assert called is False
    assert "OWNER_VALUATION_REPO" in capsys.readouterr().err


def test_cli_bounded_reader_rejects_a_file_that_grows_after_initial_fstat(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    path = tmp_path / "growing.bin"
    path.write_bytes(b"x")
    original_fstat = valuation_cli_module.os.fstat
    calls = 0

    def grow_after_fstat(descriptor: int):
        nonlocal calls
        details = original_fstat(descriptor)
        if calls == 0:
            with path.open("ab") as handle:
                handle.write(b"y" * 100)
                handle.flush()
        calls += 1
        return details

    monkeypatch.setattr(valuation_cli_module.os, "fstat", grow_after_fstat)
    with pytest.raises(valuation_cli_module.ValuationCLIError, match="byte limit"):
        valuation_cli_module._regular_bytes(path, "growing input", maximum=4)
