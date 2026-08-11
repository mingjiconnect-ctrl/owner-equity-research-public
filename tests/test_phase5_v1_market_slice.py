from __future__ import annotations

import hashlib
import json
import os
import pwd
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import replace
from pathlib import Path

import pytest
import test_phase5d5_price_blind_freeze as price_blind_fixtures
import test_phase5e2b12a_integration_contracts as v2_fixtures
from phase4a_support import replace_graph
from phase5e2a_support import (
    PHASE5C_DILUTED_ROOT_ID,
    _rebind_freeze_to_phase5c_authority,
    resign_snapshot,
)
from test_phase5a_contract_graph import _valid_graph
from test_phase5e1_market_access import _security_context

import owner_research.valuation_market_provider as market_provider_module
from owner_research.calculation_integrity import build_calculation_result
from owner_research.contracts import Fact
from owner_research.fingerprints import canonical_sha256
from owner_research.validation import ContractGraphError
from owner_research.valuation_current_share_compiler import (
    compile_quote_date_current_common_shares,
)
from owner_research.valuation_handoff_validation import (
    candidate_evidence_graph_sha256,
    market_evidence_closure_sha256,
    parser_replay_fingerprint,
)
from owner_research.valuation_market_provider import (
    ReviewedFileMarketProvider,
    RunClock,
    acquire_reviewed_market_reference,
    exact_decimal_product,
    reviewed_file_authority_hashes,
)
from owner_research.valuation_market_snapshot import (
    build_reviewed_market_reference_snapshot,
)
from owner_research.valuation_owner_preparation import prepare_owner_valuation
from owner_research.valuation_price_blind_freeze import write_price_blind_input_artifact
from owner_research.valuation_security_identity import compile_security_identity
from owner_research.valuation_share_event_integration_types import (
    CurrentShareEvidenceClosureV2,
)

ROOT = Path(__file__).parents[1]


def _resign_market_snapshot(graph, snapshot, **changes):
    payload = snapshot.to_dict()
    payload.update(changes)
    context = graph.market_reference_validation_contexts[0]
    governed = context.market_access_result.receipt
    assert governed is not None
    authorization = next(
        item
        for item in graph.valuation_handoffs
        if item.handoff_id == snapshot.authorization_handoff_id
    )
    payload["raw_evidence"]["parser_replay_fingerprint"] = parser_replay_fingerprint(
        payload,
        governed.receipt,
    )
    payload["market_evidence_closure_sha256"] = market_evidence_closure_sha256(
        graph,
        payload,
        authorization,
        context,
    )
    payload.pop("snapshot_fingerprint")
    payload["snapshot_fingerprint"] = canonical_sha256(payload)
    return type(snapshot)(**payload)


@pytest.fixture(autouse=True)
def _isolated_market_authorization_store(
    monkeypatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        market_provider_module,
        "_AUTHORIZATION_STATE_BASE",
        tmp_path / "owner-research-state",
    )


def _reviewed_market_files(tmp_path: Path, security, freeze, *, close: str = "50.125"):
    assert security.decision is not None
    authorization = freeze.handoffs[-1]
    raw = tmp_path / "reviewed-close.raw"
    raw.write_bytes(b"ACME reviewed regular-session close 50.125\n")
    review = tmp_path / "reviewed-close.json"
    payload = {
        "schema_version": "1.0.0",
        "issuer_id": security.decision.issuer_id,
        "security_id": security.decision.security_id,
        "ticker": security.decision.ticker,
        "mic": security.decision.exchange,
        "share_class": security.decision.share_class,
        "trading_date": security.proposal.data_cutoff_date,
        "quote_timestamp": f"{security.proposal.data_cutoff_date}T20:00:00Z",
        "close_decimal": close,
        "currency": security.decision.quote_currency,
        "price_basis": "reviewed_unadjusted_regular_session_close",
        "session_kind": "regular",
        "source_url": "https://market.example.invalid/reviewed/acme-close",
        "source_locator": "reviewed daily close row 1",
        "source_published_date": security.proposal.data_cutoff_date,
        "source_retrieved_at": "2026-07-14T00:30:00Z",
        "raw_evidence_sha256": hashlib.sha256(raw.read_bytes()).hexdigest(),
        "raw_content_type": "text/plain",
        "reviewer_id": "human:mingji",
        "reviewed_at": "2026-07-14T00:45:00Z",
        "authorization_handoff_id": authorization.handoff_id,
        "authorization_handoff_fingerprint": authorization.fingerprint,
        "price_blind_input_fingerprint": freeze.artifact.fingerprint,
        "review_statement": "human_verified_source_date_security_close_and_currency",
    }
    review.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    return review, raw


def _unacquired_inputs(
    sample_payloads,
    monkeypatch,
    tmp_path: Path,
    *,
    current_share_value: int | float = 100_000_000,
):
    graph, freeze, directory, security = _security_context(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    graph, freeze = _rebind_freeze_to_phase5c_authority(graph, freeze)
    security = compile_security_identity(
        graph=graph,
        expected_freeze=freeze,
        proposal=security.proposal,
    )
    assert security.decision is not None
    formal_source = graph.documents[0]
    phase5c_shares = Fact(
        schema_version="2.0.0",
        fact_id=PHASE5C_DILUTED_ROOT_ID,
        issuer_id=security.decision.issuer_id,
        concept="diluted_shares",
        value_type="number",
        value=100_000_000,
        unit="shares",
        currency=None,
        period={"start": None, "end": "2025-12-31"},
        source_document_id=formal_source.document_id,
        source_locator="phase5c:reviewed-diluted-shares",
        derivation=None,
        parent_fact_ids=(),
        confidence="high",
    )
    current = Fact(
        schema_version="2.0.0",
        fact_id="fact:acme:current-common-shares:2026-06-30",
        issuer_id=security.decision.issuer_id,
        concept="common_shares_outstanding",
        value_type="number",
        value=current_share_value,
        unit="shares",
        currency=None,
        period={"start": None, "end": security.proposal.data_cutoff_date},
        source_document_id=formal_source.document_id,
        source_locator="reviewed quote-date current common shares",
        derivation=None,
        parent_fact_ids=(),
        confidence="high",
    )
    graph = replace_graph(
        graph,
        facts=graph.facts + (phase5c_shares, current),
        valuation_handoffs=freeze.handoffs,
        component_lock_path=ROOT / "component-lock.json",
    )
    write_price_blind_input_artifact(graph, freeze, output_directory=directory, overwrite=True)
    review, raw = _reviewed_market_files(tmp_path, security, freeze)
    return graph, freeze, directory, security, review, raw


def _prepared_inputs(
    sample_payloads,
    monkeypatch,
    tmp_path: Path,
    *,
    current_share_value: int | float = 100_000_000,
):
    graph, freeze, directory, security, review, raw = _unacquired_inputs(
        sample_payloads,
        monkeypatch,
        tmp_path,
        current_share_value=current_share_value,
    )
    acquisition = acquire_reviewed_market_reference(
        price_blind_artifact_directory=directory,
        graph=graph,
        expected_freeze=freeze,
        expected_security=security,
        provider=ReviewedFileMarketProvider(review, raw),
        clock=RunClock(
            request_started_at="2026-07-14T01:00:00Z",
            retrieved_at="2026-07-14T01:00:01Z",
        ),
    )
    current_shares = compile_quote_date_current_common_shares(
        price_blind_artifact_directory=directory,
        graph=graph,
        expected_freeze=freeze,
        expected_security=security,
        expected_market_access=acquisition.access_result,
    )
    assert current_shares.status == "eligible"
    return graph, freeze, directory, security, acquisition, current_shares


def _v2_rollforward_inputs(sample_payloads, monkeypatch, tmp_path: Path):
    expected, graph = v2_fixtures._accepted_context(
        sample_payloads=sample_payloads,
        corroborating_count=2,
    )
    base = _valid_graph(sample_payloads)
    bundle = graph.research_bundles[0]
    candidates = tuple(
        replace(
            candidate,
            research_bundle_id=bundle.bundle_id,
            research_bundle_fingerprint=bundle.bundle_fingerprint,
            research_bundle_dependency_sha256=bundle.dependency_closure_sha256,
        )
        for candidate in base.valuation_assumption_candidates
    )
    graph_for_candidate_hashes = replace_graph(
        graph,
        valuation_assumption_candidates=candidates,
    )
    candidates = tuple(
        replace(
            candidate,
            evidence_graph_sha256=candidate_evidence_graph_sha256(
                graph_for_candidate_hashes,
                candidate,
            ),
        )
        for candidate in candidates
    )
    candidate_by_id = {item.candidate_id: item for item in candidates}
    decisions = tuple(
        replace(
            decision,
            candidate_fingerprint=candidate_by_id[decision.candidate_id].fingerprint,
            evidence_graph_sha256=(
                candidate_by_id[decision.candidate_id].evidence_graph_sha256
            ),
        )
        for decision in base.valuation_assumption_review_decisions
    )
    opening_source = next(
        item
        for item in graph.documents
        if item.document_id == expected.opening_share_fact.source_document_id
    )
    phase5c_diluted_shares = Fact(
        schema_version="2.0.0",
        fact_id=PHASE5C_DILUTED_ROOT_ID,
        issuer_id=expected.issuer_id,
        concept="diluted_shares",
        value_type="number",
        value=125_000_000,
        unit="shares",
        currency=None,
        period={"start": None, "end": "2025-12-31"},
        source_document_id=opening_source.document_id,
        source_locator="phase5c EPS weighted-average diluted-share denominator",
        derivation=None,
        parent_fact_ids=(),
        confidence="high",
    )
    graph = replace_graph(
        graph,
        facts=(*graph.facts, phase5c_diluted_shares),
        valuation_assumption_candidates=candidates,
        valuation_assumption_review_decisions=decisions,
        valuation_handoffs=(),
        component_lock_path=ROOT / "component-lock.json",
    )
    graph.validate()
    monkeypatch.setattr(price_blind_fixtures, "_valid_graph", lambda _: graph)
    graph, freeze = price_blind_fixtures._compile(sample_payloads, monkeypatch)
    graph, freeze = _rebind_freeze_to_phase5c_authority(graph, freeze)
    security_seed = expected.bundle_evidence_closure.security_compilation_result
    security = compile_security_identity(
        graph=graph,
        expected_freeze=freeze,
        proposal=security_seed.proposal,
    )
    assert security == security_seed
    graph = replace_graph(
        graph,
        valuation_handoffs=freeze.handoffs,
        component_lock_path=ROOT / "component-lock.json",
    )
    directory = tmp_path / "price-blind-v2"
    write_price_blind_input_artifact(graph, freeze, output_directory=directory)
    review, raw = _reviewed_market_files(tmp_path, security, freeze)
    acquisition = acquire_reviewed_market_reference(
        price_blind_artifact_directory=directory,
        graph=graph,
        expected_freeze=freeze,
        expected_security=security,
        provider=ReviewedFileMarketProvider(review, raw),
        clock=RunClock(
            request_started_at="2026-07-14T01:00:00Z",
            retrieved_at="2026-07-14T01:00:01Z",
        ),
    )
    current_shares = compile_quote_date_current_common_shares(
        price_blind_artifact_directory=directory,
        graph=graph,
        expected_freeze=freeze,
        expected_security=security,
        expected_market_access=acquisition.access_result,
    )
    assert current_shares.status == "eligible"
    assert type(current_shares.evidence_closure) is CurrentShareEvidenceClosureV2
    return graph, freeze, directory, security, acquisition, current_shares


def test_reviewed_file_provider_recomputes_raw_hash_and_binds_named_human(
    sample_payloads,
    monkeypatch,
    tmp_path: Path,
) -> None:
    graph, freeze, directory, security, acquisition, _ = _prepared_inputs(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    assert graph and freeze
    assert acquisition.quote.reviewer_id == "human:mingji"
    assert acquisition.access_result.provider_call_count == 1
    assert acquisition.access_result.receipt is not None
    assert acquisition.access_result.receipt.evidence_mode == "human_reviewed_file"

    acquisition.raw_evidence_file.write_bytes(b"tampered")
    with pytest.raises(ValueError, match="raw evidence SHA"):
        ReviewedFileMarketProvider(
            acquisition.raw_evidence_file.with_name("reviewed-close.json"),
            acquisition.raw_evidence_file,
        ).acquire(acquisition.request)


def test_reviewed_file_provider_rejects_symlinks_and_non_https_sources(
    sample_payloads,
    monkeypatch,
    tmp_path: Path,
) -> None:
    graph, freeze, directory, security, acquisition, _ = _prepared_inputs(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    review = acquisition.raw_evidence_file.with_name("reviewed-close.json")
    raw_link = tmp_path / "reviewed-close-link.raw"
    raw_link.symlink_to(acquisition.raw_evidence_file)
    with pytest.raises(ValueError, match="non-symlink"):
        ReviewedFileMarketProvider(review, raw_link).acquire(acquisition.request)

    payload = json.loads(review.read_text(encoding="utf-8"))
    payload["source_url"] = "http://market.example.invalid/reviewed/acme-close"
    review.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    with pytest.raises(ValueError, match="HTTPS URL"):
        ReviewedFileMarketProvider(review, acquisition.raw_evidence_file).acquire(
            acquisition.request
        )


def test_reviewed_file_provider_rejects_symlinked_ancestor_directories(
    sample_payloads,
    monkeypatch,
    tmp_path: Path,
) -> None:
    _, _, _, _, acquisition, _ = _prepared_inputs(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    real_directory = tmp_path / "reviewed-real"
    real_directory.mkdir()
    real_review = real_directory / "reviewed-close.json"
    real_raw = real_directory / "reviewed-close.raw"
    shutil.copy2(acquisition.raw_evidence_file.with_name("reviewed-close.json"), real_review)
    shutil.copy2(acquisition.raw_evidence_file, real_raw)
    linked_directory = tmp_path / "reviewed-link"
    linked_directory.symlink_to(real_directory, target_is_directory=True)

    with pytest.raises(ValueError, match="path cannot contain a symlink"):
        ReviewedFileMarketProvider(
            linked_directory / real_review.name,
            linked_directory / real_raw.name,
        ).acquire(acquisition.request)


def test_reviewed_file_provider_rejects_world_writable_or_hardlinked_evidence(
    sample_payloads,
    monkeypatch,
    tmp_path: Path,
) -> None:
    _, _, _, _, acquisition, _ = _prepared_inputs(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    review = acquisition.raw_evidence_file.with_name("reviewed-close.json")
    review.chmod(0o666)
    with pytest.raises(ValueError, match="account-owned"):
        ReviewedFileMarketProvider(review, acquisition.raw_evidence_file).acquire(
            acquisition.request
        )
    review.chmod(0o600)

    hardlink = tmp_path / "reviewed-close-hardlink.raw"
    os.link(acquisition.raw_evidence_file, hardlink)
    with pytest.raises(ValueError, match="singly linked"):
        ReviewedFileMarketProvider(review, hardlink).acquire(acquisition.request)


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin extended ACL regression")
def test_reviewed_file_and_authorization_store_reject_extended_acls(
    sample_payloads,
    monkeypatch,
    tmp_path: Path,
) -> None:
    graph, freeze, directory, security, review, raw = _unacquired_inputs(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    subprocess.run(
        ["chmod", "+a", "everyone allow write", str(review)],
        check=True,
    )
    with pytest.raises(ValueError, match="extended ACL"):
        market_provider_module._read_regular_file(
            review,
            label="reviewed market receipt",
            maximum_bytes=market_provider_module._MAX_REVIEW_RECEIPT_BYTES,
        )

    subprocess.run(["chmod", "-a#", "0", str(review)], check=True)
    store_root = (
        market_provider_module._AUTHORIZATION_STATE_BASE / "market-authorizations-v1"
    )
    store_root.mkdir(mode=0o700, parents=True)
    subprocess.run(
        [
            "chmod",
            "+a",
            "everyone allow list,search,add_file,add_subdirectory,delete_child",
            str(store_root),
        ],
        check=True,
    )
    with pytest.raises(ValueError, match="extended ACL"):
        acquire_reviewed_market_reference(
            price_blind_artifact_directory=directory,
            graph=graph,
            expected_freeze=freeze,
            expected_security=security,
            provider=ReviewedFileMarketProvider(review, raw),
            clock=RunClock(
                request_started_at="2026-07-14T01:00:00Z",
                retrieved_at="2026-07-14T01:00:01Z",
            ),
        )


@pytest.mark.parametrize("raw_content_type", (False, [], "text/plain; charset=utf-8"))
def test_reviewed_file_provider_rejects_unregistered_raw_content_types(
    sample_payloads,
    monkeypatch,
    tmp_path: Path,
    raw_content_type,
) -> None:
    _, _, _, _, acquisition, _ = _prepared_inputs(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    review = acquisition.raw_evidence_file.with_name("reviewed-close.json")
    payload = json.loads(review.read_text(encoding="utf-8"))
    payload["raw_content_type"] = raw_content_type
    review.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")

    with pytest.raises(ValueError, match="content type is not registered"):
        ReviewedFileMarketProvider(review, acquisition.raw_evidence_file).acquire(
            acquisition.request
        )


def test_reviewed_file_provider_requires_canonical_utc_receipt_timestamps(
    sample_payloads,
    monkeypatch,
    tmp_path: Path,
) -> None:
    _, _, _, _, acquisition, _ = _prepared_inputs(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    review = acquisition.raw_evidence_file.with_name("reviewed-close.json")
    payload = json.loads(review.read_text(encoding="utf-8"))
    payload["quote_timestamp"] = "2026-06-30T16:00:00-04:00"
    review.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")

    with pytest.raises(ValueError, match="canonical UTC"):
        ReviewedFileMarketProvider(review, acquisition.raw_evidence_file).acquire(
            acquisition.request
        )


def test_reviewed_file_provider_rejects_subclasses_and_duplicate_receipt_fields(
    sample_payloads,
    monkeypatch,
    tmp_path: Path,
) -> None:
    graph, freeze, directory, security, acquisition, _ = _prepared_inputs(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    review = acquisition.raw_evidence_file.with_name("reviewed-close.json")

    class CallerProvider(ReviewedFileMarketProvider):
        pass

    with pytest.raises(ValueError, match="component-owned"):
        acquire_reviewed_market_reference(
            price_blind_artifact_directory=directory,
            graph=graph,
            expected_freeze=freeze,
            expected_security=security,
            provider=CallerProvider(review, acquisition.raw_evidence_file),
            clock=RunClock(
                request_started_at="2026-07-14T01:00:00Z",
                retrieved_at="2026-07-14T01:00:01Z",
            ),
        )

    text = review.read_text(encoding="utf-8")
    review.write_text(text[:-1] + ', "ticker": "ACME"}', encoding="utf-8")
    with pytest.raises(ValueError, match="repeats field ticker"):
        ReviewedFileMarketProvider(review, acquisition.raw_evidence_file).acquire(
            acquisition.request
        )


def test_reviewed_file_receipt_rejects_secret_url_and_bad_chronology(
    sample_payloads,
    monkeypatch,
    tmp_path: Path,
) -> None:
    graph, freeze, directory, security, acquisition, _ = _prepared_inputs(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    review = acquisition.raw_evidence_file.with_name("reviewed-close.json")
    payload = json.loads(review.read_text(encoding="utf-8"))
    payload["source_url"] = "https://market.example.invalid/close?token=secret"
    review.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    with pytest.raises(ValueError, match="credential"):
        ReviewedFileMarketProvider(review, acquisition.raw_evidence_file).acquire(
            acquisition.request
        )



def test_reviewed_file_receipt_rejects_bad_chronology_before_first_consumption(
    sample_payloads,
    monkeypatch,
    tmp_path: Path,
) -> None:
    graph, freeze, directory, security, review, raw = _unacquired_inputs(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    payload = json.loads(review.read_text(encoding="utf-8"))
    payload["reviewed_at"] = "2026-07-14T00:15:00Z"
    review.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    with pytest.raises(ValueError, match="chronology"):
        acquire_reviewed_market_reference(
            price_blind_artifact_directory=directory,
            graph=graph,
            expected_freeze=freeze,
            expected_security=security,
            provider=ReviewedFileMarketProvider(review, raw),
            clock=RunClock(
                request_started_at="2026-07-14T01:00:00Z",
                retrieved_at="2026-07-14T01:00:01Z",
            ),
        )


def test_reviewed_file_receipt_rejects_retrieval_before_session_close(
    sample_payloads,
    monkeypatch,
    tmp_path: Path,
) -> None:
    graph, freeze, directory, security, review, raw = _unacquired_inputs(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    payload = json.loads(review.read_text(encoding="utf-8"))
    payload["source_retrieved_at"] = "2026-06-30T19:59:59Z"
    review.write_text(
        json.dumps(payload, sort_keys=True),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="chronology"):
        acquire_reviewed_market_reference(
            price_blind_artifact_directory=directory,
            graph=graph,
            expected_freeze=freeze,
            expected_security=security,
            provider=ReviewedFileMarketProvider(review, raw),
            clock=RunClock(
                request_started_at="2026-07-14T01:00:00Z",
                retrieved_at="2026-07-14T01:00:01Z",
            ),
        )


@pytest.mark.parametrize("fifo_name", ("reviewed-close.json", "reviewed-close.raw"))
def test_reviewed_market_evidence_fifo_is_rejected_without_blocking(
    tmp_path: Path,
    fifo_name: str,
) -> None:
    fifo = tmp_path / fifo_name
    os.mkfifo(fifo)
    script = (
        "from pathlib import Path; "
        "from owner_research.valuation_market_provider import _read_regular_file; "
        f"_read_regular_file(Path({str(fifo)!r}), label='market evidence', "
        "maximum_bytes=65536)"
    )
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=2,
        check=False,
    )
    assert completed.returncode != 0
    assert "regular non-symlink file" in completed.stderr


def test_reviewed_file_provider_registration_is_component_locked(
    sample_payloads,
    monkeypatch,
    tmp_path: Path,
) -> None:
    _, _, _, _, acquisition, _ = _prepared_inputs(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    assert acquisition.access_result.receipt is not None
    lock = json.loads((ROOT / "component-lock.json").read_text(encoding="utf-8"))
    lock["market_access_authority"]["reviewed_file_provider"]["adapter_sha256"] = "0" * 64
    drifted = tmp_path / "component-lock-drifted.json"
    drifted.write_text(json.dumps(lock, sort_keys=True), encoding="utf-8")
    with pytest.raises(ValueError, match="registration drifted"):
        reviewed_file_authority_hashes(
            drifted,
            calendar_dataset_sha256=(
                acquisition.access_result.receipt.calendar_dataset_sha256
            ),
        )


def test_reviewed_file_authorization_is_single_use(
    sample_payloads,
    monkeypatch,
    tmp_path: Path,
) -> None:
    graph, freeze, directory, security, acquisition, current_shares = _prepared_inputs(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    prepared = build_reviewed_market_reference_snapshot(
        price_blind_artifact_directory=directory,
        graph=graph,
        expected_freeze=freeze,
        expected_security=security,
        acquisition=acquisition,
        current_shares=current_shares,
    )
    review = acquisition.raw_evidence_file.with_name("reviewed-close.json")
    with pytest.raises(ValueError, match=r"already (?:reserved or )?consumed"):
        acquire_reviewed_market_reference(
            price_blind_artifact_directory=directory,
            graph=prepared.graph,
            expected_freeze=freeze,
            expected_security=security,
            provider=ReviewedFileMarketProvider(review, acquisition.raw_evidence_file),
            clock=RunClock(
                request_started_at="2026-07-14T01:00:00Z",
                retrieved_at="2026-07-14T01:00:01Z",
            ),
        )


def test_reviewed_file_authorization_cannot_fork_from_the_same_root(
    sample_payloads,
    monkeypatch,
    tmp_path: Path,
) -> None:
    graph, freeze, directory, security, acquisition, current_shares = _prepared_inputs(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    alternate_raw = tmp_path / "alternate-reviewed-close.raw"
    alternate_raw.write_bytes(b"ACME reviewed regular-session close 60.125\n")
    alternate_review = tmp_path / "alternate-reviewed-close.json"
    alternate_payload = json.loads(acquisition.review_file.read_text(encoding="utf-8"))
    alternate_payload["close_decimal"] = "60.125"
    alternate_payload["raw_evidence_sha256"] = hashlib.sha256(
        alternate_raw.read_bytes()
    ).hexdigest()
    alternate_payload["source_locator"] = "independent reviewed daily close row 1"
    alternate_review.write_text(
        json.dumps(alternate_payload, sort_keys=True),
        encoding="utf-8",
    )

    copied_directory = tmp_path / "copied-price-blind"
    shutil.copytree(directory, copied_directory)
    with pytest.raises(ValueError, match=r"already (?:reserved or )?consumed"):
        acquire_reviewed_market_reference(
            price_blind_artifact_directory=copied_directory,
            graph=graph,
            expected_freeze=freeze,
            expected_security=security,
            provider=ReviewedFileMarketProvider(alternate_review, alternate_raw),
            clock=RunClock(
                request_started_at="2026-07-14T01:00:00Z",
                retrieved_at="2026-07-14T01:00:01Z",
            ),
        )

    prepared = build_reviewed_market_reference_snapshot(
        price_blind_artifact_directory=directory,
        graph=graph,
        expected_freeze=freeze,
        expected_security=security,
        acquisition=acquisition,
        current_shares=current_shares,
    )
    assert prepared.snapshot.quote_price_decimal == "50.125"
    prepared.graph.validate()


def test_market_authorization_records_have_canonical_ids_and_sealed_permissions(
    sample_payloads,
    monkeypatch,
    tmp_path: Path,
) -> None:
    graph, _, _, _, acquisition, _ = _prepared_inputs(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    reservation = acquisition.authorization_reservation
    consumption = acquisition.authorization_consumption

    with pytest.raises(ValueError, match="reservation identity"):
        replace(reservation, reservation_id="market-authorization-reservation:forged")
    with pytest.raises(ValueError, match="consumption identity"):
        replace(consumption, consumption_id="market-authorization-consumption:forged")

    authorization_directory, reservation_path, consumption_path, _, _ = (
        market_provider_module._authorization_record_paths(
            graph.component_lock_path,
            authorization_handoff_id=reservation.authorization_handoff_id,
            authorization_handoff_fingerprint=(
                reservation.authorization_handoff_fingerprint
            ),
            create_store=False,
        )
    )
    assert stat.S_IMODE(authorization_directory.lstat().st_mode) == 0o500
    assert stat.S_IMODE(reservation_path.lstat().st_mode) == 0o400
    assert stat.S_IMODE(consumption_path.lstat().st_mode) == 0o400
    reservation_path.chmod(0o600)
    with pytest.raises(ValueError, match="private regular file"):
        market_provider_module._verify_authorization_consumption(
            graph.component_lock_path,
            reservation,
            consumption,
        )


def test_market_authorization_store_rejects_symlinked_ancestor_before_provider_read(
    sample_payloads,
    monkeypatch,
    tmp_path: Path,
) -> None:
    graph, freeze, directory, security, _, _ = _unacquired_inputs(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    real_state = tmp_path / "real-state"
    real_state.mkdir()
    linked_state = tmp_path / "linked-state"
    linked_state.symlink_to(real_state, target_is_directory=True)
    monkeypatch.setattr(
        market_provider_module,
        "_AUTHORIZATION_STATE_BASE",
        linked_state / "owner-research",
    )

    with pytest.raises(ValueError, match="cannot contain a symlink"):
        acquire_reviewed_market_reference(
            price_blind_artifact_directory=directory,
            graph=graph,
            expected_freeze=freeze,
            expected_security=security,
            provider=ReviewedFileMarketProvider(
                tmp_path / "must-not-be-read.json",
                tmp_path / "must-not-be-read.raw",
            ),
            clock=RunClock(
                request_started_at="2026-07-14T01:00:00Z",
                retrieved_at="2026-07-14T01:00:01Z",
            ),
        )


def test_market_authorization_store_rejects_writable_parent_before_provider_read(
    sample_payloads,
    monkeypatch,
    tmp_path: Path,
) -> None:
    graph, freeze, directory, security, _, _ = _unacquired_inputs(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    unsafe_parent = tmp_path / "unsafe-state-parent"
    unsafe_parent.mkdir(mode=0o700)
    unsafe_parent.chmod(0o777)
    monkeypatch.setattr(
        market_provider_module,
        "_AUTHORIZATION_STATE_BASE",
        unsafe_parent / "owner-research",
    )

    with pytest.raises(ValueError, match="group/other writable"):
        acquire_reviewed_market_reference(
            price_blind_artifact_directory=directory,
            graph=graph,
            expected_freeze=freeze,
            expected_security=security,
            provider=ReviewedFileMarketProvider(
                tmp_path / "must-not-be-read.json",
                tmp_path / "must-not-be-read.raw",
            ),
            clock=RunClock(
                request_started_at="2026-07-14T01:00:00Z",
                retrieved_at="2026-07-14T01:00:01Z",
            ),
        )


def test_market_authorization_store_accepts_root_owned_sticky_temp_anchor() -> None:
    sticky_root = Path("/private/tmp") if Path("/private/tmp").is_dir() else Path("/tmp")
    metadata = sticky_root.stat()
    if metadata.st_uid != 0 or not metadata.st_mode & stat.S_ISVTX:
        pytest.skip("platform has no root-owned sticky temporary anchor")
    sandbox = Path(tempfile.mkdtemp(prefix="owner-research-auth-", dir=sticky_root))
    try:
        created = market_provider_module._private_authorization_directory(
            sandbox / "state" / "market-authorizations-v1",
            create=True,
        )
        assert created.st_uid == os.getuid()
        assert not created.st_mode & 0o077
    finally:
        shutil.rmtree(sandbox)


def test_authorization_namespace_is_durable_before_provider_read(
    sample_payloads,
    monkeypatch,
    tmp_path: Path,
) -> None:
    graph, freeze, directory, security, review, raw = _unacquired_inputs(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    state_base = market_provider_module._AUTHORIZATION_STATE_BASE
    namespace = state_base / "market-authorizations-v1"
    namespace.mkdir(mode=0o700, parents=True)
    state_base.chmod(0o700)
    namespace.chmod(0o700)
    fsynced_directories: list[tuple[int, int]] = []
    original_flush = market_provider_module._durable_flush
    original_acquire = ReviewedFileMarketProvider.acquire

    def tracked_flush(descriptor: int) -> None:
        metadata = os.fstat(descriptor)
        if stat.S_ISDIR(metadata.st_mode):
            fsynced_directories.append((metadata.st_dev, metadata.st_ino))
        original_flush(descriptor)

    def observed_acquire(self, request):
        namespace_metadata = namespace.stat()
        state_base_metadata = state_base.stat()
        authorization_directories = tuple(
            item for item in namespace.iterdir() if item.is_dir()
        )
        assert len(authorization_directories) == 1
        authorization_metadata = authorization_directories[0].stat()
        assert (namespace_metadata.st_dev, namespace_metadata.st_ino) in (
            fsynced_directories
        )
        assert (state_base_metadata.st_dev, state_base_metadata.st_ino) in (
            fsynced_directories
        )
        assert (authorization_metadata.st_dev, authorization_metadata.st_ino) in (
            fsynced_directories
        )
        return original_acquire(self, request)

    monkeypatch.setattr(market_provider_module, "_durable_flush", tracked_flush)
    monkeypatch.setattr(ReviewedFileMarketProvider, "acquire", observed_acquire)
    acquisition = acquire_reviewed_market_reference(
        price_blind_artifact_directory=directory,
        graph=graph,
        expected_freeze=freeze,
        expected_security=security,
        provider=ReviewedFileMarketProvider(review, raw),
        clock=RunClock(
            request_started_at="2026-07-14T01:00:00Z",
            retrieved_at="2026-07-14T01:00:01Z",
        ),
    )
    assert acquisition.access_result.status == "eligible"


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin full-flush regression")
def test_authorization_durable_flush_uses_f_fullfsync(
    monkeypatch,
    tmp_path: Path,
) -> None:
    path = tmp_path / "durability-probe"
    path.write_bytes(b"probe")
    descriptor = os.open(path, os.O_RDONLY)
    calls: list[tuple[int, int]] = []

    def tracked_fcntl(target_descriptor: int, command: int):
        calls.append((target_descriptor, command))
        return 0

    monkeypatch.setattr(market_provider_module.fcntl, "fcntl", tracked_fcntl)
    try:
        market_provider_module._durable_flush(descriptor)
    finally:
        os.close(descriptor)
    assert calls == [(descriptor, market_provider_module.fcntl.F_FULLFSYNC)]


def test_market_authorization_store_root_ignores_mutable_home_environment(
    tmp_path: Path,
) -> None:
    fake_home = tmp_path / "caller-controlled-home"
    environment = os.environ.copy()
    environment["HOME"] = str(fake_home)
    script = (
        "from owner_research.valuation_market_provider import "
        "_AUTHORIZATION_STATE_BASE; print(_AUTHORIZATION_STATE_BASE)"
    )
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    expected = (
        Path(pwd.getpwuid(os.getuid()).pw_dir)
        / ".local"
        / "state"
        / "owner-research"
    )
    assert Path(completed.stdout.strip()) == expected
    assert fake_home not in Path(completed.stdout.strip()).parents


def test_second_authorization_is_blocked_before_alternate_provider_files_are_read(
    sample_payloads,
    monkeypatch,
    tmp_path: Path,
) -> None:
    graph, freeze, directory, security, _, _ = _prepared_inputs(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    copied_directory = tmp_path / "copied-price-blind-unreadable-provider"
    shutil.copytree(directory, copied_directory)

    with pytest.raises(ValueError, match=r"already (?:reserved or )?consumed"):
        acquire_reviewed_market_reference(
            price_blind_artifact_directory=copied_directory,
            graph=graph,
            expected_freeze=freeze,
            expected_security=security,
            provider=ReviewedFileMarketProvider(
                tmp_path / "missing-alternate-review.json",
                tmp_path / "missing-alternate-raw.bin",
            ),
            clock=RunClock(
                request_started_at="2026-07-14T01:00:00Z",
                retrieved_at="2026-07-14T01:00:01Z",
            ),
        )


def test_reviewed_file_rejects_publication_before_the_trading_date(
    sample_payloads,
    monkeypatch,
    tmp_path: Path,
) -> None:
    graph, freeze, directory, security, review, raw = _unacquired_inputs(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    payload = json.loads(review.read_text(encoding="utf-8"))
    payload["source_published_date"] = "2026-06-29"
    review.write_text(
        json.dumps(payload, sort_keys=True),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="chronology"):
        acquire_reviewed_market_reference(
            price_blind_artifact_directory=directory,
            graph=graph,
            expected_freeze=freeze,
            expected_security=security,
            provider=ReviewedFileMarketProvider(review, raw),
            clock=RunClock(
                request_started_at="2026-07-14T01:00:00Z",
                retrieved_at="2026-07-14T01:00:01Z",
            ),
        )


def test_reviewed_file_rejects_publication_after_the_data_cutoff(
    sample_payloads,
    monkeypatch,
    tmp_path: Path,
) -> None:
    graph, freeze, directory, security, review, raw = _unacquired_inputs(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    payload = json.loads(review.read_text(encoding="utf-8"))
    payload["source_published_date"] = "2026-07-01"
    review.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")

    with pytest.raises(ValueError, match="chronology"):
        acquire_reviewed_market_reference(
            price_blind_artifact_directory=directory,
            graph=graph,
            expected_freeze=freeze,
            expected_security=security,
            provider=ReviewedFileMarketProvider(review, raw),
            clock=RunClock(
                request_started_at="2026-07-14T01:00:00Z",
                retrieved_at="2026-07-14T01:00:01Z",
            ),
        )


def test_exact_decimal_product_is_independent_of_default_precision() -> None:
    assert format(
        exact_decimal_product("9999999999999999999999999999.9", "10"),
        "f",
    ) == "99999999999999999999999999999.0"


def test_market_vertical_slice_builds_validated_release_candidate_snapshot(
    sample_payloads,
    monkeypatch,
    tmp_path: Path,
) -> None:
    graph, freeze, directory, security, acquisition, current_shares = _prepared_inputs(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    result = build_reviewed_market_reference_snapshot(
        price_blind_artifact_directory=directory,
        graph=graph,
        expected_freeze=freeze,
        expected_security=security,
        acquisition=acquisition,
        current_shares=current_shares,
    )
    assert result.snapshot.schema_version == "4.0.0"
    assert result.snapshot.source_authority_kind == "human_reviewed_file"
    assert result.snapshot.usage_scope == "release_candidate"
    assert result.snapshot.quote_price_decimal == "50.125"
    assert result.snapshot.market_equity["value_decimal"] == "5012500000.000"
    assert result.market_equity_calculation.input_assumption_ids == ()
    result.graph.validate()


def test_snapshot_canonicalizes_scientific_notation_share_values(
    sample_payloads,
    monkeypatch,
    tmp_path: Path,
) -> None:
    graph, freeze, directory, security, acquisition, current_shares = _prepared_inputs(
        sample_payloads,
        monkeypatch,
        tmp_path,
        current_share_value=1e20,
    )

    result = build_reviewed_market_reference_snapshot(
        price_blind_artifact_directory=directory,
        graph=graph,
        expected_freeze=freeze,
        expected_security=security,
        acquisition=acquisition,
        current_shares=current_shares,
    )

    assert result.snapshot.share_basis[
        "current_common_shares_outstanding_decimal"
    ] == "100000000000000000000"
    assert result.snapshot.market_equity["value_decimal"] == "5012500000000000000000.000"
    result.graph.validate()


def test_snapshot_preserves_large_integer_share_precision(
    sample_payloads,
    monkeypatch,
    tmp_path: Path,
) -> None:
    shares = 123456789012345678901234567896
    graph, freeze, directory, security, acquisition, current_shares = _prepared_inputs(
        sample_payloads,
        monkeypatch,
        tmp_path,
        current_share_value=shares,
    )

    result = build_reviewed_market_reference_snapshot(
        price_blind_artifact_directory=directory,
        graph=graph,
        expected_freeze=freeze,
        expected_security=security,
        acquisition=acquisition,
        current_shares=current_shares,
    )

    assert result.snapshot.market_equity["value_decimal"] == (
        "6188271549243827154924382715787.000"
    )
    result.graph.validate()


def test_reviewed_snapshot_binds_raw_content_type_to_the_reviewed_receipt(
    sample_payloads,
    monkeypatch,
    tmp_path: Path,
) -> None:
    graph, freeze, directory, security, acquisition, current_shares = _prepared_inputs(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    prepared = build_reviewed_market_reference_snapshot(
        price_blind_artifact_directory=directory,
        graph=graph,
        expected_freeze=freeze,
        expected_security=security,
        acquisition=acquisition,
        current_shares=current_shares,
    )
    raw = dict(prepared.snapshot.raw_evidence)
    raw["content_type"] = "application/pdf"
    forged_snapshot = _resign_market_snapshot(
        prepared.graph,
        prepared.snapshot,
        raw_evidence=raw,
    )
    forged_graph = replace_graph(
        prepared.graph,
        market_reference_snapshots=(forged_snapshot,),
    )

    with pytest.raises(ContractGraphError):
        forged_graph.validate()


def test_reviewed_snapshot_identity_is_builder_owned(
    sample_payloads,
    monkeypatch,
    tmp_path: Path,
) -> None:
    graph, freeze, directory, security, acquisition, current_shares = _prepared_inputs(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    prepared = build_reviewed_market_reference_snapshot(
        price_blind_artifact_directory=directory,
        graph=graph,
        expected_freeze=freeze,
        expected_security=security,
        acquisition=acquisition,
        current_shares=current_shares,
    )
    forged_snapshot = _resign_market_snapshot(
        prepared.graph,
        prepared.snapshot,
        snapshot_id=f"{prepared.snapshot.snapshot_id}:caller-renamed",
    )
    forged_graph = replace_graph(
        prepared.graph,
        market_reference_snapshots=(forged_snapshot,),
    )

    with pytest.raises(ContractGraphError, match="Snapshot identity"):
        forged_graph.validate()


def test_reviewed_snapshot_binds_the_exact_source_document_projection(
    sample_payloads,
    monkeypatch,
    tmp_path: Path,
) -> None:
    graph, freeze, directory, security, acquisition, current_shares = _prepared_inputs(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    prepared = build_reviewed_market_reference_snapshot(
        price_blind_artifact_directory=directory,
        graph=graph,
        expected_freeze=freeze,
        expected_security=security,
        acquisition=acquisition,
        current_shares=current_shares,
    )
    forged_source = replace(
        prepared.market_source,
        document_type="press-release",
        period={"start": "2026-01-01", "end": "2026-06-30"},
        source_url="https://other.example.invalid/unreviewed/source",
    )
    forged_graph = replace_graph(
        prepared.graph,
        documents=tuple(
            forged_source if item.document_id == forged_source.document_id else item
            for item in prepared.graph.documents
        ),
    )
    forged_snapshot = _resign_market_snapshot(
        forged_graph,
        prepared.snapshot,
    )
    forged_graph = replace_graph(
        forged_graph,
        market_reference_snapshots=(forged_snapshot,),
    )

    with pytest.raises(ContractGraphError):
        forged_graph.validate()


def test_reviewed_snapshot_binds_quote_fact_semantics_and_identity(
    sample_payloads,
    monkeypatch,
    tmp_path: Path,
) -> None:
    graph, freeze, directory, security, acquisition, current_shares = _prepared_inputs(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    prepared = build_reviewed_market_reference_snapshot(
        price_blind_artifact_directory=directory,
        graph=graph,
        expected_freeze=freeze,
        expected_security=security,
        acquisition=acquisition,
        current_shares=current_shares,
    )
    forged_quote = replace(prepared.quote_fact, concept="revenue")
    facts = {
        item.fact_id: (forged_quote if item.fact_id == forged_quote.fact_id else item)
        for item in prepared.graph.facts
    }
    forged_calculation = build_calculation_result(
        prepared.market_equity_calculation.to_dict(),
        facts=facts,
        assumptions={},
        calculations={},
    )
    forged_graph = replace_graph(
        prepared.graph,
        facts=tuple(facts.values()),
        calculations=tuple(
            forged_calculation
            if item.calculation_id == forged_calculation.calculation_id
            else item
            for item in prepared.graph.calculations
        ),
    )
    forged_snapshot = _resign_market_snapshot(forged_graph, prepared.snapshot)
    forged_graph = replace_graph(
        forged_graph,
        market_reference_snapshots=(forged_snapshot,),
    )

    with pytest.raises(ContractGraphError):
        forged_graph.validate()


def test_reviewed_snapshot_binds_market_equity_calculator_identity_and_period(
    sample_payloads,
    monkeypatch,
    tmp_path: Path,
) -> None:
    graph, freeze, directory, security, acquisition, current_shares = _prepared_inputs(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    prepared = build_reviewed_market_reference_snapshot(
        price_blind_artifact_directory=directory,
        graph=graph,
        expected_freeze=freeze,
        expected_security=security,
        acquisition=acquisition,
        current_shares=current_shares,
    )
    calculation_payload = prepared.market_equity_calculation.to_dict()
    calculation_payload.update(
        {
            "calculator_id": "unreviewed-calculator",
            "calculator_version": "999.0.0",
            "code_sha256": "0" * 64,
            "period": {"start": "2026-01-01", "end": "2026-06-30"},
            "generated_at": "2026-12-31T23:59:59Z",
        }
    )
    facts = {item.fact_id: item for item in prepared.graph.facts}
    forged_calculation = build_calculation_result(
        calculation_payload,
        facts=facts,
        assumptions={},
        calculations={},
    )
    forged_graph = replace_graph(
        prepared.graph,
        calculations=tuple(
            forged_calculation
            if item.calculation_id == forged_calculation.calculation_id
            else item
            for item in prepared.graph.calculations
        ),
    )
    forged_snapshot = _resign_market_snapshot(forged_graph, prepared.snapshot)
    forged_graph = replace_graph(
        forged_graph,
        market_reference_snapshots=(forged_snapshot,),
    )

    with pytest.raises(ContractGraphError):
        forged_graph.validate()


def test_reviewed_snapshot_rejects_market_equity_period_dependencies(
    sample_payloads,
    monkeypatch,
    tmp_path: Path,
) -> None:
    graph, freeze, directory, security, acquisition, current_shares = _prepared_inputs(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    prepared = build_reviewed_market_reference_snapshot(
        price_blind_artifact_directory=directory,
        graph=graph,
        expected_freeze=freeze,
        expected_security=security,
        acquisition=acquisition,
        current_shares=current_shares,
    )
    period = prepared.graph.periods[0]
    payload = prepared.market_equity_calculation.to_dict()
    payload["input_period_ids"] = [period.period_id]
    facts = {item.fact_id: item for item in prepared.graph.facts}
    forged_calculation = build_calculation_result(
        payload,
        facts=facts,
        assumptions={},
        calculations={},
        periods={period.period_id: period},
    )
    forged_graph = replace_graph(
        prepared.graph,
        calculations=tuple(
            forged_calculation
            if item.calculation_id == forged_calculation.calculation_id
            else item
            for item in prepared.graph.calculations
        ),
    )
    forged_snapshot = _resign_market_snapshot(forged_graph, prepared.snapshot)
    forged_graph = replace_graph(
        forged_graph,
        market_reference_snapshots=(forged_snapshot,),
    )

    with pytest.raises(ContractGraphError, match="CalculationResult is not canonical"):
        forged_graph.validate()


def test_v2_rollforward_builds_snapshot_and_validates_the_final_graph(
    sample_payloads,
    monkeypatch,
    tmp_path: Path,
) -> None:
    graph, freeze, directory, security, acquisition, current_shares = (
        _v2_rollforward_inputs(sample_payloads, monkeypatch, tmp_path)
    )
    assert current_shares.output_fact is not None
    assert current_shares.output_fact.value == 95_000_000
    assert current_shares.canonical_rollforward is not None
    assert len(current_shares.canonical_rollforward.numeric_consumptions) == 1
    assert len(current_shares.evidence_closure.materializations[0].members) == 2

    prepared = build_reviewed_market_reference_snapshot(
        price_blind_artifact_directory=directory,
        graph=graph,
        expected_freeze=freeze,
        expected_security=security,
        acquisition=acquisition,
        current_shares=current_shares,
    )

    assert prepared.snapshot.share_basis[
        "current_common_shares_outstanding_decimal"
    ] == "95000000"
    assert prepared.snapshot.market_equity["value_decimal"] == "4761875000.000"
    assert prepared.market_equity_calculation.input_fact_ids == (
        prepared.quote_fact.fact_id,
        current_shares.output_fact.fact_id,
    )
    prepared.graph.validate()


def test_snapshot_builder_replays_and_rejects_a_forged_acquisition_quote(
    sample_payloads,
    monkeypatch,
    tmp_path: Path,
) -> None:
    graph, freeze, directory, security, acquisition, current_shares = _prepared_inputs(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    forged = replace(
        acquisition,
        quote=replace(acquisition.quote, close_decimal="999"),
    )

    with pytest.raises(ValueError, match="does not replay"):
        build_reviewed_market_reference_snapshot(
            price_blind_artifact_directory=directory,
            graph=graph,
            expected_freeze=freeze,
            expected_security=security,
            acquisition=forged,
            current_shares=current_shares,
        )


def test_contract_graph_replays_and_rejects_forged_reviewed_quote_context(
    sample_payloads,
    monkeypatch,
    tmp_path: Path,
) -> None:
    graph, freeze, directory, security, acquisition, current_shares = _prepared_inputs(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    prepared = build_reviewed_market_reference_snapshot(
        price_blind_artifact_directory=directory,
        graph=graph,
        expected_freeze=freeze,
        expected_security=security,
        acquisition=acquisition,
        current_shares=current_shares,
    )
    context = prepared.graph.market_reference_validation_contexts[0]
    with pytest.raises(ValueError, match="lacks replayable provider evidence"):
        replace(
            context,
            reviewed_quote=replace(context.reviewed_quote, close_decimal="999"),
        )


def test_snapshot_uses_current_shares_not_eps_weighted_average_shares(
    sample_payloads,
    monkeypatch,
    tmp_path: Path,
) -> None:
    graph, freeze, directory, security, acquisition, current_shares = _prepared_inputs(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    current_fact = current_shares.output_fact
    assert current_fact is not None
    weighted_average = Fact(
        schema_version="2.0.0",
        fact_id="fact:acme:weighted-average-diluted-shares:2026-h1",
        issuer_id=current_fact.issuer_id,
        concept="weighted_average_diluted_shares",
        value_type="number",
        value=125_000_000,
        unit="shares",
        currency=None,
        period={"start": "2026-01-01", "end": current_fact.period["end"]},
        source_document_id=current_fact.source_document_id,
        source_locator="eps denominator for the 2026 first half",
        derivation=None,
        parent_fact_ids=(),
        confidence="high",
    )
    graph = replace_graph(graph, facts=(*graph.facts, weighted_average))

    prepared = build_reviewed_market_reference_snapshot(
        price_blind_artifact_directory=directory,
        graph=graph,
        expected_freeze=freeze,
        expected_security=security,
        acquisition=acquisition,
        current_shares=current_shares,
    )

    assert current_fact.value == 100_000_000
    assert weighted_average.value == 125_000_000
    assert prepared.snapshot.share_basis["shares_outstanding_fact_id"] == current_fact.fact_id
    assert prepared.market_equity_calculation.input_fact_ids == (
        prepared.quote_fact.fact_id,
        current_fact.fact_id,
    )
    assert prepared.snapshot.market_equity["value_decimal"] == "5012500000.000"
    prepared.graph.validate()


def test_human_reviewed_snapshot_cannot_masquerade_as_production_vendor_evidence(
    sample_payloads,
    monkeypatch,
    tmp_path: Path,
) -> None:
    graph, freeze, directory, security, acquisition, current_shares = _prepared_inputs(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    prepared = build_reviewed_market_reference_snapshot(
        price_blind_artifact_directory=directory,
        graph=graph,
        expected_freeze=freeze,
        expected_security=security,
        acquisition=acquisition,
        current_shares=current_shares,
    )
    forged_snapshot = resign_snapshot(
        prepared.snapshot,
        source_authority_kind="governed_vendor",
        evidence_mode="governed_vendor",
        usage_scope="production",
    )
    forged_graph = replace_graph(
        prepared.graph,
        market_reference_snapshots=(forged_snapshot,),
    )

    with pytest.raises(ContractGraphError):
        forged_graph.validate()


def test_human_reviewed_receipt_and_snapshot_cannot_jointly_masquerade_as_vendor(
    sample_payloads,
    monkeypatch,
    tmp_path: Path,
) -> None:
    graph, freeze, directory, security, acquisition, current_shares = _prepared_inputs(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    prepared = build_reviewed_market_reference_snapshot(
        price_blind_artifact_directory=directory,
        graph=graph,
        expected_freeze=freeze,
        expected_security=security,
        acquisition=acquisition,
        current_shares=current_shares,
    )
    context = prepared.graph.market_reference_validation_contexts[0]
    forged_governed = replace(
        context.market_access_result.receipt,
        evidence_mode="governed_vendor",
    )
    forged_access = replace(
        context.market_access_result,
        receipt=forged_governed,
    )
    forged_quote = replace(context.reviewed_quote, authority_kind="governed_vendor")
    forged_consumption = replace(
        context.authorization_consumption,
        market_access_result_fingerprint=forged_access.fingerprint,
        quote_fingerprint=forged_quote.fingerprint,
    )
    with pytest.raises(ValueError, match="cannot carry reviewed-file replay authority"):
        replace(
            context,
            market_access_result=forged_access,
            reviewed_quote=forged_quote,
            authorization_consumption=forged_consumption,
        )


def test_reviewed_file_quote_is_not_a_command_line_price(
    sample_payloads,
    monkeypatch,
    tmp_path: Path,
) -> None:
    graph, freeze, _, security, acquisition, current_shares = _prepared_inputs(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    signature = __import__("inspect").signature(build_reviewed_market_reference_snapshot)
    assert "quote_price" not in signature.parameters
    assert "market_equity_value" not in signature.parameters
    assert not hasattr(__import__("owner_research"), "build_reviewed_market_reference_snapshot")
    assert graph and freeze and security and acquisition and current_shares


def test_prepare_owner_valuation_replays_price_blind_freeze_before_market(
    sample_payloads,
    monkeypatch,
    tmp_path: Path,
) -> None:
    graph, freeze, directory, security = _security_context(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    graph, freeze = _rebind_freeze_to_phase5c_authority(graph, freeze)
    security = compile_security_identity(
        graph=graph,
        expected_freeze=freeze,
        proposal=security.proposal,
    )
    formal_source = graph.documents[0]
    facts = (
        Fact(
            schema_version="2.0.0",
            fact_id=PHASE5C_DILUTED_ROOT_ID,
            issuer_id="issuer:acme",
            concept="diluted_shares",
            value_type="number",
            value=100_000_000,
            unit="shares",
            currency=None,
            period={"start": None, "end": "2025-12-31"},
            source_document_id=formal_source.document_id,
            source_locator="phase5c:reviewed-diluted-shares",
            derivation=None,
            parent_fact_ids=(),
            confidence="high",
        ),
        Fact(
            schema_version="2.0.0",
            fact_id="fact:acme:current-common-shares:2026-06-30",
            issuer_id="issuer:acme",
            concept="common_shares_outstanding",
            value_type="number",
            value=100_000_000,
            unit="shares",
            currency=None,
            period={"start": None, "end": "2026-06-30"},
            source_document_id=formal_source.document_id,
            source_locator="reviewed quote-date current common shares",
            derivation=None,
            parent_fact_ids=(),
            confidence="high",
        ),
    )
    graph = replace_graph(
        graph,
        facts=graph.facts + facts,
        valuation_handoffs=freeze.handoffs,
        component_lock_path=ROOT / "component-lock.json",
    )
    write_price_blind_input_artifact(graph, freeze, output_directory=directory, overwrite=True)
    review, raw = _reviewed_market_files(tmp_path, security, freeze)
    result = prepare_owner_valuation(
        graph=graph,
        price_blind_artifact_directory=directory,
        expected_freeze=freeze,
        expected_security=security,
        market_provider=ReviewedFileMarketProvider(review, raw),
        clock=RunClock(
            request_started_at="2026-07-14T01:00:00Z",
            retrieved_at="2026-07-14T01:00:01Z",
        ),
    )
    assert result.status == "prepared"
    assert result.prepared_market_reference is not None
    assert result.prepared_market_reference.snapshot.usage_scope == "release_candidate"
