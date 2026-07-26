from __future__ import annotations

import copy
from pathlib import Path

import httpx
import pytest

from owner_research.contracts import contract_from_dict
from owner_research.extraction import extract_ixbrl_candidates, parse_displayed_number, table_matrix
from owner_research.sec import (
    ContentAddressedCache,
    SecClient,
    SecIntakeError,
    build_filing_artifact,
    normalize_cik,
    select_latest_filings,
    validate_sec_url,
)

ROOT = Path(__file__).parents[1]
FIXTURES = ROOT / "evals" / "golden" / "sec"


def _submissions() -> dict:
    return {
        "filings": {
            "recent": {
                "accessionNumber": [
                    "0001018724-26-000003",
                    "0001018724-26-000002",
                    "0001018724-25-000001",
                ],
                "form": ["10-Q", "10-K/A", "10-K"],
                "filingDate": ["2026-05-02", "2026-02-20", "2025-02-10"],
                "reportDate": ["2026-03-31", "2025-12-31", "2024-12-31"],
                "primaryDocument": ["q1.html", "annual-amended.html", "annual.html"],
            }
        }
    }


def test_sec_intake_rejects_missing_identity_rate_and_non_sec_url(tmp_path: Path) -> None:
    with pytest.raises(SecIntakeError, match="USER_AGENT"):
        SecClient(user_agent="", cache=ContentAddressedCache(tmp_path / "cache"))
    with pytest.raises(SecIntakeError, match="at most 10"):
        SecClient(
            user_agent="owner-research test",
            requests_per_second=10.1,
            cache=ContentAddressedCache(tmp_path / "cache"),
        )
    with pytest.raises(SecIntakeError, match="only HTTPS sec.gov"):
        validate_sec_url("https://example.com/filing.html")
    assert normalize_cik(1018724) == "0001018724"


def test_sec_client_sends_identity_and_caches_content(tmp_path: Path) -> None:
    observed = {}

    def handler(request: httpx.Request) -> httpx.Response:
        observed["user_agent"] = request.headers["User-Agent"]
        return httpx.Response(200, content=b'{"ok": true}')

    cache = ContentAddressedCache(tmp_path / "cache")
    with SecClient(
        user_agent="owner-research/0.3 test@example.invalid",
        cache=cache,
        transport=httpx.MockTransport(handler),
    ) as client:
        assert client.get_json("https://data.sec.gov/test.json") == {"ok": True}
    assert observed["user_agent"].startswith("owner-research/0.3")
    assert len(list((tmp_path / "cache").glob("*/*"))) == 1


def test_filing_selection_obeys_cutoff_and_prefers_amendment() -> None:
    selected = select_latest_filings(_submissions(), cik="1018724", cutoff_date="2026-07-11")
    assert selected["10-K"].form == "10-K/A"
    assert selected["10-Q"].report_period == "2026-03-31"
    with pytest.raises(SecIntakeError, match="no filing"):
        select_latest_filings(_submissions(), cik="1018724", cutoff_date="2024-01-01")


def test_complex_table_and_display_sign_are_deterministic() -> None:
    matrix = table_matrix((FIXTURES / "complex-filing.html").read_bytes(), table_id="segment-table")
    assert matrix[0] == ("Reportable segment", "Revenue", "Revenue")
    assert matrix[1] == ("Reportable segment", "2025", "2024")
    assert parse_displayed_number("($50)").value == -50


def test_ixbrl_dimensions_period_and_unit_are_extracted(sample_payloads: dict[str, dict]) -> None:
    source = contract_from_dict("source-document", sample_payloads["source-document"])
    raw = (FIXTURES / "ixbrl-dimensions.html").read_bytes()
    selection = select_latest_filings(_submissions(), cik="1018724", cutoff_date="2026-07-11")[
        "10-K"
    ]
    selection = copy.copy(selection)
    artifact = build_filing_artifact(
        issuer_id=source.issuer_id,
        source_document_id=source.document_id,
        selection=selection,
        raw=raw,
        retrieved_at="2026-07-11T00:00:00Z",
    )
    candidates = extract_ixbrl_candidates(raw, artifact=artifact, source_document=source)
    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.value == 1250
    assert candidate.currency == "USD"
    assert candidate.period["start"] == "2025-01-01"
    assert candidate.dimensions["us-gaap:OperatingSegmentsAxis"] == "amzn:CloudMember"
