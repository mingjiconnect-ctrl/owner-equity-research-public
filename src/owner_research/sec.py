from __future__ import annotations

import hashlib
import json
import math
import os
import re
import time
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
from lxml import etree, html

from .contracts import FilingArtifact

SEC_USER_AGENT_ENV = "OWNER_RESEARCH_SEC_USER_AGENT"
DEFAULT_RATE_LIMIT = 5.0
MAX_RATE_LIMIT = 10.0
PARSER_ID = "owner-research-sec-html"
PARSER_VERSION = "0.3.0-alpha.1"
ALLOWED_FORMS = frozenset({"10-K", "10-K/A", "10-Q", "10-Q/A"})


class SecIntakeError(ValueError):
    pass


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalize_cik(cik: str | int) -> str:
    digits = str(cik).strip()
    if not digits.isdigit() or len(digits) > 10:
        raise SecIntakeError("CIK must contain at most ten digits")
    return digits.zfill(10)


def validate_sec_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.username or parsed.password or not (
        parsed.hostname == "sec.gov" or (parsed.hostname or "").endswith(".sec.gov")
    ):
        raise SecIntakeError("SEC intake accepts only HTTPS sec.gov URLs")


def normalized_html_bytes(raw: bytes) -> bytes:
    try:
        document = html.fromstring(raw)
    except (etree.ParserError, ValueError) as exc:
        raise SecIntakeError("filing HTML cannot be parsed") from exc
    for node in document.xpath("//script|//style"):
        node.getparent().remove(node)
    for node in document.iter():
        if node.text:
            node.text = " ".join(node.text.split())
        if node.tail:
            node.tail = " ".join(node.tail.split())
    return etree.tostring(document, method="html", encoding="utf-8", with_tail=False)


@dataclass(frozen=True, slots=True)
class FilingSelection:
    cik: str
    accession: str
    form: str
    filing_date: str
    report_period: str
    primary_document: str

    @property
    def source_url(self) -> str:
        accession_compact = self.accession.replace("-", "")
        return (
            f"https://www.sec.gov/Archives/edgar/data/{int(self.cik)}/"
            f"{accession_compact}/{self.primary_document}"
        )


class ContentAddressedCache:
    def __init__(self, root: Path | None = None) -> None:
        default = Path.home() / ".cache" / "owner-equity-research" / "sec"
        self.root = Path(root or os.environ.get("OWNER_RESEARCH_SEC_CACHE", default)).expanduser()
        resolved_root = self.root.resolve()
        repository_roots = {Path.cwd().resolve(), Path(__file__).parents[2].resolve()}
        if any(
            resolved_root == repository_root
            or repository_root in resolved_root.parents
            for repository_root in repository_roots
        ):
            raise SecIntakeError("SEC raw cache must be outside the repository working tree")

    def put(self, content: bytes) -> tuple[str, Path]:
        digest = _sha256(content)
        path = self.root / digest[:2] / digest
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_bytes(content)
        return digest, path


class SecClient:
    def __init__(
        self,
        *,
        user_agent: str | None = None,
        requests_per_second: float = DEFAULT_RATE_LIMIT,
        timeout: float = 30.0,
        cache: ContentAddressedCache | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        resolved_agent = (user_agent or os.environ.get(SEC_USER_AGENT_ENV, "")).strip()
        if not resolved_agent:
            raise SecIntakeError(f"{SEC_USER_AGENT_ENV} is required")
        if (
            not math.isfinite(float(requests_per_second))
            or requests_per_second <= 0
            or requests_per_second > MAX_RATE_LIMIT
        ):
            raise SecIntakeError("SEC request rate must be greater than zero and at most 10 rps")
        self.requests_per_second = float(requests_per_second)
        self.cache = cache or ContentAddressedCache()
        self._last_request = 0.0
        self._client = httpx.Client(
            headers={"User-Agent": resolved_agent, "Accept-Encoding": "gzip, deflate"},
            timeout=timeout,
            follow_redirects=True,
            transport=transport,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> SecClient:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def get_bytes(self, url: str) -> bytes:
        validate_sec_url(url)
        wait = 1.0 / self.requests_per_second - (time.monotonic() - self._last_request)
        if wait > 0:
            time.sleep(wait)
        response = self._client.get(url)
        self._last_request = time.monotonic()
        response.raise_for_status()
        content = response.content
        self.cache.put(content)
        return content

    def get_json(self, url: str) -> dict[str, Any]:
        try:
            payload = json.loads(self.get_bytes(url))
        except json.JSONDecodeError as exc:
            raise SecIntakeError("SEC response is not JSON") from exc
        if not isinstance(payload, dict):
            raise SecIntakeError("SEC response JSON must be an object")
        return payload

    def submissions(self, cik: str | int) -> dict[str, Any]:
        return self.get_json(f"https://data.sec.gov/submissions/CIK{normalize_cik(cik)}.json")

    def company_facts(self, cik: str | int) -> dict[str, Any]:
        return self.get_json(
            f"https://data.sec.gov/api/xbrl/companyfacts/CIK{normalize_cik(cik)}.json"
        )


def select_latest_filings(
    submissions: dict[str, Any],
    *,
    cik: str | int,
    cutoff_date: str,
    forms: tuple[str, ...] = ("10-K", "10-Q"),
) -> dict[str, FilingSelection]:
    cutoff = date.fromisoformat(cutoff_date)
    if not set(forms).issubset(ALLOWED_FORMS):
        raise SecIntakeError("unsupported filing form")
    requested_base_forms = tuple(dict.fromkeys(form.removesuffix("/A") for form in forms))
    recent = submissions.get("filings", {}).get("recent", {})
    required = ("accessionNumber", "form", "filingDate", "reportDate", "primaryDocument")
    if any(not isinstance(recent.get(key), list) for key in required):
        raise SecIntakeError("SEC submissions payload lacks recent filing arrays")
    lengths = {len(recent[key]) for key in required}
    if len(lengths) != 1:
        raise SecIntakeError("SEC submissions arrays have inconsistent lengths")
    normalized = normalize_cik(cik)
    selected: dict[str, FilingSelection] = {}
    for values in zip(*(recent[key] for key in required), strict=True):
        accession, form, filing_date, report_period, primary_document = map(str, values)
        if not re.fullmatch(r"[0-9]{10}-[0-9]{2}-[0-9]{6}", accession):
            raise SecIntakeError("SEC submissions contains an invalid accession")
        if form not in ALLOWED_FORMS:
            continue
        if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", filing_date) or not re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}", report_period
        ):
            raise SecIntakeError("SEC submissions contains an invalid filing or report date")
        if not re.fullmatch(r"[^/]+\.(?:html?|xhtml)", primary_document, re.IGNORECASE):
            raise SecIntakeError("SEC submissions contains an unsafe primary document")
        base_form = form.removesuffix("/A")
        filing_day = date.fromisoformat(filing_date)
        report_day = date.fromisoformat(report_period)
        if report_day > filing_day:
            raise SecIntakeError("SEC filing report date follows filing date")
        if (
            base_form not in requested_base_forms
            or filing_day > cutoff
            or report_day > cutoff
        ):
            continue
        candidate = FilingSelection(
            cik=normalized,
            accession=accession,
            form=form,
            filing_date=filing_date,
            report_period=report_period,
            primary_document=primary_document,
        )
        current = selected.get(base_form)
        if current is None or (candidate.filing_date, candidate.form.endswith("/A")) > (
            current.filing_date,
            current.form.endswith("/A"),
        ):
            selected[base_form] = candidate
    missing = set(requested_base_forms).difference(selected)
    if missing:
        raise SecIntakeError(f"no filing at or before cutoff for: {', '.join(sorted(missing))}")
    return selected


def build_filing_artifact(
    *,
    issuer_id: str,
    source_document_id: str,
    selection: FilingSelection,
    raw: bytes,
    retrieved_at: str,
) -> FilingArtifact:
    if selection.form not in ALLOWED_FORMS:
        raise SecIntakeError("unsupported filing form")
    if not re.fullmatch(r"[0-9]{10}-[0-9]{2}-[0-9]{6}", selection.accession):
        raise SecIntakeError("invalid filing accession")
    if not re.fullmatch(r"[0-9]{10}", selection.cik):
        raise SecIntakeError("invalid filing CIK")
    if date.fromisoformat(selection.report_period) > date.fromisoformat(selection.filing_date):
        raise SecIntakeError("filing report date follows filing date")
    if not re.fullmatch(r"[^/]+\.(?:html?|xhtml)", selection.primary_document, re.IGNORECASE):
        raise SecIntakeError("unsafe primary document")
    normalized = normalized_html_bytes(raw)
    return FilingArtifact(
        schema_version="1.0.0",
        artifact_id=f"filing:{issuer_id}:{selection.accession}",
        issuer_id=issuer_id,
        source_document_id=source_document_id,
        cik=selection.cik,
        accession=selection.accession,
        form=selection.form,
        filing_date=selection.filing_date,
        report_period=selection.report_period,
        primary_document=selection.primary_document,
        source_url=selection.source_url,
        raw_sha256=_sha256(raw),
        normalized_sha256=_sha256(normalized),
        parser_id=PARSER_ID,
        parser_version=PARSER_VERSION,
        retrieved_at=retrieved_at,
    )


def filing_accession_from_url(url: str) -> str | None:
    validate_sec_url(url)
    match = re.search(r"/([0-9]{18})/[^/]+$", url)
    if not match:
        return None
    compact = match.group(1)
    return f"{compact[:10]}-{compact[10:12]}-{compact[12:]}"
