from __future__ import annotations

import hashlib
import math
import os
import time
from datetime import date
from pathlib import Path
from urllib.parse import urljoin, urlparse

import httpx

from .contracts import SourceDocument
from .sec import ContentAddressedCache, FilingSelection, normalize_cik

OFFICIAL_CACHE_ENV = "OWNER_RESEARCH_OFFICIAL_CACHE"
MANAGEMENT_SEC_FORMS = frozenset(
    {"10-K", "10-K/A", "10-Q", "10-Q/A", "8-K", "8-K/A", "DEF 14A", "DEFA14A"}
)


class OfficialSourceError(ValueError):
    pass


def validate_official_url(url: str, allowed_hosts: frozenset[str]) -> None:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or parsed.username or parsed.password:
        raise OfficialSourceError("official source URL must be credential-free HTTPS")
    if not any(host == allowed or host.endswith(f".{allowed}") for allowed in allowed_hosts):
        raise OfficialSourceError("official source host is not in the issuer allowlist")


class OfficialSourceClient:
    def __init__(
        self,
        *,
        allowed_hosts: frozenset[str],
        requests_per_second: float = 5.0,
        timeout: float = 30.0,
        cache: ContentAddressedCache | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if not allowed_hosts:
            raise OfficialSourceError("issuer official-source host allowlist is required")
        if not math.isfinite(requests_per_second) or not 0 < requests_per_second <= 10:
            raise OfficialSourceError(
                "official source rate must be greater than zero and at most 10"
            )
        root = Path(
            os.environ.get(
                OFFICIAL_CACHE_ENV,
                Path.home() / ".cache" / "owner-equity-research" / "official",
            )
        )
        self.allowed_hosts = frozenset(item.lower() for item in allowed_hosts)
        self.requests_per_second = requests_per_second
        self.cache = cache or ContentAddressedCache(root)
        self._last_request = 0.0
        self._client = httpx.Client(timeout=timeout, follow_redirects=False, transport=transport)

    def __enter__(self) -> OfficialSourceClient:
        return self

    def __exit__(self, *_: object) -> None:
        self._client.close()

    def get_bytes(self, url: str) -> bytes:
        current = url
        for _ in range(6):
            validate_official_url(current, self.allowed_hosts)
            wait = 1 / self.requests_per_second - (time.monotonic() - self._last_request)
            if wait > 0:
                time.sleep(wait)
            response = self._client.get(current)
            self._last_request = time.monotonic()
            if response.is_redirect:
                location = response.headers.get("location")
                if not location:
                    raise OfficialSourceError("official source redirect lacks a location")
                current = urljoin(str(response.url), location)
                continue
            response.raise_for_status()
            validate_official_url(str(response.url), self.allowed_hosts)
            self.cache.put(response.content)
            return response.content
        raise OfficialSourceError("official source exceeded redirect limit")


def select_management_filings(
    submissions: dict[str, object],
    *,
    cik: str | int,
    cutoff_date: str,
    forms: frozenset[str] = MANAGEMENT_SEC_FORMS,
) -> tuple[FilingSelection, ...]:
    if not forms or not forms.issubset(MANAGEMENT_SEC_FORMS):
        raise OfficialSourceError("unsupported management filing form")
    recent = submissions.get("filings", {})
    if not isinstance(recent, dict):
        raise OfficialSourceError("SEC submissions lacks filings")
    recent = recent.get("recent", {})
    if not isinstance(recent, dict):
        raise OfficialSourceError("SEC submissions lacks recent filings")
    keys = ("accessionNumber", "form", "filingDate", "reportDate", "primaryDocument")
    if any(not isinstance(recent.get(key), list) for key in keys):
        raise OfficialSourceError("SEC submissions recent arrays are incomplete")
    rows = list(zip(*(recent[key] for key in keys), strict=True))
    cutoff = date.fromisoformat(cutoff_date)
    normalized_cik = normalize_cik(cik)
    selected = []
    for accession, form, filing_date, report_date, primary_document in rows:
        form = str(form)
        if form not in forms or date.fromisoformat(str(filing_date)) > cutoff:
            continue
        selected.append(
            FilingSelection(
                cik=normalized_cik,
                accession=str(accession),
                form=form,
                filing_date=str(filing_date),
                report_period=str(report_date or filing_date),
                primary_document=str(primary_document),
            )
        )
    return tuple(sorted(selected, key=lambda item: (item.filing_date, item.accession)))


def build_official_source_document(
    *,
    issuer_id: str,
    document_id: str,
    document_type: str,
    period: dict[str, str | None],
    published_date: str,
    retrieved_at: str,
    source_url: str,
    authority_level: str,
    raw: bytes,
    allowed_hosts: frozenset[str],
) -> SourceDocument:
    validate_official_url(source_url, allowed_hosts)
    if authority_level not in {"primary_regulatory", "company_primary"}:
        raise OfficialSourceError("management source must be regulatory or company primary")
    return SourceDocument(
        schema_version="1.0.0",
        document_id=document_id,
        issuer_id=issuer_id,
        document_type=document_type,
        period=period,
        published_date=published_date,
        retrieved_at=retrieved_at,
        source_url=source_url,
        authority_level=authority_level,
        content_sha256=hashlib.sha256(raw).hexdigest(),
    )
