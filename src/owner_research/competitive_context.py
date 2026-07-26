from __future__ import annotations

import hashlib
import math
import os
import time
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from urllib.parse import urljoin, urlparse

import httpx
from lxml import html

from .contracts import CompetitiveContextSnapshot, ContextObservation, SourceDocument
from .fingerprints import canonical_sha256
from .sec import ContentAddressedCache
from .units import validate_unit_currency
from .validation import CONTEXT_TOPICS, OFFICIAL_AUTHORITY_LEVELS

CONTEXT_CACHE_ENV = "OWNER_RESEARCH_CONTEXT_CACHE"
CRITICAL_CONTEXT_TOPICS = frozenset(
    {"product_service", "customer_group", "competitor_set", "substitutes", "rivalry"}
)
ALLOWED_CONTEXT_AUTHORITIES = frozenset(
    {*OFFICIAL_AUTHORITY_LEVELS, "audited_secondary", "secondary"}
)


class CompetitiveContextError(ValueError):
    pass


def validate_context_url(url: str, allowed_hosts: frozenset[str]) -> None:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or parsed.username or parsed.password:
        raise CompetitiveContextError("context source URL must be credential-free HTTPS")
    if host == "sec.gov" or host.endswith(".sec.gov"):
        raise CompetitiveContextError("SEC retrieval must use the governed SEC client")
    if not any(host == allowed or host.endswith(f".{allowed}") for allowed in allowed_hosts):
        raise CompetitiveContextError("context source host is not in the explicit allowlist")


class ContextSourceClient:
    def __init__(
        self,
        *,
        allowed_hosts: frozenset[str],
        user_agent: str,
        requests_per_second: float = 5.0,
        timeout: float = 30.0,
        cache: ContentAddressedCache | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if not allowed_hosts:
            raise CompetitiveContextError("context source host allowlist is required")
        if not user_agent.strip():
            raise CompetitiveContextError("context source User-Agent is required")
        if not math.isfinite(requests_per_second) or not 0 < requests_per_second <= 10:
            raise CompetitiveContextError(
                "context source rate must be greater than zero and at most 10"
            )
        root = Path(
            os.environ.get(
                CONTEXT_CACHE_ENV,
                Path.home() / ".cache" / "owner-equity-research" / "context",
            )
        )
        self.allowed_hosts = frozenset(item.lower() for item in allowed_hosts)
        self.requests_per_second = requests_per_second
        self.cache = cache or ContentAddressedCache(root)
        self._last_request = 0.0
        self._client = httpx.Client(
            timeout=timeout,
            follow_redirects=False,
            transport=transport,
            headers={"User-Agent": user_agent},
        )

    def __enter__(self) -> ContextSourceClient:
        return self

    def __exit__(self, *_: object) -> None:
        self._client.close()

    def get_bytes(self, url: str) -> bytes:
        current = url
        for _ in range(6):
            validate_context_url(current, self.allowed_hosts)
            wait = 1 / self.requests_per_second - (time.monotonic() - self._last_request)
            if wait > 0:
                time.sleep(wait)
            response = self._client.get(current)
            self._last_request = time.monotonic()
            if response.is_redirect:
                location = response.headers.get("location")
                if not location:
                    raise CompetitiveContextError("context redirect lacks a location")
                current = urljoin(str(response.url), location)
                continue
            response.raise_for_status()
            validate_context_url(str(response.url), self.allowed_hosts)
            self.cache.put(response.content)
            return response.content
        raise CompetitiveContextError("context source exceeded redirect limit")


def build_context_source_document(
    *,
    subject_entity_id: str,
    document_id: str,
    document_type: str,
    period: Mapping[str, str | None],
    published_date: str,
    retrieved_at: str,
    source_url: str,
    authority_level: str,
    raw: bytes,
    allowed_hosts: frozenset[str],
) -> SourceDocument:
    validate_context_url(source_url, allowed_hosts)
    if authority_level not in ALLOWED_CONTEXT_AUTHORITIES:
        raise CompetitiveContextError("unsupported competitive-context authority level")
    return SourceDocument(
        schema_version="1.0.0",
        document_id=document_id,
        issuer_id=subject_entity_id,
        document_type=document_type,
        period=dict(period),
        published_date=published_date,
        retrieved_at=retrieved_at,
        source_url=source_url,
        authority_level=authority_level,
        content_sha256=hashlib.sha256(raw).hexdigest(),
    )


def normalized_context_text(raw: bytes) -> str:
    decoded = raw.decode("utf-8", errors="replace")
    if "<" in decoded and ">" in decoded:
        try:
            decoded = " ".join(html.fromstring(raw).text_content().split())
        except (ValueError, TypeError):
            pass
    return " ".join(decoded.split())


def build_confirmed_context_observation(
    *,
    raw: bytes,
    source_document: SourceDocument,
    target_issuer_id: str,
    subject: Mapping[str, str],
    as_of_date: str,
    scope: Mapping[str, object],
    observation_type: str,
    start: int,
    end: int,
    extraction_method: str,
    reviewer_id: str,
    reviewed_at: str,
    confidence: str,
    value_type: str = "none",
    value: float | int | str | bool | None = None,
    unit: str | None = None,
    currency: str | None = None,
    period: Mapping[str, str | None] | None = None,
    limitations: tuple[str, ...] = (),
) -> ContextObservation:
    if extraction_method == "language_model":
        raise CompetitiveContextError(
            "language-model output cannot create a confirmed ContextObservation"
        )
    if extraction_method not in {"deterministic", "manual"}:
        raise CompetitiveContextError("unsupported context extraction method")
    if hashlib.sha256(raw).hexdigest() != source_document.content_sha256:
        raise CompetitiveContextError("context source content hash mismatch")
    if date.fromisoformat(source_document.published_date) > date.fromisoformat(as_of_date):
        raise CompetitiveContextError("context source follows the analysis cutoff")
    expected_subject = (
        target_issuer_id if subject["role"] == "target_issuer" else subject["entity_id"]
    )
    if source_document.issuer_id != expected_subject:
        raise CompetitiveContextError("context source subject does not match the observation")
    text = normalized_context_text(raw)
    if not 0 <= start < end <= len(text):
        raise CompetitiveContextError("context source span is outside normalized content")
    statement = text[start:end].strip()
    if not statement:
        raise CompetitiveContextError("context observation span is empty")
    if value_type == "number":
        validate_unit_currency(unit, currency)
    elif unit is not None or currency is not None:
        raise CompetitiveContextError("nonnumeric context value cannot carry unit or currency")
    identifier = canonical_sha256(
        {
            "target_issuer_id": target_issuer_id,
            "subject": subject,
            "source_document_id": source_document.document_id,
            "source_locator": f"text:{start}:{end}",
            "statement": statement,
        }
    )[:20]
    return ContextObservation(
        schema_version="1.0.0",
        observation_id=f"context-observation:{target_issuer_id}:{identifier}",
        target_issuer_id=target_issuer_id,
        subject=dict(subject),
        as_of_date=as_of_date,
        scope=dict(scope),
        observation_type=observation_type,
        statement=statement,
        value_type=value_type,
        value=value,
        unit=unit,
        currency=currency,
        period=dict(period or {"start": None, "end": None}),
        source_document_id=source_document.document_id,
        source_locator=f"text:{start}:{end}",
        extraction_method=extraction_method,
        verification_status="human_confirmed",
        reviewer_id=reviewer_id,
        reviewed_at=reviewed_at,
        confidence=confidence,
        limitations=limitations,
    )


@dataclass(frozen=True, slots=True)
class ContextCoverageInput:
    reviewed_observation_ids: tuple[str, ...] = ()
    not_applicable_claim_ids: tuple[str, ...] = ()
    missing_evidence: tuple[str, ...] = ()


def build_competitive_context_snapshot(
    *,
    issuer_id: str,
    as_of_date: str,
    scope: Mapping[str, object],
    source_documents: tuple[SourceDocument, ...],
    observations: tuple[ContextObservation, ...],
    competitor_selection_claim_ids: tuple[str, ...],
    topic_inputs: Mapping[str, ContextCoverageInput],
) -> CompetitiveContextSnapshot:
    unknown_topics = set(topic_inputs) - CONTEXT_TOPICS
    if unknown_topics:
        raise CompetitiveContextError(f"unknown competitive-context topics: {unknown_topics}")
    observation_ids = {item.observation_id for item in observations}
    source_ids = {item.document_id for item in source_documents}
    coverage = []
    for topic in sorted(CONTEXT_TOPICS):
        item = topic_inputs.get(topic, ContextCoverageInput(missing_evidence=(f"{topic} missing",)))
        if set(item.reviewed_observation_ids) - observation_ids:
            raise CompetitiveContextError("topic references an undeclared ContextObservation")
        if item.reviewed_observation_ids and item.not_applicable_claim_ids:
            raise CompetitiveContextError("topic cannot be reviewed and not-applicable")
        if item.reviewed_observation_ids:
            status = "reviewed"
            missing = ()
        elif item.not_applicable_claim_ids:
            status = "not_applicable"
            missing = ()
        else:
            status = "blocked"
            missing = item.missing_evidence or (f"{topic} missing",)
        coverage.append(
            {
                "topic": topic,
                "status": status,
                "observation_ids": item.reviewed_observation_ids,
                "claim_ids": item.not_applicable_claim_ids,
                "missing_evidence": missing,
            }
        )
    missing = [
        evidence
        for item in coverage
        if item["status"] == "blocked"
        for evidence in item["missing_evidence"]
    ]
    if not competitor_selection_claim_ids:
        missing.append("Competitor set lacks an analytical selection Claim")
    blocked_topics = {item["topic"] for item in coverage if item["status"] == "blocked"}
    has_target_primary = any(
        item.issuer_id == issuer_id and item.authority_level in OFFICIAL_AUTHORITY_LEVELS
        for item in source_documents
    )
    has_independent = any(
        item.issuer_id != issuer_id
        and item.authority_level in {*OFFICIAL_AUTHORITY_LEVELS, "audited_secondary"}
        for item in source_documents
    )
    if not competitor_selection_claim_ids or blocked_topics & CRITICAL_CONTEXT_TOPICS:
        status = "blocked"
    elif blocked_topics or not (has_target_primary and has_independent):
        status = "partial"
        if not (has_target_primary and has_independent):
            missing.append("Target and independent primary source diversity is incomplete")
    else:
        status = "complete"
    if any(item.source_document_id not in source_ids for item in observations):
        raise CompetitiveContextError("snapshot omits an observation SourceDocument")
    identifier = canonical_sha256(
        {
            "issuer_id": issuer_id,
            "as_of_date": as_of_date,
            "scope": scope,
            "observation_ids": sorted(observation_ids),
            "competitor_selection_claim_ids": sorted(competitor_selection_claim_ids),
        }
    )[:20]
    return CompetitiveContextSnapshot(
        schema_version="1.0.0",
        context_snapshot_id=f"competitive-context:{issuer_id}:{identifier}",
        issuer_id=issuer_id,
        as_of_date=as_of_date,
        status=status,
        scope=dict(scope),
        source_document_ids=tuple(sorted(source_ids)),
        observation_ids=tuple(sorted(observation_ids)),
        competitor_selection_claim_ids=tuple(sorted(competitor_selection_claim_ids)),
        coverage=tuple(coverage),
        missing_evidence=tuple(sorted(set(missing))),
    )
