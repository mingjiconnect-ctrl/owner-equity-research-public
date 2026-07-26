from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import date, datetime

from .capital_allocation_ledger import source_family
from .capital_allocation_policies import EVENT_TYPES, OFFICIAL_AUTHORITY_LEVELS, SOURCE_FAMILIES
from .contracts import SourceDocument, SourceSearchReceipt
from .fingerprints import canonical_sha256


class SourceSearchReceiptError(ValueError):
    pass


def source_search_request_fingerprint(
    *,
    issuer_id: str,
    source_family_id: str,
    query_scope: Mapping[str, object],
    period: Mapping[str, str],
    cutoff_date: str,
    searched_endpoints: Sequence[str],
    tool_version: str,
) -> str:
    return canonical_sha256(
        {
            "issuer_id": issuer_id,
            "source_family": source_family_id,
            "query_scope": query_scope,
            "period": period,
            "cutoff_date": cutoff_date,
            "searched_endpoints": sorted(set(searched_endpoints)),
            "tool_version": tool_version,
        }
    )


def build_source_search_receipt(
    *,
    issuer_id: str,
    source_family_id: str,
    query_scope: Mapping[str, object],
    period: Mapping[str, str],
    cutoff_date: str,
    searched_endpoints: Sequence[str],
    result_documents: Sequence[SourceDocument],
    completed_at: str,
    tool_version: str,
    status: str = "completed",
    issues: Sequence[str] = (),
) -> SourceSearchReceipt:
    if source_family_id not in SOURCE_FAMILIES:
        raise SourceSearchReceiptError("unregistered source family")
    if set(query_scope) != {"cik", "event_types"}:
        raise SourceSearchReceiptError("source search query scope is invalid")
    if not str(query_scope["cik"]).isdigit() or len(str(query_scope["cik"])) != 10:
        raise SourceSearchReceiptError("source search CIK is invalid")
    event_types = tuple(query_scope["event_types"])
    if not event_types or len(event_types) != len(set(event_types)) or not set(
        event_types
    ).issubset(EVENT_TYPES):
        raise SourceSearchReceiptError("source search event types are invalid")
    start = date.fromisoformat(period["start"])
    end = date.fromisoformat(period["end"])
    cutoff = date.fromisoformat(cutoff_date)
    if start > end or end > cutoff:
        raise SourceSearchReceiptError("source search period is invalid")
    try:
        datetime.fromisoformat(completed_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SourceSearchReceiptError("source search completion time is invalid") from exc
    endpoints = tuple(sorted(set(searched_endpoints)))
    if not endpoints or any(not item.strip() for item in endpoints):
        raise SourceSearchReceiptError("source search endpoints are incomplete")
    if status not in {"completed", "blocked"}:
        raise SourceSearchReceiptError("source search status is invalid")
    normalized_issues = tuple(sorted(set(issues)))
    if status == "completed" and normalized_issues:
        raise SourceSearchReceiptError("completed source search contains issues")
    if status == "blocked" and not normalized_issues:
        raise SourceSearchReceiptError("blocked source search lacks issues")
    document_ids: list[str] = []
    for document in result_documents:
        if (
            document.issuer_id != issuer_id
            or document.authority_level not in OFFICIAL_AUTHORITY_LEVELS
            or date.fromisoformat(document.published_date) > cutoff
            or source_family(document) != source_family_id
        ):
            raise SourceSearchReceiptError("source search result document is invalid")
        document_ids.append(document.document_id)
    if len(document_ids) != len(set(document_ids)):
        raise SourceSearchReceiptError("source search repeats a result document")
    request_fingerprint = source_search_request_fingerprint(
        issuer_id=issuer_id,
        source_family_id=source_family_id,
        query_scope=query_scope,
        period=period,
        cutoff_date=cutoff_date,
        searched_endpoints=endpoints,
        tool_version=tool_version,
    )
    receipt_id = (
        f"source-search:{issuer_id}:"
        f"{canonical_sha256([request_fingerprint, completed_at, sorted(document_ids), status])}"
    )
    return SourceSearchReceipt(
        schema_version="1.0.0",
        receipt_id=receipt_id,
        issuer_id=issuer_id,
        source_family=source_family_id,
        query_scope=dict(query_scope),
        period=dict(period),
        cutoff_date=cutoff_date,
        searched_endpoints=endpoints,
        result_document_ids=tuple(sorted(document_ids)),
        completed_at=completed_at,
        tool_version=tool_version,
        request_fingerprint=request_fingerprint,
        status=status,
        issues=normalized_issues,
    )
