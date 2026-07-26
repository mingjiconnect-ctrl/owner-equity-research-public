from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any

from lxml import html

from .contracts import (
    Fact,
    ManagementStatement,
    ManagementStatementCandidate,
    ManagementStatementReviewDecision,
    SourceDocument,
)
from .fingerprints import canonical_sha256
from .units import validate_unit_currency


class StatementLedgerError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class StatementConfirmation:
    decision: ManagementStatementReviewDecision
    statement: ManagementStatement | None
    facts: tuple[Fact, ...]


def normalized_source_text(raw: bytes) -> str:
    decoded = raw.decode("utf-8", errors="replace")
    if "<" in decoded and ">" in decoded:
        try:
            decoded = " ".join(html.fromstring(raw).text_content().split())
        except (ValueError, TypeError):
            pass
    return " ".join(decoded.split())


def build_statement_candidate(
    *,
    raw: bytes,
    source_document: SourceDocument,
    start: int,
    end: int,
    speaker_name: str,
    speaker_role: str,
    statement_date: str,
    statement_type: str,
    kpi_concept: str | None,
    extraction_method: str,
    metric_mentions: tuple[dict[str, Any], ...] = (),
) -> ManagementStatementCandidate:
    if hashlib.sha256(raw).hexdigest() != source_document.content_sha256:
        raise StatementLedgerError("source content hash mismatch")
    text = normalized_source_text(raw)
    if not 0 <= start < end <= len(text):
        raise StatementLedgerError("statement text span is outside normalized source")
    excerpt = text[start:end]
    if not excerpt.strip():
        raise StatementLedgerError("statement text span is empty")
    issues: list[str] = []
    seen: set[tuple[str, str, str]] = set()
    for mention in metric_mentions:
        key = (mention["component_id"], mention["metric_concept"], mention["role"])
        if key in seen:
            issues.append("duplicate_metric_role")
        seen.add(key)
        if mention["value_type"] == "number":
            try:
                validate_unit_currency(mention["unit"], mention["currency"])
            except ValueError:
                issues.append("metric_unit_currency_unresolved")
        elif mention["unit"] is not None or mention["currency"] is not None:
            issues.append("nonnumeric_metric_has_unit_or_currency")
    digest = canonical_sha256(
        {
            "source_document_id": source_document.document_id,
            "source_locator": f"text:{start}:{end}",
            "statement_text": excerpt,
        }
    )[:20]
    return ManagementStatementCandidate(
        schema_version="1.0.0",
        candidate_id=f"management-candidate:{source_document.issuer_id}:{digest}",
        issuer_id=source_document.issuer_id,
        source_document_id=source_document.document_id,
        source_locator=f"text:{start}:{end}",
        excerpt_sha256=hashlib.sha256(excerpt.encode()).hexdigest(),
        statement_text=excerpt,
        statement_sha256=hashlib.sha256(excerpt.encode()).hexdigest(),
        speaker_name=speaker_name,
        speaker_role=speaker_role,
        statement_date=statement_date,
        statement_type=statement_type,
        kpi_concept=kpi_concept,
        extraction_method=extraction_method,
        metric_mentions=metric_mentions,
        validation_status="validated" if not issues else "blocked",
        validation_issues=tuple(sorted(set(issues))),
    )


def review_statement_candidate(
    candidate: ManagementStatementCandidate,
    *,
    source_document: SourceDocument,
    decision: str,
    reviewer_id: str,
    reviewed_at: str,
    rationale: str,
    issues: tuple[str, ...] = (),
) -> StatementConfirmation:
    if source_document.document_id != candidate.source_document_id:
        raise StatementLedgerError("candidate source_document_id mismatch")
    if source_document.issuer_id != candidate.issuer_id:
        raise StatementLedgerError("candidate issuer mismatch")
    if source_document.authority_level not in {"primary_regulatory", "company_primary"}:
        raise StatementLedgerError("confirmed Statement requires an official source")
    if decision not in {"confirmed", "blocked", "rejected"}:
        raise StatementLedgerError("invalid statement review decision")
    if decision == "confirmed" and candidate.validation_status in {"blocked", "rejected"}:
        raise StatementLedgerError("blocked or rejected candidate cannot be confirmed")
    digest = canonical_sha256([candidate.candidate_id, reviewed_at])[:20]
    statement_id = f"management-statement:{candidate.issuer_id}:{digest}"
    facts: list[Fact] = []
    metric_bindings = []
    if decision == "confirmed":
        for mention in candidate.metric_mentions:
            fact_id = (
                f"fact:{candidate.issuer_id}:management-target:{digest}:"
                f"{mention['component_id']}:{mention['role']}"
            )
            facts.append(
                Fact(
                    schema_version="2.0.0",
                    fact_id=fact_id,
                    issuer_id=candidate.issuer_id,
                    concept=mention["metric_concept"],
                    value_type=mention["value_type"],
                    value=mention["value"],
                    unit=mention["unit"],
                    currency=mention["currency"],
                    period=mention["period"],
                    source_document_id=candidate.source_document_id,
                    source_locator=candidate.source_locator,
                    derivation=(
                        "Human-confirmed management metric mention from candidate "
                        f"{candidate.fingerprint}."
                    ),
                    parent_fact_ids=(),
                    confidence="high",
                )
            )
            metric_bindings.append(
                {
                    "component_id": mention["component_id"],
                    "metric_concept": mention["metric_concept"],
                    "role": mention["role"],
                    "fact_id": fact_id,
                }
            )
    statement = None
    if decision == "confirmed":
        eligibility = "measurable" if metric_bindings else "narrative_only"
        statement = ManagementStatement(
            schema_version="2.0.0",
            statement_id=statement_id,
            issuer_id=candidate.issuer_id,
            speaker_name=candidate.speaker_name,
            speaker_role=candidate.speaker_role,
            statement_date=candidate.statement_date,
            statement_type=candidate.statement_type,
            kpi_concept=candidate.kpi_concept,
            definition_change=(
                "initial"
                if candidate.statement_type == "kpi_definition"
                else "not_applicable"
            ),
            source_document_id=candidate.source_document_id,
            source_locator=candidate.source_locator,
            statement_text=candidate.statement_text,
            statement_sha256=candidate.statement_sha256,
            extraction_method=candidate.extraction_method,
            verification_status="human_confirmed",
            reviewer_id=reviewer_id,
            reviewed_at=reviewed_at,
            lifecycle_status="current",
            predecessor_statement_ids=(),
            kpi_definition_fact_ids=(),
            commitment_eligibility=eligibility,
            metric_bindings=tuple(metric_bindings),
            missing_evidence=(),
        )
    resolved_issues = issues
    if decision != "confirmed" and not resolved_issues:
        resolved_issues = (f"candidate_{decision}",)
    review = ManagementStatementReviewDecision(
        schema_version="1.0.0",
        decision_id=f"statement-review:{candidate.issuer_id}:{digest}",
        issuer_id=candidate.issuer_id,
        candidate_id=candidate.candidate_id,
        candidate_fingerprint=candidate.fingerprint,
        decision=decision,
        output_statement_id=statement_id if statement is not None else None,
        output_fact_ids=tuple(item.fact_id for item in facts),
        reviewer_id=reviewer_id,
        reviewed_at=reviewed_at,
        rationale=rationale,
        issues=resolved_issues,
    )
    return StatementConfirmation(review, statement, tuple(facts))


def parse_text_locator(locator: str) -> tuple[int, int]:
    match = re.fullmatch(r"text:([0-9]+):([0-9]+)", locator)
    if not match:
        raise StatementLedgerError("invalid text-span locator")
    return int(match.group(1)), int(match.group(2))
