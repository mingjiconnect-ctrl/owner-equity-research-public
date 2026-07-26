from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import date
from typing import Any

from lxml import html

from .capital_allocation_policies import (
    EVENT_POLICY_VERSION,
    OFFICIAL_AUTHORITY_LEVELS,
    economic_event_key,
    policy_for,
    role_accepts_unit,
)
from .contracts import (
    CapitalAllocationEvent,
    CapitalAllocationEventCandidate,
    CapitalAllocationEventReviewDecision,
    Fact,
    SourceDocument,
)
from .fingerprints import canonical_sha256
from .sec import FilingSelection, normalize_cik
from .units import unit_spec

CAPITAL_ALLOCATION_SEC_FORMS = frozenset(
    {
        "10-K",
        "10-K/A",
        "10-Q",
        "10-Q/A",
        "8-K",
        "8-K/A",
        "DEF 14A",
        "DEFA14A",
        "DEFM14A",
        "PREM14A",
        "S-3",
        "S-3/A",
        "S-4",
        "S-4/A",
        "424B2",
        "424B3",
        "424B4",
        "424B5",
        "SC TO-I",
        "SC TO-I/A",
        "SC 13E3",
        "SC 13E3/A",
    }
)


class CapitalAllocationLedgerError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class EventCompilation:
    event: CapitalAllocationEvent
    candidate_ids: tuple[str, ...]
    decision_ids: tuple[str, ...]
    no_change: bool


def _normalized_source_text(raw: bytes) -> str:
    decoded = raw.decode("utf-8", errors="replace")
    if "<" in decoded and ">" in decoded:
        try:
            decoded = html.fromstring(raw).text_content()
        except (TypeError, ValueError):
            pass
    return " ".join(decoded.split())


def _validate_submission_arrays(submissions: dict[str, object]) -> dict[str, list[Any]]:
    filings = submissions.get("filings")
    if not isinstance(filings, dict) or not isinstance(filings.get("recent"), dict):
        raise CapitalAllocationLedgerError("SEC submissions lacks recent filings")
    recent = filings["recent"]
    keys = ("accessionNumber", "form", "filingDate", "reportDate", "primaryDocument")
    if any(not isinstance(recent.get(key), list) for key in keys):
        raise CapitalAllocationLedgerError("SEC submissions recent arrays are incomplete")
    lengths = {len(recent[key]) for key in keys}
    if len(lengths) != 1:
        raise CapitalAllocationLedgerError("SEC submissions arrays have inconsistent lengths")
    return {key: recent[key] for key in keys}


def select_capital_allocation_filings(
    submissions: dict[str, object],
    *,
    cik: str | int,
    cutoff_date: str,
    forms: frozenset[str] = CAPITAL_ALLOCATION_SEC_FORMS,
) -> tuple[FilingSelection, ...]:
    if not forms or not forms.issubset(CAPITAL_ALLOCATION_SEC_FORMS):
        raise CapitalAllocationLedgerError("unsupported capital-allocation filing form")
    recent = _validate_submission_arrays(submissions)
    cutoff = date.fromisoformat(cutoff_date)
    normalized_cik = normalize_cik(cik)
    selections: list[FilingSelection] = []
    for accession, form, filing_date, report_date, primary_document in zip(
        *(recent[key] for key in recent), strict=True
    ):
        accession = str(accession)
        form = str(form)
        filing_date = str(filing_date)
        report_date = str(report_date or filing_date)
        primary_document = str(primary_document)
        if form not in forms or date.fromisoformat(filing_date) > cutoff:
            continue
        if not re.fullmatch(r"[0-9]{10}-[0-9]{2}-[0-9]{6}", accession):
            raise CapitalAllocationLedgerError("SEC submissions contains an invalid accession")
        if date.fromisoformat(report_date) > date.fromisoformat(filing_date):
            raise CapitalAllocationLedgerError("SEC report date follows filing date")
        if not re.fullmatch(r"[^/]+\.(?:html?|xhtml)", primary_document, re.IGNORECASE):
            raise CapitalAllocationLedgerError("SEC filing primary document is unsafe")
        selections.append(
            FilingSelection(
                cik=normalized_cik,
                accession=accession,
                form=form,
                filing_date=filing_date,
                report_period=report_date,
                primary_document=primary_document,
            )
        )
    return tuple(sorted(selections, key=lambda item: (item.filing_date, item.accession)))


def source_family(source_document: SourceDocument) -> str:
    document_type = source_document.document_type.upper().replace(" ", "")
    if source_document.authority_level == "company_primary":
        return "official_ir"
    if document_type.startswith("10-K"):
        return "10-K"
    if document_type.startswith("10-Q"):
        return "10-Q"
    if document_type.startswith("8-K"):
        return "8-K"
    if document_type in {"DEF14A", "DEFA14A"}:
        return "DEF14A"
    if document_type.startswith(("S-3", "S-4", "424B")):
        return "registration_or_prospectus"
    if document_type.startswith(("SCTO-I", "SC13E3", "DEFM14A", "PREM14A")):
        return "tender_or_merger_material"
    if document_type.startswith(("EX-4", "INDENTURE", "CREDITAGREEMENT")):
        return "credit_or_indentures"
    raise CapitalAllocationLedgerError("source document has no registered formal source family")


def logical_event_id(issuer_id: str, key: str) -> str:
    return f"capital-event:{issuer_id}:{key}"


def build_event_candidate(
    *,
    raw: bytes,
    source_document: SourceDocument,
    start: int,
    end: int,
    as_of_date: str,
    event_type: str,
    event_subtype: str,
    scope: dict[str, Any],
    identity_components: tuple[dict[str, str], ...],
    announcement_date: str,
    execution_period: dict[str, str | None],
    growth_classification: str,
    source_role: str,
    fact_bindings: tuple[dict[str, str], ...] = (),
    rationale_statement_ids: tuple[str, ...] = (),
    related_commitment_ids: tuple[str, ...] = (),
    supersedes_candidate_ids: tuple[str, ...] = (),
    extraction_method: str = "deterministic",
    validation_issues: tuple[str, ...] = (),
    facts: tuple[Fact, ...] = (),
    existing_candidates: tuple[CapitalAllocationEventCandidate, ...] = (),
) -> CapitalAllocationEventCandidate:
    if source_document.authority_level not in OFFICIAL_AUTHORITY_LEVELS:
        raise CapitalAllocationLedgerError("Event Candidate requires an official source")
    source_family(source_document)
    if hashlib.sha256(raw).hexdigest() != source_document.content_sha256:
        raise CapitalAllocationLedgerError("Event Candidate source content hash mismatch")
    as_of = date.fromisoformat(as_of_date)
    published = date.fromisoformat(source_document.published_date)
    announced = date.fromisoformat(announcement_date)
    if published > as_of or announced > published:
        raise CapitalAllocationLedgerError("Event Candidate source or announcement exceeds cutoff")
    period_start = execution_period["start"]
    period_end = execution_period["end"]
    if period_end is not None and period_start is None:
        raise CapitalAllocationLedgerError("Event Candidate execution end requires a start")
    if period_start is not None:
        start_date = date.fromisoformat(period_start)
        if start_date < announced or start_date > as_of:
            raise CapitalAllocationLedgerError("Event Candidate execution start is invalid")
    if period_end is not None:
        end_date = date.fromisoformat(period_end)
        if end_date < date.fromisoformat(period_start) or end_date > as_of:
            raise CapitalAllocationLedgerError("Event Candidate execution end is invalid")
    if source_role == "completion" and period_end is None:
        raise CapitalAllocationLedgerError("completion Candidate requires an execution end")
    if source_role == "execution_update" and period_start is None:
        raise CapitalAllocationLedgerError("execution-update Candidate requires a start")
    policy = policy_for(event_type)
    key = economic_event_key(
        issuer_id=source_document.issuer_id,
        event_type=event_type,
        event_subtype=event_subtype,
        identity_components=identity_components,
    )
    if event_type == "acquisition" and growth_classification == "organic":
        raise CapitalAllocationLedgerError("acquisition revenue cannot be organic growth")
    normalized = _normalized_source_text(raw)
    if not 0 <= start < end <= len(normalized):
        raise CapitalAllocationLedgerError("Event Candidate source span is invalid")
    excerpt = normalized[start:end]
    if not excerpt.strip():
        raise CapitalAllocationLedgerError("Event Candidate source span is empty")
    facts_by_id = {item.fact_id: item for item in facts}
    binding_ids: set[str] = set()
    bound_fact_ids: set[str] = set()
    for binding in fact_bindings:
        if binding["binding_id"] in binding_ids or binding["fact_id"] in bound_fact_ids:
            raise CapitalAllocationLedgerError("Event Candidate repeats a Fact binding")
        binding_ids.add(binding["binding_id"])
        bound_fact_ids.add(binding["fact_id"])
        try:
            fact = facts_by_id[binding["fact_id"]]
        except KeyError as exc:
            raise CapitalAllocationLedgerError("Event Candidate Fact is unavailable") from exc
        if fact.source_document_id != source_document.document_id:
            raise CapitalAllocationLedgerError("Event Candidate Fact belongs to another source")
        if binding["role_id"] not in policy.fact_roles:
            raise CapitalAllocationLedgerError("Event Candidate uses an unregistered Fact role")
        if fact.value_type != "number" or not role_accepts_unit(
            binding["role_id"], unit_spec(fact.unit).family
        ):
            raise CapitalAllocationLedgerError("Event Candidate Fact role unit mismatch")
    existing_by_id = {item.candidate_id: item for item in existing_candidates}
    for candidate_id in supersedes_candidate_ids:
        if candidate_id not in existing_by_id:
            raise CapitalAllocationLedgerError("superseded Event Candidate is unavailable")
        if existing_by_id[candidate_id].issuer_id != source_document.issuer_id:
            raise CapitalAllocationLedgerError("superseded Event Candidate issuer mismatch")
    duplicate_ids = []
    for item in existing_candidates:
        item_key = economic_event_key(
            issuer_id=item.issuer_id,
            event_type=item.proposed_event_type,
            event_subtype=item.proposed_event_subtype,
            identity_components=item.proposed_identity_components,
        )
        if item_key == key and item.candidate_id not in supersedes_candidate_ids:
            duplicate_ids.append(item.candidate_id)
    semantic_identity = {
        "source_document_id": source_document.document_id,
        "source_locator": f"text:{start}:{end}",
        "excerpt_sha256": hashlib.sha256(excerpt.encode()).hexdigest(),
        "economic_event_key": key,
        "source_role": source_role,
        "fact_bindings": fact_bindings,
        "announcement_date": announcement_date,
        "execution_period": execution_period,
        "growth_classification": growth_classification,
    }
    candidate_id = (
        f"capital-candidate:{source_document.issuer_id}:{canonical_sha256(semantic_identity)}"
    )
    duplicate_ids = [item for item in duplicate_ids if item != candidate_id]
    return CapitalAllocationEventCandidate(
        schema_version="2.0.0",
        candidate_id=candidate_id,
        issuer_id=source_document.issuer_id,
        as_of_date=as_of_date,
        source_document_id=source_document.document_id,
        source_locator=f"text:{start}:{end}",
        excerpt_sha256=hashlib.sha256(excerpt.encode()).hexdigest(),
        proposed_event_type=event_type,
        proposed_event_subtype=event_subtype,
        proposed_scope=scope,
        proposed_identity_components=identity_components,
        proposed_announcement_date=announcement_date,
        proposed_execution_period=execution_period,
        proposed_growth_classification=growth_classification,
        proposed_source_role=source_role,
        proposed_fact_bindings=fact_bindings,
        proposed_rationale_statement_ids=rationale_statement_ids,
        proposed_related_commitment_ids=related_commitment_ids,
        potential_duplicate_candidate_ids=tuple(sorted(duplicate_ids)),
        supersedes_candidate_ids=tuple(sorted(supersedes_candidate_ids)),
        extraction_method=extraction_method,
        validation_status="blocked" if validation_issues else "ready",
        validation_issues=tuple(sorted(set(validation_issues))),
    )


def review_event_candidate(
    candidate: CapitalAllocationEventCandidate,
    *,
    source_document: SourceDocument,
    decision: str,
    reviewer_id: str,
    reviewed_at: str,
    rationale: str,
    issues: tuple[str, ...] = (),
    existing_decisions: tuple[CapitalAllocationEventReviewDecision, ...] = (),
) -> CapitalAllocationEventReviewDecision:
    if source_document.document_id != candidate.source_document_id:
        raise CapitalAllocationLedgerError("Event review source mismatch")
    if source_document.issuer_id != candidate.issuer_id:
        raise CapitalAllocationLedgerError("Event review issuer mismatch")
    if source_document.authority_level not in OFFICIAL_AUTHORITY_LEVELS:
        raise CapitalAllocationLedgerError("confirmed Event review requires an official source")
    if decision not in {"confirmed", "blocked", "rejected"}:
        raise CapitalAllocationLedgerError("invalid Event review decision")
    if decision == "confirmed" and candidate.validation_status != "ready":
        raise CapitalAllocationLedgerError("blocked Event Candidate cannot be confirmed")
    key = economic_event_key(
        issuer_id=candidate.issuer_id,
        event_type=candidate.proposed_event_type,
        event_subtype=candidate.proposed_event_subtype,
        identity_components=candidate.proposed_identity_components,
    )
    superseded = tuple(
        sorted(
            item.decision_id
            for item in existing_decisions
            if item.candidate_id in candidate.supersedes_candidate_ids
            and item.decision == "confirmed"
        )
    )
    resolved_issues = tuple(sorted(set(issues)))
    if decision != "confirmed" and not resolved_issues:
        resolved_issues = (f"candidate_{decision}",)
    decision_id = (
        f"capital-decision:{candidate.issuer_id}:"
        f"{canonical_sha256([candidate.fingerprint, reviewed_at, decision])}"
    )
    return CapitalAllocationEventReviewDecision(
        schema_version="1.0.0",
        decision_id=decision_id,
        issuer_id=candidate.issuer_id,
        candidate_id=candidate.candidate_id,
        candidate_fingerprint=candidate.fingerprint,
        decision=decision,
        output_event_id=(
            logical_event_id(candidate.issuer_id, key) if decision == "confirmed" else None
        ),
        output_economic_event_key=key if decision == "confirmed" else None,
        supersedes_decision_ids=superseded,
        reviewer_id=reviewer_id,
        reviewed_at=reviewed_at,
        rationale=rationale,
        issues=resolved_issues,
    )


def _binding_id(*values: str) -> str:
    return f"capital-binding:{canonical_sha256(values)}"


def _event_content(event: CapitalAllocationEvent) -> dict[str, Any]:
    payload = event.to_dict()
    for field in ("event_id", "event_version", "predecessor_event_id"):
        payload.pop(field)
    return payload


def compile_event(
    *,
    candidates: tuple[CapitalAllocationEventCandidate, ...],
    decisions: tuple[CapitalAllocationEventReviewDecision, ...],
    source_documents: tuple[SourceDocument, ...],
    facts: tuple[Fact, ...] = (),
    existing_events: tuple[CapitalAllocationEvent, ...] = (),
    as_of_date: str,
) -> EventCompilation:
    if len({item.candidate_id for item in candidates}) != len(candidates):
        raise CapitalAllocationLedgerError("Event compilation repeats a Candidate ID")
    if len({item.decision_id for item in decisions}) != len(decisions):
        raise CapitalAllocationLedgerError("Event compilation repeats a Decision ID")
    if len({item.document_id for item in source_documents}) != len(source_documents):
        raise CapitalAllocationLedgerError("Event compilation repeats a SourceDocument ID")
    if len({item.fact_id for item in facts}) != len(facts):
        raise CapitalAllocationLedgerError("Event compilation repeats a Fact ID")
    documents = {item.document_id: item for item in source_documents}
    facts_by_id = {item.fact_id: item for item in facts}
    candidates_by_id = {item.candidate_id: item for item in candidates}
    superseded_decisions = {
        item_id for item in decisions for item_id in item.supersedes_decision_ids
    }
    active = tuple(
        item
        for item in decisions
        if item.decision == "confirmed" and item.decision_id not in superseded_decisions
    )
    if not active:
        raise CapitalAllocationLedgerError("Event compilation requires a confirmed Decision")
    selected_candidates: list[CapitalAllocationEventCandidate] = []
    keys: set[str] = set()
    for decision in active:
        try:
            candidate = candidates_by_id[decision.candidate_id]
        except KeyError as exc:
            raise CapitalAllocationLedgerError("Event Decision Candidate is unavailable") from exc
        if candidate.validation_status != "ready":
            raise CapitalAllocationLedgerError("Event Decision uses a blocked Candidate")
        if decision.issuer_id != candidate.issuer_id:
            raise CapitalAllocationLedgerError("Event Decision issuer mismatch")
        if decision.candidate_fingerprint != candidate.fingerprint:
            raise CapitalAllocationLedgerError("Event Decision fingerprint is stale")
        key = economic_event_key(
            issuer_id=candidate.issuer_id,
            event_type=candidate.proposed_event_type,
            event_subtype=candidate.proposed_event_subtype,
            identity_components=candidate.proposed_identity_components,
        )
        if decision.output_economic_event_key != key:
            raise CapitalAllocationLedgerError("Event Decision economic identity is stale")
        if decision.output_event_id != logical_event_id(candidate.issuer_id, key):
            raise CapitalAllocationLedgerError("Event Decision logical Event ID is stale")
        if date.fromisoformat(candidate.as_of_date) > date.fromisoformat(as_of_date):
            raise CapitalAllocationLedgerError("Event Candidate follows compilation cutoff")
        candidate_as_of = date.fromisoformat(candidate.as_of_date)
        announced = date.fromisoformat(candidate.proposed_announcement_date)
        period_start = candidate.proposed_execution_period["start"]
        period_end = candidate.proposed_execution_period["end"]
        if period_end is not None and period_start is None:
            raise CapitalAllocationLedgerError("Event Candidate execution end requires a start")
        if period_start is not None:
            parsed_start = date.fromisoformat(period_start)
            if parsed_start < announced or parsed_start > candidate_as_of:
                raise CapitalAllocationLedgerError("Event Candidate execution start is invalid")
        if period_end is not None:
            parsed_end = date.fromisoformat(period_end)
            if parsed_end < date.fromisoformat(period_start) or parsed_end > candidate_as_of:
                raise CapitalAllocationLedgerError("Event Candidate execution end is invalid")
        if candidate.proposed_source_role == "completion" and period_end is None:
            raise CapitalAllocationLedgerError("completion Candidate requires an execution end")
        if candidate.proposed_source_role == "execution_update" and period_start is None:
            raise CapitalAllocationLedgerError("execution-update Candidate requires a start")
        selected_candidates.append(candidate)
        keys.add(key)
    if len(keys) != 1:
        raise CapitalAllocationLedgerError("Event compilation mixes economic events")
    key = next(iter(keys))
    issuer_ids = {item.issuer_id for item in selected_candidates}
    scopes = {canonical_sha256(item.proposed_scope) for item in selected_candidates}
    announcements = {item.proposed_announcement_date for item in selected_candidates}
    if len(issuer_ids) != 1 or len(scopes) != 1 or len(announcements) != 1:
        raise CapitalAllocationLedgerError("Event compilation has conflicting reviewed semantics")
    issuer_id = next(iter(issuer_ids))
    first = selected_candidates[0]
    source_bindings = []
    fact_bindings = []
    seen_facts: dict[str, str] = {}
    seen_fact_binding_ids: set[str] = set()
    for decision, candidate in sorted(
        zip(active, selected_candidates, strict=True), key=lambda pair: pair[0].decision_id
    ):
        try:
            document = documents[candidate.source_document_id]
        except KeyError as exc:
            raise CapitalAllocationLedgerError("Event source document is unavailable") from exc
        if document.authority_level not in OFFICIAL_AUTHORITY_LEVELS:
            raise CapitalAllocationLedgerError("Event compilation requires official sources")
        if document.issuer_id != candidate.issuer_id:
            raise CapitalAllocationLedgerError("Event source issuer mismatch")
        if document.document_id != candidate.source_document_id:
            raise CapitalAllocationLedgerError("Event Candidate source mismatch")
        source_family(document)
        if date.fromisoformat(document.published_date) > date.fromisoformat(candidate.as_of_date):
            raise CapitalAllocationLedgerError("Event source follows Candidate cutoff")
        if date.fromisoformat(candidate.proposed_announcement_date) > date.fromisoformat(
            document.published_date
        ):
            raise CapitalAllocationLedgerError("Event announcement follows its source")
        if date.fromisoformat(document.published_date) > date.fromisoformat(as_of_date):
            raise CapitalAllocationLedgerError("Event source follows compilation cutoff")
        source_bindings.append(
            {
                "binding_id": _binding_id(decision.decision_id, candidate.proposed_source_role),
                "candidate_id": candidate.candidate_id,
                "decision_id": decision.decision_id,
                "source_document_id": document.document_id,
                "role_id": candidate.proposed_source_role,
            }
        )
        for binding in candidate.proposed_fact_bindings:
            if binding["role_id"] not in policy_for(candidate.proposed_event_type).fact_roles:
                raise CapitalAllocationLedgerError(
                    "Event compilation uses an unregistered Fact role"
                )
            if binding["binding_id"] in seen_fact_binding_ids:
                raise CapitalAllocationLedgerError(
                    "Event compilation repeats a Candidate Fact binding ID"
                )
            seen_fact_binding_ids.add(binding["binding_id"])
            try:
                fact = facts_by_id[binding["fact_id"]]
            except KeyError as exc:
                raise CapitalAllocationLedgerError("Event compilation Fact is unavailable") from exc
            if fact.source_document_id != candidate.source_document_id:
                raise CapitalAllocationLedgerError(
                    "Event compilation Fact belongs to another Candidate source"
                )
            if fact.value_type != "number" or not role_accepts_unit(
                binding["role_id"], unit_spec(fact.unit).family
            ):
                raise CapitalAllocationLedgerError("Event compilation Fact role unit mismatch")
            prior_role = seen_facts.get(binding["fact_id"])
            if prior_role is not None and prior_role != binding["role_id"]:
                raise CapitalAllocationLedgerError("Event Fact has conflicting reviewed roles")
            seen_facts[binding["fact_id"]] = binding["role_id"]
            fact_bindings.append(
                {
                    "binding_id": binding["binding_id"],
                    "candidate_id": candidate.candidate_id,
                    "decision_id": decision.decision_id,
                    "fact_id": binding["fact_id"],
                    "role_id": binding["role_id"],
                }
            )
    fact_bindings = list({item["binding_id"]: item for item in fact_bindings}.values())
    policy = policy_for(first.proposed_event_type)
    source_roles = {item["role_id"] for item in source_bindings}
    fact_roles = {item["role_id"] for item in fact_bindings}
    starts = sorted(
        item.proposed_execution_period["start"]
        for item in selected_candidates
        if item.proposed_execution_period["start"] is not None
    )
    ends = sorted(
        item.proposed_execution_period["end"]
        for item in selected_candidates
        if item.proposed_execution_period["end"] is not None
    )
    execution_period = {"start": starts[0] if starts else None, "end": ends[-1] if ends else None}
    missing: list[str] = []
    if "cancellation" in source_roles:
        lifecycle = "cancelled"
    elif "completion" in source_roles and fact_roles.intersection(policy.completion_roles):
        lifecycle = "completed"
    elif source_roles.intersection({"execution_update", "completion"}) and fact_roles.intersection(
        policy.execution_roles
    ):
        lifecycle = "in_progress"
        if "completion" in source_roles:
            missing.append("completion_fact_role_unresolved")
    elif source_roles.intersection({"authorization", "announcement", "terms"}):
        lifecycle = "announced"
    else:
        lifecycle = "blocked"
        missing.append("lifecycle_source_missing")
    if lifecycle in {"in_progress", "completed"} and execution_period["start"] is None:
        lifecycle = "blocked"
        missing.append("execution_start_missing")
    if lifecycle == "completed" and execution_period["end"] is None:
        lifecycle = "blocked"
        missing.append("execution_end_missing")
    if (
        first.proposed_event_type == "debt_issuance"
        and first.proposed_event_subtype == "refinancing"
        and lifecycle in {"in_progress", "completed"}
        and "debt_refinanced" not in fact_roles
    ):
        lifecycle = "blocked"
        missing.append("refinance_bridge_missing")
    growth_values = {
        item.proposed_growth_classification
        for item in selected_candidates
        if item.proposed_growth_classification != "unknown"
    }
    if len(growth_values) > 1:
        raise CapitalAllocationLedgerError("Event growth classifications conflict")
    growth = next(iter(growth_values), "unknown")
    latest = max(
        (item for item in existing_events if item.economic_event_key == key),
        key=lambda item: item.event_version,
        default=None,
    )
    if latest is not None:
        supplied_decision_ids = {item.decision_id for item in decisions}
        predecessor_decision_ids = {item["decision_id"] for item in latest.source_bindings}.union(
            item["decision_id"] for item in latest.fact_bindings
        )
        omitted = predecessor_decision_ids - supplied_decision_ids
        if omitted:
            raise CapitalAllocationLedgerError(
                "Event compilation omits predecessor review Decisions"
            )
    next_version = 1 if latest is None else latest.event_version + 1
    root_id = logical_event_id(issuer_id, key)
    event_id = root_id if next_version == 1 else f"{root_id}:v{next_version}"
    superseded_event_ids: set[str] = set()
    decision_by_candidate = {
        item.candidate_id: item for item in decisions if item.decision == "confirmed"
    }
    latest_by_key: dict[str, CapitalAllocationEvent] = {}
    for event in existing_events:
        current = latest_by_key.get(event.economic_event_key)
        if current is None or event.event_version > current.event_version:
            latest_by_key[event.economic_event_key] = event
    for candidate in selected_candidates:
        for superseded_candidate_id in candidate.supersedes_candidate_ids:
            prior_decision = decision_by_candidate.get(superseded_candidate_id)
            if prior_decision is None or prior_decision.output_economic_event_key == key:
                continue
            prior_event = latest_by_key.get(prior_decision.output_economic_event_key)
            if prior_event is not None:
                superseded_event_ids.add(prior_event.event_id)
    event = CapitalAllocationEvent(
        schema_version="2.0.0",
        event_id=event_id,
        issuer_id=issuer_id,
        event_policy_id=policy.event_policy_id,
        event_policy_version=EVENT_POLICY_VERSION,
        economic_event_key=key,
        event_version=next_version,
        predecessor_event_id=latest.event_id if latest is not None else None,
        supersedes_event_ids=tuple(sorted(superseded_event_ids)),
        event_type=first.proposed_event_type,
        event_subtype=first.proposed_event_subtype,
        scope=first.proposed_scope,
        identity_components=first.proposed_identity_components,
        announcement_date=first.proposed_announcement_date,
        execution_period=execution_period,
        lifecycle_status=lifecycle,
        source_bindings=tuple(sorted(source_bindings, key=lambda item: item["binding_id"])),
        fact_bindings=tuple(sorted(fact_bindings, key=lambda item: item["binding_id"])),
        claim_bindings=latest.claim_bindings if latest is not None else (),
        rationale_statement_ids=tuple(
            sorted(
                {
                    item_id
                    for item in selected_candidates
                    for item_id in item.proposed_rationale_statement_ids
                }
            )
        ),
        related_commitment_ids=tuple(
            sorted(
                {
                    item_id
                    for item in selected_candidates
                    for item_id in item.proposed_related_commitment_ids
                }
            )
        ),
        growth_classification=growth,
        missing_evidence=tuple(sorted(set(missing))),
    )
    if latest is not None and _event_content(event) == _event_content(latest):
        return EventCompilation(
            event=latest,
            candidate_ids=tuple(sorted(item.candidate_id for item in selected_candidates)),
            decision_ids=tuple(sorted(item.decision_id for item in active)),
            no_change=True,
        )
    return EventCompilation(
        event=event,
        candidate_ids=tuple(sorted(item.candidate_id for item in selected_candidates)),
        decision_ids=tuple(sorted(item.decision_id for item in active)),
        no_change=False,
    )
