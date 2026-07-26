from __future__ import annotations

import copy

from owner_research.contracts import contract_from_dict
from owner_research.promotion import evaluate_candidate


def test_exact_primary_ixbrl_candidate_can_auto_promote(sample_payloads: dict[str, dict]) -> None:
    source = contract_from_dict("source-document", sample_payloads["source-document"])
    artifact = contract_from_dict("filing-artifact", sample_payloads["filing-artifact"])
    candidate = contract_from_dict("extraction-candidate", sample_payloads["extraction-candidate"])
    outcome = evaluate_candidate(
        candidate,
        source=source,
        artifact=artifact,
        reviewed_at="2026-02-16T02:00:00Z",
        duplicates_resolved=True,
        reconciliation_resolved=True,
    )
    assert outcome.promotion.decision == "auto_fact"
    assert outcome.fact is not None
    assert outcome.fact.value == candidate.value


def test_language_model_candidate_never_auto_promotes(sample_payloads: dict[str, dict]) -> None:
    payload = copy.deepcopy(sample_payloads["extraction-candidate"])
    payload.update(
        candidate_kind="claim_draft",
        value_type="text",
        value="Management expects durable growth.",
        unit=None,
        currency=None,
        extraction_method="language_model",
        high_impact=True,
    )
    candidate = contract_from_dict("extraction-candidate", payload)
    outcome = evaluate_candidate(
        candidate,
        source=contract_from_dict("source-document", sample_payloads["source-document"]),
        artifact=contract_from_dict("filing-artifact", sample_payloads["filing-artifact"]),
        reviewed_at="2026-02-16T02:00:00Z",
    )
    assert outcome.fact is None
    assert outcome.promotion.decision == "blocked"
    assert "language_model_cannot_auto_promote" in outcome.promotion.issues


def test_duplicate_or_reconciliation_conflict_blocks_auto_promotion(
    sample_payloads: dict[str, dict],
) -> None:
    outcome = evaluate_candidate(
        contract_from_dict("extraction-candidate", sample_payloads["extraction-candidate"]),
        source=contract_from_dict("source-document", sample_payloads["source-document"]),
        artifact=contract_from_dict("filing-artifact", sample_payloads["filing-artifact"]),
        reviewed_at="2026-02-16T02:00:00Z",
        duplicates_resolved=False,
        reconciliation_resolved=False,
    )
    assert outcome.promotion.decision == "blocked"
    assert set(outcome.promotion.issues) >= {"duplicates_resolved", "reconciliation_resolved"}
