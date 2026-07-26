from __future__ import annotations

from dataclasses import replace

from phase4a_support import replace_graph, valid_phase4a_graph

from owner_research.management_reviews import build_management_review


def _build(graph, **updates):
    values = {
        "issuer_id": "issuer:acme",
        "review_period": {"start": "2026-01-01", "end": "2026-06-30"},
        "as_of_date": "2026-06-30",
        "statements": graph.management_statements,
        "commitments": graph.management_commitments,
        "outcomes": graph.management_outcomes,
        "claims": graph.claims,
        "calculations": graph.calculations,
        "review_claim_ids": (graph.claims[0].claim_id,),
        "explicit_missing_evidence": (),
    }
    values.update(updates)
    return build_management_review(**values)


def test_builder_selects_objects_and_recomputes_complete_coverage(
    sample_payloads: dict[str, dict],
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    review = _build(graph)
    assert review.status == "complete"
    assert review.statement_ids == (graph.management_statements[0].statement_id,)
    assert review.commitment_ids == (graph.management_commitments[0].commitment_id,)
    assert review.outcome_ids == (graph.management_outcomes[0].outcome_id,)
    assert review.coverage["not_due_count"] == 1
    assert review.coverage["due_count"] == 0
    assert review.coverage["pending_count"] == 1
    replace_graph(graph, management_reviews=(review,)).validate()


def test_due_commitment_without_final_outcome_blocks_review(
    sample_payloads: dict[str, dict],
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    review = _build(
        graph,
        review_period={"start": "2026-01-01", "end": "2027-01-31"},
        as_of_date="2027-01-31",
    )
    assert review.status == "blocked"
    assert review.coverage["due_count"] == 1
    assert review.coverage["evaluated_due_count"] == 0
    assert "due_commitment_without_final_outcome" in review.missing_evidence


def test_unverifiable_due_outcome_yields_partial_not_complete(
    sample_payloads: dict[str, dict],
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    outcome = replace(
        graph.management_outcomes[0],
        assessed_at="2027-01-15",
        evaluation_period={"start": "2026-01-01", "end": "2026-12-31"},
        status="unverifiable",
        missing_evidence=("official_result_not_disclosed",),
    )
    review = _build(
        graph,
        review_period={"start": "2026-01-01", "end": "2027-01-31"},
        as_of_date="2027-01-31",
        outcomes=(outcome,),
    )
    assert review.status == "partial"
    assert review.coverage["unverifiable_count"] == 1
    assert "official_result_not_disclosed" in review.missing_evidence
    replace_graph(
        graph,
        management_outcomes=(outcome,),
        management_reviews=(review,),
    ).validate()


def test_lifecycle_commitment_is_never_due_or_missed(
    sample_payloads: dict[str, dict],
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    commitment = replace(
        graph.management_commitments[0],
        status="withdrawn",
        withdrawal_statement_id=graph.management_statements[0].statement_id,
    )
    outcome = replace(
        graph.management_outcomes[0],
        status="withdrawn",
        result_bindings=(),
        missing_evidence=(),
    )
    review = _build(graph, commitments=(commitment,), outcomes=(outcome,))
    assert review.status == "complete"
    assert review.coverage["due_count"] == 0
    assert review.coverage["missed_count"] == 0
    assert review.coverage["withdrawn_count"] == 1
    replace_graph(
        graph,
        management_commitments=(commitment,),
        management_outcomes=(outcome,),
        management_reviews=(review,),
    ).validate()


def test_lifecycle_commitment_without_lifecycle_outcome_is_blocked(
    sample_payloads: dict[str, dict],
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    commitment = replace(
        graph.management_commitments[0],
        status="superseded",
        superseded_by_commitment_id="commitment:successor",
    )
    review = _build(graph, commitments=(commitment,), outcomes=())
    assert review.status == "blocked"
    assert "lifecycle_outcome_missing" in review.missing_evidence


def test_cross_issuer_objects_do_not_pollute_review(
    sample_payloads: dict[str, dict],
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    foreign_statement = replace(
        graph.management_statements[0],
        statement_id="statement:foreign",
        issuer_id="issuer:foreign",
    )
    review = _build(graph, statements=(*graph.management_statements, foreign_statement))
    assert foreign_statement.statement_id not in review.statement_ids


def test_missing_review_claim_blocks_instead_of_fabricating_completion(
    sample_payloads: dict[str, dict],
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    review = _build(graph, review_claim_ids=(), outcomes=())
    assert review.status == "blocked"
    assert "review_claim_missing" in review.missing_evidence
