from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import pytest
import test_phase5e2b12a_integration_contracts as fixtures

import owner_research.valuation_current_share_compiler as compiler
from owner_research.validation import ContractGraph
from owner_research.valuation_share_event_grouping import ShareEventGroupingError


@dataclass(frozen=True)
class _ClosureProbe:
    output_share_fact_id: str
    object_fingerprints: tuple[tuple[str, str, str], ...] = ()


class _Artifact:
    fingerprint = "f" * 64

    def to_dict(self) -> dict[str, str]:
        return {
            "issuer_id": fixtures.ISSUER,
            "data_cutoff_date": fixtures.CUTOFF,
            "protected_mckinsey_sha256": "a" * 64,
            "protected_penman_assumptions_sha256": "b" * 64,
        }


class _Authority:
    standard_path_disposition = "eligible"

    @classmethod
    def from_price_blind_artifact(cls, _artifact: object) -> _Authority:
        return cls()


def _compile(
    monkeypatch: pytest.MonkeyPatch,
    *,
    group_specs: tuple[tuple[int, str, str], ...],
    reverse_inputs: bool = False,
):
    raw_facts = []
    sources = []
    candidates = []
    decisions = []
    events = []
    for count, concept, suffix in group_specs:
        (
            _grouping,
            group_facts,
            group_sources,
            group_candidates,
            group_decisions,
            event,
        ) = fixtures._grouping(
            corroborating_count=count,
            concept=concept,
            identity_suffix=suffix,
        )
        raw_facts.extend(group_facts)
        sources.extend(group_sources)
        candidates.extend(group_candidates)
        decisions.extend(group_decisions)
        events.append(event)

    opening_source, _ = fixtures._coverage_documents()
    opening = fixtures._fact(
        fact_id="fact:2b:opening",
        concept="common_shares_outstanding",
        value=100_000_000,
        source=opening_source,
        end=fixtures.OPENING_DATE,
    )
    security_facts, claim, analytical_candidate, analytical_review, security = (
        fixtures._security_evidence(opening_source)
    )
    values = {
        "documents": (*sources, opening_source),
        "facts": (*raw_facts, opening, *security_facts),
        "capital_allocation_event_candidates": tuple(candidates),
        "capital_allocation_event_review_decisions": tuple(decisions),
        "capital_allocation_events": tuple(events),
    }
    if reverse_inputs:
        values = {key: tuple(reversed(value)) for key, value in values.items()}
    graph = ContractGraph(
        documents=values["documents"],
        facts=values["facts"],
        claims=(claim,),
        analytical_claim_candidates=(analytical_candidate,),
        analytical_claim_review_decisions=(analytical_review,),
        capital_allocation_event_candidates=values[
            "capital_allocation_event_candidates"
        ],
        capital_allocation_event_review_decisions=values[
            "capital_allocation_event_review_decisions"
        ],
        capital_allocation_events=values["capital_allocation_events"],
        component_lock_path=fixtures.ROOT / "component-lock.json",
    )
    graph.validate()

    artifact = _Artifact()
    freeze = SimpleNamespace(
        artifact=artifact,
        handoffs=(SimpleNamespace(handoff_id="handoff:2b"),),
    )
    access = SimpleNamespace(
        status="eligible",
        request=SimpleNamespace(
            authorization_handoff_id="handoff:2b",
            security_id=fixtures.SECURITY,
        ),
        receipt=SimpleNamespace(
            security_compilation_fingerprint=security.fingerprint,
            receipt=SimpleNamespace(trading_date=fixtures.QUOTE_DATE),
        ),
        issuer_id=fixtures.ISSUER,
        data_cutoff_date=fixtures.CUTOFF,
        authorization_handoff_id="handoff:2b",
        price_blind_input_fingerprint=artifact.fingerprint,
        protected_mckinsey_sha256="a" * 64,
        protected_penman_assumptions_sha256="b" * 64,
    )
    monkeypatch.setattr(
        compiler,
        "load_price_blind_input_artifact",
        lambda *args, **kwargs: freeze,
    )
    monkeypatch.setattr(
        compiler,
        "compile_security_identity",
        lambda *args, **kwargs: security,
    )
    monkeypatch.setattr(compiler, "Phase5CDilutionClaimAuthority", _Authority)
    monkeypatch.setattr(
        compiler,
        "derive_current_share_evidence_closure",
        lambda **kwargs: _ClosureProbe(kwargs["share_fact"].fact_id),
    )
    return compiler.compile_quote_date_current_common_shares(
        price_blind_artifact_directory=Path("/unused"),
        graph=graph,
        expected_freeze=freeze,
        expected_security=security,
        expected_market_access=access,
    )


def _one_repurchase(monkeypatch: pytest.MonkeyPatch, sources: int):
    return _compile(
        monkeypatch,
        group_specs=(
            (sources, "common_shares_repurchased_completed", "repurchase-a"),
        ),
    )


def test_canonical_event_two_sources_is_consumed_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _one_repurchase(monkeypatch, 2)
    assert result.status == "eligible"
    assert result.output_fact is not None
    assert result.output_fact.value == 95_000_000
    assert len(result.canonical_rollforward.materializations) == 1
    assert len(result.canonical_rollforward.numeric_consumptions) == 1


def test_canonical_event_three_sources_is_consumed_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _one_repurchase(monkeypatch, 3)
    assert result.output_fact is not None
    assert result.output_fact.value == 95_000_000
    assert len(result.canonical_rollforward.numeric_consumptions) == 1


def test_canonical_event_magnitude_conflict_blocks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        compiler,
        "group_governed_completed_share_events",
        lambda **kwargs: (_ for _ in ()).throw(
            ShareEventGroupingError("blocked_share_event_conflict")
        ),
    )
    result = _one_repurchase(monkeypatch, 2)
    assert result.status == "blocked"


def test_canonical_event_date_conflict_blocks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        compiler,
        "group_governed_completed_share_events",
        lambda **kwargs: (_ for _ in ()).throw(
            ShareEventGroupingError("blocked_share_event_conflict")
        ),
    )
    result = _one_repurchase(monkeypatch, 2)
    assert result.status == "blocked"


def test_distinct_legal_event_ids_are_consumed_independently(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _compile(
        monkeypatch,
        group_specs=(
            (2, "common_shares_repurchased_completed", "repurchase-a"),
            (2, "common_shares_issued_completed", "issuance-b"),
        ),
    )
    assert result.output_fact is not None
    assert result.output_fact.value == 100_000_000
    assert len(result.canonical_rollforward.numeric_consumptions) == 2


def test_missing_legal_identity_blocks(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        compiler,
        "group_governed_completed_share_events",
        lambda **kwargs: (_ for _ in ()).throw(
            ShareEventGroupingError("blocked_share_event_identity_ambiguous")
        ),
    )
    assert _one_repurchase(monkeypatch, 2).status == "blocked"


def test_same_day_same_amount_without_distinct_legal_ids_blocks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        compiler,
        "group_governed_completed_share_events",
        lambda **kwargs: (_ for _ in ()).throw(
            ShareEventGroupingError("blocked_share_event_identity_ambiguous")
        ),
    )
    assert _one_repurchase(monkeypatch, 2).status == "blocked"


def test_option_event_is_consumed_once_per_canonical_group(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _one_repurchase(monkeypatch, 3)
    groups = tuple(
        item.group_id for item in result.canonical_rollforward.numeric_consumptions
    )
    assert len(groups) == len(set(groups)) == 1


def test_event_input_order_is_irrelevant(monkeypatch: pytest.MonkeyPatch) -> None:
    regular = _one_repurchase(monkeypatch, 3)
    reversed_result = _compile(
        monkeypatch,
        group_specs=(
            (3, "common_shares_repurchased_completed", "repurchase-a"),
        ),
        reverse_inputs=True,
    )
    assert regular.to_dict() == reversed_result.to_dict()


def test_corroborating_source_changes_closure_not_share_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    two = _one_repurchase(monkeypatch, 2)
    three = _one_repurchase(monkeypatch, 3)
    assert two.output_fact.value == three.output_fact.value
    assert (
        two.canonical_rollforward.rollforward_fingerprint
        != three.canonical_rollforward.rollforward_fingerprint
    )


def test_cumulative_event_fact_cannot_be_consumed_as_an_increment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        compiler,
        "group_governed_completed_share_events",
        lambda **kwargs: (_ for _ in ()).throw(
            ShareEventGroupingError("blocked_share_event_identity_ambiguous")
        ),
    )
    assert _one_repurchase(monkeypatch, 2).status == "blocked"


def test_canonical_event_fact_preserves_all_member_lineage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _one_repurchase(monkeypatch, 3)
    materialization = result.canonical_rollforward.materializations[0]
    assert materialization.canonical_event_fact.parent_fact_ids == tuple(
        sorted(item.fact_id for item in materialization.members)
    )
