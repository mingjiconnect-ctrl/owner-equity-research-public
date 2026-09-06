from __future__ import annotations

from decimal import ROUND_UP, Decimal, Subnormal, localcontext
from types import SimpleNamespace
from typing import Any

import pytest
from test_phase5_v1_valuation_synthesis import (
    _bundle_fact_binding,
    _complete_synthesis,
    _contested_composite,
    _review,
)

from owner_research.fingerprints import canonical_sha256, to_json_value
from owner_research.owner_scorecard import (
    LENS_COMPONENTS,
    CompositeScoreGapAuthority,
    OwnerScorecardError,
    build_owner_scorecard,
    build_score_v2,
    resolve_score_review_authority,
)
from owner_research.validation import ContractGraph
from owner_research.valuation_synthesis import build_composite_valuation
from owner_research.valuation_synthesis_types import (
    ExtensionAuthorityError,
    retained_authority_replay_scope,
)


def _components(
    lens: str,
    binding: dict[str, str],
    *,
    score: str = "17",
    confidence: str = "90",
    unknown: bool = False,
    permanent_loss: bool = False,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for index, component_id in enumerate(LENS_COMPONENTS[lens]):
        is_unknown = unknown and index == 0
        flags = []
        if permanent_loss and index == 0:
            flags = [
                {
                    "code": f"flag:{lens}:permanent-loss",
                    "severity": "permanent_loss",
                    "rationale": "Evidence identifies a permanent-loss condition.",
                    "evidence_bindings": [binding],
                }
            ]
        rows.append(
            {
                "component_id": component_id,
                "status": "unknown" if is_unknown else "complete",
                "score": None if is_unknown else score,
                "confidence_percent": None if is_unknown else confidence,
                "rationale": (
                    "Evidence is unavailable for this component."
                    if is_unknown
                    else "The retained evidence supports this component score."
                ),
                "evidence_bindings": [] if is_unknown else [binding],
                "missing_evidence": [f"missing:{component_id}"] if is_unknown else [],
                "red_flags": flags,
            }
        )
    return rows


@retained_authority_replay_scope
def _lens_scores(
    run_result,
    composite,
    *,
    score: str = "17",
    confidence: str = "90",
    partial_lens: str | None = None,
    permanent_loss_lens: str | None = None,
):
    binding = _bundle_fact_binding(run_result)
    output = []
    for lens in LENS_COMPONENTS:
        components = _components(
            lens,
            binding,
            score=score,
            confidence=confidence,
            unknown=lens == partial_lens,
            permanent_loss=lens == permanent_loss_lens,
        )
        planned_review = _review(
            run_result,
            scope=f"score:{lens}",
            reviewed_at="2026-08-15T01:07:00Z",
            reviewed_payload={
                "composite_valuation_fingerprint": composite.fingerprint,
                "components": components,
            },
        )
        output.append(
            build_score_v2(
                composite_valuation=composite,
                review_authority=resolve_score_review_authority(
                    composite_valuation=composite,
                    planned_review=planned_review,
                ),
            )
        )
    return tuple(output)


@retained_authority_replay_scope
def _lens_scorecard(run_result, composite, **score_options):
    scores = _lens_scores(run_result, composite, **score_options)
    return scores, build_owner_scorecard(
        composite_valuation=composite,
        lens_scores=scores,
    )


def test_four_complete_graph_bound_lenses_average_without_mutating_valuation(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    run_result, *_, composite, scores, scorecard = _complete_synthesis(
        sample_payloads, monkeypatch, tmp_path
    )
    before = composite.to_dict()

    assert {item.lens for item in scores} == set(LENS_COMPONENTS)
    assert all(item.total_score == "85" for item in scores)
    assert scorecard.overall_score == "85"
    assert scorecard.composite_valuation_fingerprint == composite.fingerprint
    assert composite.to_dict() == before
    assert all(
        item.contract_graph_fingerprint == run_result.input_receipt.graph_fingerprint
        for item in scores
    )


def test_score_builders_ignore_the_ambient_decimal_context(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    run_result, *_, composite, _scores, _scorecard = _complete_synthesis(
        sample_payloads, monkeypatch, tmp_path
    )
    score = "10.123456789012345678901234567890123456789"
    confidence = "80.123456789012345678901234567890123456789"
    binding = _bundle_fact_binding(run_result)
    reviews = tuple(
        _review(
            run_result,
            scope=f"score:{lens}",
            reviewed_at="2026-08-15T01:07:00Z",
            reviewed_payload={
                "composite_valuation_fingerprint": composite.fingerprint,
                "components": _components(
                    lens,
                    binding,
                    score=score,
                    confidence=confidence,
                ),
            },
        )
        for lens in LENS_COMPONENTS
    )

    with localcontext() as context:
        context.prec = 2
        context.rounding = ROUND_UP
        context.Emax = 0
        context.Emin = -1
        context.traps[Subnormal] = True
        scores = tuple(
            build_score_v2(
                composite_valuation=composite,
                review_authority=resolve_score_review_authority(
                    composite_valuation=composite,
                    planned_review=review,
                ),
            )
            for review in reviews
        )
        scorecard = build_owner_scorecard(
            composite_valuation=composite,
            lens_scores=scores,
        )

    assert all(
        item.total_score == "50.617283945061728394506172839450617283945"
        for item in scores
    )
    assert scorecard.overall_score == "50.617283945061728394506172839450617283945"


def test_score_builder_decimal_domain_is_closed() -> None:
    import owner_research.owner_scorecard as scorecard_module

    in_domain = "10." + "0" * 999 + "1"
    assert scorecard_module._decimal(in_domain, "component score") == Decimal(in_domain)
    with pytest.raises(OwnerScorecardError, match="bounded decimal domain"):
        scorecard_module._decimal(
            "10." + "0" * 1199 + "1",
            "component score",
        )


def test_unknown_is_partial_never_zero_and_mixed_string_types_fail_closed(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    run_result, *_, composite, _scores, _scorecard = _complete_synthesis(
        sample_payloads, monkeypatch, tmp_path
    )
    scores, scorecard = _lens_scorecard(
        run_result,
        composite,
        partial_lens="graham",
    )

    graham = scores[0]
    assert graham.status == "partial"
    assert graham.total_score is None
    assert graham.components[0]["score"] is None
    assert scorecard.recommendation == "无法评级"

    binding = _bundle_fact_binding(run_result)
    invalid = _components("graham", binding, unknown=True)
    invalid[0]["missing_evidence"] = ["missing", 1]
    review = _review(
        run_result,
        scope="score:graham",
        reviewed_at="2026-08-15T01:08:00Z",
        reviewed_payload={
            "composite_valuation_fingerprint": composite.fingerprint,
            "components": invalid,
        },
    )
    with pytest.raises(OwnerScorecardError, match="nonempty strings"):
        build_score_v2(composite_valuation=composite, review_authority=review)


def test_fixed_recommendation_order_and_permanent_loss_override(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    run_result, *_, composite, _scores, _scorecard = _complete_synthesis(
        sample_payloads, monkeypatch, tmp_path
    )
    import owner_research.owner_scorecard as scorecard_module

    expected = {"16": "重点关注", "14": "关注", "12": "观察", "9": "回避"}
    for component_score, recommendation in expected.items():
        assert scorecard_module._recommendation(
            status="complete",
            composite=SimpleNamespace(
                status="complete",
                recommendation_eligible=True,
                contested=False,
                current_intrinsic_value="100",
                market_price="75",
                margin_of_safety="0.25",
                twelve_month_upside="0.20",
            ),
            overall=Decimal(component_score) * 5,
            confidence=Decimal("90"),
            critical_flags=(),
        ) == recommendation

    for intrinsic, recommendation in (
        ("1." + "0" * 89 + "1", "观察"),
        ("1", "回避"),
    ):
        assert scorecard_module._recommendation(
            status="complete",
            composite=SimpleNamespace(
                status="complete",
                recommendation_eligible=True,
                contested=False,
                current_intrinsic_value=intrinsic,
                market_price="1.15",
                margin_of_safety="-0.15",
                twelve_month_upside="0.05",
            ),
            overall=Decimal("60"),
            confidence=Decimal("80"),
            critical_flags=(),
        ) == recommendation

    _overvalued_scores, overvalued = _lens_scorecard(
        run_result,
        composite,
        score="16",
        confidence="90",
    )
    assert overvalued.recommendation == "回避"

    _flagged_scores, flagged = _lens_scorecard(
        run_result,
        composite,
        permanent_loss_lens="munger",
    )
    assert flagged.recommendation == "回避"
    assert flagged.critical_red_flags[0]["severity"] == "permanent_loss"


def test_coordinated_score_replace_cannot_rebind_total_or_review_authority(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    _run_result, *_, _composite, scores, _scorecard = _complete_synthesis(
        sample_payloads, monkeypatch, tmp_path
    )
    score = scores[0]
    payload = score.to_dict()
    payload["total_score"] = "99"
    payload.pop("score_id")
    payload["score_id"] = (
        f"score-v2:{score.issuer_id}:{score.lens}:{canonical_sha256(payload)[:24]}"
    )

    from dataclasses import replace

    with pytest.raises(ValueError, match="does not replay"):
        replace(score, total_score="99", score_id=payload["score_id"])

    with pytest.raises(
        ExtensionAuthorityError,
        match="does not retain a graph ResearchBundle",
    ):
        replace(score._review_authority, graph=ContractGraph())


def test_score_review_cannot_rebind_to_another_composite(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    run_result, basis, forward, _peer_authority, comparables, composite, scores, _ = (
        _complete_synthesis(sample_payloads, monkeypatch, tmp_path)
    )
    stale_complete_review = _review(
        run_result,
        scope="score:graham",
        reviewed_at="2026-08-15T01:08:00Z",
        reviewed_payload={
            "composite_valuation_fingerprint": "f" * 64,
            "components": to_json_value(scores[0].components),
        },
    )
    with pytest.raises(
        OwnerScorecardError,
        match="score review is bound to another composite valuation",
    ):
        resolve_score_review_authority(
            composite_valuation=composite,
            planned_review=stale_complete_review,
        )

    contested = _contested_composite(run_result, basis, forward, comparables)

    assert contested.fingerprint != composite.fingerprint
    with pytest.raises(
        OwnerScorecardError,
        match="score review is bound to another composite valuation",
    ):
        build_score_v2(
            composite_valuation=contested,
            review_authority=scores[0]._review_authority,
        )

    blocked = build_composite_valuation(
        run_result,
        basis_receipt=basis,
        forward_reoi=forward,
        comparables=None,
    )
    matching_blocked_review = _review(
        run_result,
        scope="score:graham",
        reviewed_at="2026-08-15T01:08:00Z",
        reviewed_payload={
            "composite_valuation_fingerprint": blocked.fingerprint,
            "components": to_json_value(scores[0].components),
        },
    )
    with pytest.raises(
        OwnerScorecardError,
        match="ineligible composite requires typed score gap authority",
    ):
        build_score_v2(
            composite_valuation=blocked,
            review_authority=matching_blocked_review,
        )
    gap = resolve_score_review_authority(
        composite_valuation=blocked,
        planned_review=matching_blocked_review,
    )
    assert type(gap) is CompositeScoreGapAuthority
    assert gap.issue_codes == ("composite_valuation_ineligible:graham",)
    assert gap.to_dict()["planned_review_fingerprint"] == matching_blocked_review.fingerprint
    blocked_score = build_score_v2(
        composite_valuation=blocked,
        review_authority=gap,
    )
    assert blocked_score.status == "partial"
    assert blocked_score.total_score is None
    assert all(item["status"] == "unknown" for item in blocked_score.components)
    assert all(
        "recommendation-ineligible" in item["rationale"]
        and "another composite" not in item["rationale"]
        for item in blocked_score.components
    )


def test_contested_composite_forces_unratable_recommendation(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    run_result, basis, forward, _peer_authority, comparables, *_ = _complete_synthesis(
        sample_payloads, monkeypatch, tmp_path
    )
    contested = _contested_composite(run_result, basis, forward, comparables)
    lens_scores, scorecard = _lens_scorecard(run_result, contested)

    assert contested.recommendation_eligible is False
    assert all(score.status == "partial" for score in lens_scores)
    assert all(score.total_score is None for score in lens_scores)
    assert all(
        component["status"] == "unknown" and component["score"] is None
        for score in lens_scores
        for component in score.components
    )
    assert scorecard.status == "blocked"
    assert scorecard.overall_score is None
    assert scorecard.confidence_percent is None
    assert scorecard.recommendation == "无法评级"
