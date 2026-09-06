from __future__ import annotations

from copy import deepcopy
from decimal import ROUND_UP, Subnormal, localcontext
from typing import Any

import pytest
from jsonschema.exceptions import ValidationError

from owner_research.fingerprints import canonical_sha256
from owner_research.owner_scorecard import LENS_COMPONENTS
from owner_research.research_report import (
    OwnerScorecardPublicationManifest,
    ResearchReportError,
    ScoreV2PublicationManifest,
    _validate_synthesis_projection_arithmetic,
)
from owner_research.valuation_synthesis_types import validate_extension_payload

_ISSUER_ID = "issuer:score-publication"
_BUNDLE_FINGERPRINT = "a" * 64
_GRAPH_FINGERPRINT = "b" * 64
_COMPOSITE_FINGERPRINT = "c" * 64
_REVIEW_FINGERPRINT = "d" * 64
_EVIDENCE = {
    "object_type": "Fact",
    "object_id": "fact:score-publication",
    "fingerprint": "e" * 64,
}


def _with_source_id(
    payload: dict[str, Any],
    *,
    id_field: str,
    id_prefix: str,
) -> dict[str, Any]:
    source = deepcopy(payload)
    source.pop(id_field, None)
    source[id_field] = f"{id_prefix}:{canonical_sha256(source)[:24]}"
    return source


def _publication_payload(
    source: dict[str, Any],
    *,
    artifact_type: str,
    source_schema: str,
    id_field: str,
) -> dict[str, Any]:
    identity = {
        "schema_version": "1.0.0",
        "artifact_type": artifact_type,
        "issuer_id": source["issuer_id"],
        "source_schema": source_schema,
        "source_object_id": source[id_field],
        "source_fingerprint": canonical_sha256(source),
        "source_payload": source,
    }
    fingerprint = canonical_sha256(identity)
    return {
        **identity,
        "manifest_id": f"{artifact_type}:{source['issuer_id']}:{fingerprint[:24]}",
        "manifest_fingerprint": fingerprint,
    }


def _complete_score_source(lens: str) -> dict[str, Any]:
    payload = {
        "schema_version": "2.0.0",
        "extension_label": "PROJECT_EXTENSION_OWNER_SCORE_V2",
        "issuer_id": _ISSUER_ID,
        "as_of_date": "2026-08-15",
        "lens": lens,
        "status": "complete",
        "research_bundle_fingerprint": _BUNDLE_FINGERPRINT,
        "contract_graph_fingerprint": _GRAPH_FINGERPRINT,
        "review_authority_fingerprint": _REVIEW_FINGERPRINT,
        "composite_valuation_fingerprint": _COMPOSITE_FINGERPRINT,
        "components": [
            {
                "component_id": component_id,
                "status": "complete",
                "score": "10",
                "max_score": "20",
                "confidence_percent": "80",
                "rationale": "Closed publication replay fixture.",
                "evidence_bindings": [_EVIDENCE],
                "missing_evidence": [],
                "red_flags": [],
            }
            for component_id in LENS_COMPONENTS[lens]
        ],
        "total_score": "50",
        "confidence_percent": "80",
        "red_flags": [],
        "missing_evidence": [],
    }
    return _with_source_id(
        payload,
        id_field="score_id",
        id_prefix=f"score-v2:{_ISSUER_ID}:{lens}",
    )


def _partial_score_source(lens: str) -> dict[str, Any]:
    missing = [f"score_review_composite_mismatch:{lens}:{item}" for item in LENS_COMPONENTS[lens]]
    payload = {
        "schema_version": "2.0.0",
        "extension_label": "PROJECT_EXTENSION_OWNER_SCORE_V2",
        "issuer_id": _ISSUER_ID,
        "as_of_date": "2026-08-15",
        "lens": lens,
        "status": "partial",
        "research_bundle_fingerprint": _BUNDLE_FINGERPRINT,
        "contract_graph_fingerprint": _GRAPH_FINGERPRINT,
        "review_authority_fingerprint": _REVIEW_FINGERPRINT,
        "composite_valuation_fingerprint": _COMPOSITE_FINGERPRINT,
        "components": [
            {
                "component_id": component_id,
                "status": "unknown",
                "score": None,
                "max_score": "20",
                "confidence_percent": None,
                "rationale": "The current incomplete conclusion has no matching review.",
                "evidence_bindings": [],
                "missing_evidence": [missing_code],
                "red_flags": [],
            }
            for component_id, missing_code in zip(LENS_COMPONENTS[lens], missing, strict=True)
        ],
        "total_score": None,
        "confidence_percent": None,
        "red_flags": [],
        "missing_evidence": sorted(missing),
    }
    return _with_source_id(
        payload,
        id_field="score_id",
        id_prefix=f"score-v2:{_ISSUER_ID}:{lens}",
    )


def _score_manifest(source: dict[str, Any]) -> ScoreV2PublicationManifest:
    rebound = _with_source_id(
        source,
        id_field="score_id",
        id_prefix=f"score-v2:{source['issuer_id']}:{source['lens']}",
    )
    return ScoreV2PublicationManifest.from_dict(
        _publication_payload(
            rebound,
            artifact_type="score-v2-publication-manifest",
            source_schema="score-v2",
            id_field="score_id",
        )
    )


def _scorecard_source(
    score_manifests: tuple[ScoreV2PublicationManifest, ...],
    *,
    status: str,
) -> dict[str, Any]:
    lens_rows = [
        {
            "lens": manifest.source_payload["lens"],
            "score_id": manifest.source_payload["score_id"],
            "score_fingerprint": manifest.source_fingerprint,
            "status": manifest.source_payload["status"],
            "total_score": manifest.source_payload["total_score"],
            "confidence_percent": manifest.source_payload["confidence_percent"],
        }
        for manifest in score_manifests
    ]
    payload = {
        "schema_version": "1.0.0",
        "extension_label": "PROJECT_EXTENSION_OWNER_SCORECARD_V1",
        "issuer_id": _ISSUER_ID,
        "as_of_date": "2026-08-15",
        "status": status,
        "research_bundle_fingerprint": _BUNDLE_FINGERPRINT,
        "composite_valuation_fingerprint": _COMPOSITE_FINGERPRINT,
        "lens_scores": lens_rows,
        "overall_score": "50" if status == "complete" else None,
        "confidence_percent": "80" if status == "complete" else None,
        "recommendation": "观察" if status == "complete" else "无法评级",
        "current_intrinsic_value": "100" if status == "complete" else None,
        "market_price": "90",
        "margin_of_safety": "0.10" if status == "complete" else None,
        "twelve_month_upside": "0.05" if status == "complete" else None,
        "critical_red_flags": [],
        "issue_codes": (
            []
            if status == "complete"
            else sorted(
                [
                    "composite_valuation_blocked",
                    *(f"{lens}_score_partial" for lens in LENS_COMPONENTS),
                ]
            )
        ),
    }
    return _with_source_id(
        payload,
        id_field="scorecard_id",
        id_prefix=f"owner-scorecard:{_ISSUER_ID}",
    )


def _scorecard_manifest(source: dict[str, Any]) -> OwnerScorecardPublicationManifest:
    rebound = _with_source_id(
        source,
        id_field="scorecard_id",
        id_prefix=f"owner-scorecard:{source['issuer_id']}",
    )
    return OwnerScorecardPublicationManifest.from_dict(
        _publication_payload(
            rebound,
            artifact_type="owner-scorecard-publication-manifest",
            source_schema="owner-scorecard",
            id_field="scorecard_id",
        )
    )


def test_score_publication_rejects_schema_and_semantic_coordinated_rebinding() -> None:
    source = _complete_score_source("graham")
    assert _score_manifest(source).source_payload["total_score"] == "50"

    rubric_rebind = deepcopy(source)
    rubric_rebind["components"][0]["component_id"] = "arbitrary_component"
    with pytest.raises(ResearchReportError, match="source schema is invalid"):
        _score_manifest(rubric_rebind)

    range_rebind = deepcopy(source)
    range_rebind["components"][0]["score"] = "999"
    with pytest.raises(ResearchReportError, match="source schema is invalid"):
        _score_manifest(range_rebind)

    arithmetic_rebind = deepcopy(source)
    arithmetic_rebind["components"][0]["score"] = "11"
    with pytest.raises(ResearchReportError, match="arithmetic does not replay"):
        _score_manifest(arithmetic_rebind)


def test_scorecard_publication_replays_recommendation_after_identity_rebinding() -> None:
    score_manifests = tuple(
        _score_manifest(_complete_score_source(lens)) for lens in LENS_COMPONENTS
    )
    source = _scorecard_source(score_manifests, status="complete")
    assert _scorecard_manifest(source).source_payload["recommendation"] == "观察"

    recommendation_rebind = deepcopy(source)
    recommendation_rebind["recommendation"] = "关注"
    with pytest.raises(ResearchReportError, match="recommendation does not replay"):
        _scorecard_manifest(recommendation_rebind)

    avoid_rebind = deepcopy(source)
    avoid_rebind["recommendation"] = "回避"
    with pytest.raises(ResearchReportError, match="recommendation does not replay"):
        _scorecard_manifest(avoid_rebind)

    warning_rebind = deepcopy(source)
    warning_rebind["critical_red_flags"] = [
        {
            "code": "warning-is-not-critical",
            "severity": "warning",
            "rationale": "A warning cannot enter the critical summary.",
            "evidence_bindings": [_EVIDENCE],
        }
    ]
    with pytest.raises(ResearchReportError, match="source schema is invalid"):
        _scorecard_manifest(warning_rebind)


def test_score_publication_replays_long_decimals_independent_of_ambient_precision() -> None:
    component_score = "10.123456789012345678901234567890123456789"
    total_score = "50.617283945061728394506172839450617283945"
    confidence = "80.123456789012345678901234567890123456789"
    source = _complete_score_source("graham")
    for component in source["components"]:
        component["score"] = component_score
        component["confidence_percent"] = confidence
    source["total_score"] = total_score
    source["confidence_percent"] = confidence

    fingerprints = set()
    for precision, emax in ((2, 0), (4, 1), (28, 1), (80, 1)):
        with localcontext() as context:
            context.prec = precision
            context.rounding = ROUND_UP
            context.Emax = emax
            context.Emin = -1
            context.traps[Subnormal] = True
            manifest = _score_manifest(source)
        fingerprints.add(manifest.fingerprint)

    assert len(fingerprints) == 1
    assert manifest.source_payload["total_score"] == total_score


def test_scorecard_publication_replays_long_lens_totals_independent_of_ambient_precision(
) -> None:
    score_manifests = tuple(
        _score_manifest(_complete_score_source(lens)) for lens in LENS_COMPONENTS
    )
    source = _scorecard_source(score_manifests, status="complete")
    lens_total = "50.123456789012345678901234567890123456789"
    confidence = "80.123456789012345678901234567890123456789"
    for row in source["lens_scores"]:
        row["total_score"] = lens_total
        row["confidence_percent"] = confidence
    source["overall_score"] = lens_total
    source["confidence_percent"] = confidence

    fingerprints = set()
    for precision, emax in ((2, 0), (4, 1), (28, 1), (80, 1)):
        with localcontext() as context:
            context.prec = precision
            context.rounding = ROUND_UP
            context.Emax = emax
            context.Emin = -1
            context.traps[Subnormal] = True
            manifest = _scorecard_manifest(source)
        fingerprints.add(manifest.fingerprint)

    assert len(fingerprints) == 1
    assert manifest.source_payload["overall_score"] == lens_total


def test_scorecard_publication_uses_exact_overvaluation_basis_at_rounded_boundary() -> None:
    score_manifests = tuple(
        _score_manifest(_complete_score_source(lens)) for lens in LENS_COMPONENTS
    )
    below_threshold = _scorecard_source(score_manifests, status="complete")
    below_threshold["current_intrinsic_value"] = "1." + "0" * 89 + "1"
    below_threshold["market_price"] = "1.15"
    below_threshold["margin_of_safety"] = "-0.15"
    below_threshold["recommendation"] = "观察"
    assert _scorecard_manifest(below_threshold).source_payload["recommendation"] == "观察"

    exact_threshold = deepcopy(below_threshold)
    exact_threshold["current_intrinsic_value"] = "1"
    exact_threshold["recommendation"] = "回避"
    assert _scorecard_manifest(exact_threshold).source_payload["recommendation"] == "回避"


def test_score_publication_matches_the_closed_builder_decimal_domain() -> None:
    in_domain = "10." + "0" * 999 + "1"
    exact_total = "50." + "0" * 999 + "5"
    source = _complete_score_source("graham")
    for component in source["components"]:
        component["score"] = in_domain
    source["total_score"] = exact_total
    assert _score_manifest(source).source_payload["total_score"] == exact_total

    rounded_total = deepcopy(source)
    rounded_total["total_score"] = "50"
    with pytest.raises(ResearchReportError, match="arithmetic does not replay"):
        _score_manifest(rounded_total)

    out_of_domain = deepcopy(source)
    for component in out_of_domain["components"]:
        component["score"] = "10." + "0" * 1199 + "1"
    out_of_domain["total_score"] = "50"
    with pytest.raises(ResearchReportError, match="bounded decimal domain"):
        _score_manifest(out_of_domain)

    score_manifests = tuple(
        _score_manifest(_complete_score_source(lens)) for lens in LENS_COMPONENTS
    )
    scorecard = _scorecard_source(score_manifests, status="complete")
    for row in scorecard["lens_scores"]:
        row["total_score"] = "50." + "0" * 1199 + "1"
    scorecard["overall_score"] = "50"
    with pytest.raises(ResearchReportError, match="bounded decimal domain"):
        _scorecard_manifest(scorecard)


def test_blocked_publication_keeps_every_unknown_and_aggregate_null() -> None:
    score_manifests = tuple(
        _score_manifest(_partial_score_source(lens)) for lens in LENS_COMPONENTS
    )
    scorecard = _scorecard_source(score_manifests, status="blocked")

    validate_extension_payload("owner-scorecard", scorecard)
    _validate_synthesis_projection_arithmetic("owner-scorecard", scorecard)
    manifest = _scorecard_manifest(scorecard)

    assert all(row["status"] == "partial" for row in scorecard["lens_scores"])
    assert all(row["total_score"] is None for row in scorecard["lens_scores"])
    assert scorecard["overall_score"] is None
    assert scorecard["confidence_percent"] is None
    assert scorecard["recommendation"] == "无法评级"
    assert manifest.source_payload["overall_score"] is None


@pytest.mark.parametrize("status", ("blocked", "partial"))
def test_incomplete_scorecard_publication_checks_market_price_domain(status: str) -> None:
    score_manifests = tuple(
        _score_manifest(_partial_score_source(lens)) for lens in LENS_COMPONENTS
    )
    scorecard = _scorecard_source(score_manifests, status=status)
    scorecard["market_price"] = "1" + "0" * 1200

    with pytest.raises(ResearchReportError, match="bounded decimal domain"):
        _scorecard_manifest(scorecard)


def test_blocked_scorecard_rejects_four_complete_lenses() -> None:
    score_manifests = tuple(
        _score_manifest(_complete_score_source(lens)) for lens in LENS_COMPONENTS
    )
    scorecard = _scorecard_source(score_manifests, status="blocked")

    with pytest.raises(ValidationError):
        validate_extension_payload("owner-scorecard", scorecard)
    with pytest.raises(ResearchReportError, match="status does not replay"):
        _validate_synthesis_projection_arithmetic("owner-scorecard", scorecard)


def test_unknown_component_with_numeric_value_fails_the_public_schema() -> None:
    payload = _partial_score_source("graham")
    payload["components"][0]["score"] = "0"

    with pytest.raises(ValidationError):
        validate_extension_payload("score-v2", payload)
