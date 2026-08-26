from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

from owner_research.contracts import SourceDocument
from owner_research.fingerprints import canonical_sha256
from owner_research.research_report import (
    _RESEARCH_ONLY_FORBIDDEN_TEXT,
    _content_status_with_scorecard,
    _decision_summary_paragraphs,
    _full_valuation_decision_summary,
    _humanized_machine_label,
    _latex_table_cell,
    _object_paragraph,
    _report_content_charts,
    _report_decimal,
    _report_ratio_percent,
    _report_value,
    _retained_scorecard_status,
    _source_document_apa7_metadata,
)


@dataclass(frozen=True)
class _BlockedCompositeStub:
    result_id: str = "composite:blocked"
    status: str = "blocked"
    basis_receipt: dict[str, str] | None = None
    fingerprint: str = "e" * 64

    def __post_init__(self) -> None:
        if self.basis_receipt is None:
            object.__setattr__(self, "basis_receipt", {"currency": "USD"})

    def to_dict(self) -> dict[str, object]:
        return {
            "result_id": self.result_id,
            "status": self.status,
            "basis_receipt": self.basis_receipt,
            "panel_scenarios": {},
        }


@dataclass(frozen=True)
class _PartialLensScoreStub:
    lens: str
    score_id: str
    status: str = "partial"
    total_score: None = None
    fingerprint: str = "f" * 64

    def to_dict(self) -> dict[str, object]:
        return {
            "score_id": self.score_id,
            "lens": self.lens,
            "status": self.status,
            "total_score": self.total_score,
        }


@dataclass(frozen=True)
class _BundleStub:
    bundle_id: str = "research-bundle:test"
    status: str = "complete"
    fingerprint: str = "c" * 64

    def to_dict(self) -> dict[str, str]:
        return {"bundle_id": self.bundle_id, "status": self.status}


@dataclass(frozen=True)
class _CompositeStub:
    result_id: str = "composite:test"
    status: str = "complete"
    market_price: str = "75"
    current_intrinsic_value: str | None = "100"
    twelve_month_target: str | None = "120"
    margin_of_safety: str | None = "0.25"
    twelve_month_upside: str | None = "0.60"
    issue_codes: tuple[str, ...] = ()
    fingerprint: str = "a" * 64

    def to_dict(self) -> dict[str, object]:
        return {
            "result_id": self.result_id,
            "status": self.status,
            "market_price": self.market_price,
            "current_intrinsic_value": self.current_intrinsic_value,
            "twelve_month_target": self.twelve_month_target,
            "margin_of_safety": self.margin_of_safety,
            "twelve_month_upside": self.twelve_month_upside,
            "issue_codes": list(self.issue_codes),
        }


@dataclass(frozen=True)
class _ScorecardStub:
    scorecard_id: str = "scorecard:test"
    recommendation: str = "重点关注"
    overall_score: int | None = 0
    confidence_percent: int | None = 0
    issue_codes: tuple[str, ...] = ()
    fingerprint: str = "b" * 64

    def to_dict(self) -> dict[str, object]:
        return {
            "scorecard_id": self.scorecard_id,
            "recommendation": self.recommendation,
            "overall_score": self.overall_score,
            "confidence_percent": self.confidence_percent,
            "issue_codes": list(self.issue_codes),
        }


@dataclass(frozen=True)
class _MarketExpectationsStub:
    comparison_id: str = "market-expectations:test"
    status: str = "partial"
    issue_codes: tuple[str, ...] = ("market_expectations_missing:analyst_consensus",)
    fingerprint: str = "d" * 64

    def to_dict(self) -> dict[str, object]:
        return {
            "comparison_id": self.comparison_id,
            "status": self.status,
            "issue_codes": list(self.issue_codes),
        }


def _source_document() -> SourceDocument:
    return SourceDocument(
        schema_version="1.0.0",
        document_id="sec:10-k:test",
        issuer_id="issuer:test",
        document_type="10-K",
        period={"start": "2025-01-01", "end": "2025-12-31"},
        published_date="2026-02-15",
        retrieved_at="2026-02-16T01:02:03Z",
        source_url="https://www.sec.gov/Archives/edgar/data/1/test.htm",
        authority_level="primary_regulatory",
        content_sha256=canonical_sha256({"fixture": "source-document"}),
    )


def test_legitimate_zero_is_rendered_as_zero_not_unknown() -> None:
    assert _report_value(0) == "0"
    assert _report_value("0") == "0"
    assert _report_value(None) == "Unknown"

    paragraph = _full_valuation_decision_summary(_CompositeStub(), _ScorecardStub())  # type: ignore[arg-type]
    assert "总评=0/100" in paragraph["text_zh"]
    assert "评分置信度=0%" in paragraph["text_zh"]
    assert "overall score=0/100" in paragraph["text_en"]
    assert "score confidence=0%" in paragraph["text_en"]

    assert _report_decimal(0) == "0.00"
    assert _report_decimal("5.019441211249971017181015094252") == "5.02"
    assert _report_ratio_percent("0.25") == "25%"
    assert _humanized_machine_label("Qot_GetCompanyExecutives") == "Company Executives"
    assert _humanized_machine_label("named_human_review_not_selected") == (
        "named human review not selected"
    )
    assert r"\allowbreak{}" not in _latex_table_cell("Company Executives", chunk_size=4)


def test_table_cell_wraps_machine_tokens_embedded_in_readable_prose() -> None:
    raw = (
        '{"decision":"confirmed","rationale":"Counterevidence remains bounded '
        'through Internationalization",'
        '"object_id":"analytical-review:issuer:acme:business-cost_structure",'
        '"source_url":"https://www.sec.gov/Archives/example-filing.htm"}'
    )
    rendered = _latex_table_cell(raw, chunk_size=4)
    unbroken = _latex_table_cell(raw, chunk_size=len(raw) + 1)

    assert rendered.replace(r"\allowbreak{}", "") == unbroken
    assert rendered.count(r"\allowbreak{}") >= 12
    assert "Counterevidence remains bounded through Internationalization" in rendered
    assert r"Counterevidence\allowbreak{}" not in rendered
    assert r"Internationalization\allowbreak{}" not in rendered
    assert r"\allowbreak{}" not in _latex_table_cell(
        "Internationalization, responsibilities.", chunk_size=4
    )


def test_source_document_keeps_incomplete_apa7_metadata_unknown() -> None:
    source = _source_document()
    metadata = _source_document_apa7_metadata(source)

    assert metadata == {
        "apa7_metadata_status": "partial",
        "verified_author": "Unknown",
        "verified_title": "Unknown",
        "missing_metadata": "verified_author;verified_title",
        "apa7_reference": "Unknown",
    }

    paragraph = _object_paragraph("references_and_source_receipts", "documents", source)
    assert "APA 7 元数据状态为 partial" in paragraph["text_zh"]
    assert "文档类型不会被当作标题" in paragraph["text_zh"]
    assert "APA 7 metadata status is partial" in paragraph["text_en"]
    assert "Reference: 10-K" not in paragraph["text_en"]
    assert paragraph["missing_evidence"] == ["verified_author", "verified_title"]


def test_full_decision_summary_renders_all_bound_metrics() -> None:
    paragraph = _full_valuation_decision_summary(_CompositeStub(), _ScorecardStub())  # type: ignore[arg-type]
    text = str(paragraph["text_zh"])

    for expected in (
        "研究建议=重点关注",
        "总评=0/100",
        "评分置信度=0%",
        "市场价格=75.00",
        "当前内在价值=100.00",
        "12个月目标价=120.00",
        "安全边际=25%",
        "12个月上涨空间=60%",
        "综合估值状态=complete",
    ):
        assert expected in text
    assert {item["object_type"] for item in paragraph["bindings"]} == {
        "CompositeValuationResult",
        "OwnerScorecard",
    }


def test_research_only_decision_summary_stays_price_blind() -> None:
    paragraphs = _decision_summary_paragraphs(
        profile="research_only",
        bundle=_BundleStub(),
        composite_valuation=None,
        owner_scorecard=None,
    )
    text = "\n".join(
        f"{paragraph['text_zh']}\n{paragraph['text_en']}" for paragraph in paragraphs
    ).lower()

    assert len(paragraphs) == 1
    assert all(marker not in text for marker in _RESEARCH_ONLY_FORBIDDEN_TEXT)


def test_partial_post_context_is_unrated_without_mutating_frozen_score() -> None:
    scorecard = _ScorecardStub(recommendation="观察")
    paragraphs = _decision_summary_paragraphs(
        profile="full_valuation",
        bundle=_BundleStub(),
        composite_valuation=_CompositeStub(),  # type: ignore[arg-type]
        owner_scorecard=scorecard,  # type: ignore[arg-type]
        market_expectations_manifest=_MarketExpectationsStub(),  # type: ignore[arg-type]
    )
    decision = paragraphs[-1]

    assert scorecard.recommendation == "观察"
    assert "研究建议=无法评级" in decision["text_zh"]
    assert "冻结评分建议=观察" in decision["text_zh"]
    assert "recommendation=无法评级" in decision["text_en"]
    assert "frozen score recommendation=观察" in decision["text_en"]
    assert decision["missing_evidence"] == [
        "market_expectations_missing:analyst_consensus"
    ]


def test_partial_lens_scores_remain_unknown_and_are_omitted_from_numeric_charts() -> None:
    scores = tuple(
        _PartialLensScoreStub(lens=lens, score_id=f"score:{lens}")
        for lens in ("graham", "buffett", "munger", "duan_yongping")
    )

    charts = _report_content_charts(
        SimpleNamespace(graph=SimpleNamespace(facts=())),
        SimpleNamespace(),
        SimpleNamespace(),
        _BlockedCompositeStub(),  # type: ignore[arg-type]
        scores,  # type: ignore[arg-type]
        None,
        SimpleNamespace(),
    )

    assert all(chart["chart_id"] != "chart:four_lens_scores" for chart in charts)
    assert all(
        point["value"] is not None
        for chart in charts
        for series in chart["series"]
        for point in series["points"]
    )
    scorecard_status = _retained_scorecard_status(
        scores,  # type: ignore[arg-type]
        SimpleNamespace(status="partial"),  # type: ignore[arg-type]
    )
    assert scorecard_status == "partial"
    assert _content_status_with_scorecard("complete", scorecard_status) == "partial"
