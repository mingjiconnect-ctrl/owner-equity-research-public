"""Deterministic Chinese report construction from strictly reloaded research inputs.

This module has no source-acquisition, market-data, valuation-kernel, publication, or
network capability.  It turns already validated typed artifacts into deterministic
LaTeX inputs and delegates PDF creation to an explicit renderer.
"""

from __future__ import annotations

import base64
import hashlib
import html
import importlib.metadata
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass, fields
from datetime import date
from decimal import (
    ROUND_HALF_EVEN,
    Context,
    Decimal,
    DivisionByZero,
    InvalidOperation,
    Overflow,
    localcontext,
)
from functools import wraps
from pathlib import Path, PurePosixPath
from typing import Any, ParamSpec, Protocol, TypeVar
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError as JSONSchemaValidationError

from .contracts import ReportSpec, Score
from .fingerprints import FrozenMap, canonical_json, canonical_sha256, freeze, to_json_value
from .futu_receipts import SignatureVerifier
from .futu_session import (
    FutuMarketExecutionEvidence,
    FutuPartialSessionPublicationManifest,
    FutuPeerEvidenceSet,
    FutuSessionEvidence,
    FutuSessionEvidenceError,
    FutuSessionPublicationManifest,
    build_futu_partial_session_publication_manifest,
    build_futu_session_publication_manifest,
    validate_futu_partial_session_publication_manifest,
    validate_futu_session_publication_manifest,
)
from .owner_equity_types import (
    FutuOptionalDataDisposition,
    FutuOptionalDataDispositionPublicationManifest,
    MarketExpectationsComparison,
    MarketExpectationsPublicationManifest,
    OwnerEquityTypeError,
    ResearchSourceIndex,
    ResearchSourceIndexPublicationManifest,
    RuntimeGapPublicationManifest,
    RuntimeGapReceipt,
    build_futu_optional_data_disposition_publication_manifests,
    build_market_expectations_publication_manifest,
    build_research_source_index_publication_manifest,
    build_runtime_gap_publication_manifest,
    validate_market_expectations_publication_manifest,
)
from .owner_scorecard import (
    LENS_COMPONENTS,
    OwnerScorecardError,
    _materially_overvalued,
    build_owner_scorecard,
    score_calculation_context,
)
from .research_bundle_artifacts import (
    ARTIFACT_FILENAMES,
    RESEARCH_ARTIFACT_LOAD_MAX_BYTES,
    RESEARCH_ARTIFACT_MEMBER_MAX_BYTES,
    ResearchArtifactReadCallback,
    load_research_bundle_artifact_snapshot,
)
from .research_bundle_builder import ResearchBundleBuildResult
from .research_bundle_policies import bundle_payload_sha256
from .validation import ContractGraph
from .valuation_run_archive import (
    VALUATION_RUN_ARCHIVE_FILENAMES,
    VALUATION_RUN_ARCHIVE_MAX_BYTES,
    VALUATION_RUN_MEMBER_MAX_BYTES,
    ValuationRunArchive,
    load_valuation_run_archive,
)
from .valuation_synthesis_types import (
    ComparableValuationResult,
    CompositeValuationResult,
    ForwardReOIValuationResult,
    OwnerScorecard,
    ScoreV2,
    extension_decimal_in_domain,
    retained_authority_replay_scope,
    validate_extension_payload,
)

REPORT_PROFILES = ("research_only", "full_valuation")
REPORT_MIN_PAGES = 30
REPORT_MAX_PAGES = 60
REPORT_PDF_MAX_BYTES = 128 * 1024 * 1024
REPORT_TEXT_MAX_BYTES = 32 * 1024 * 1024
REPORT_EXECUTABLE_MAX_BYTES = 256 * 1024 * 1024
REPORT_TECTONIC_CACHE_MAX_BYTES = 512 * 1024 * 1024
REPORT_TECTONIC_CACHE_MAX_MEMBERS = 8192
REPORT_FONT_MAX_BYTES = 32 * 1024 * 1024
REPORT_LICENSE_MAX_BYTES = 2 * 1024 * 1024
REPORT_DISTRIBUTION_MAX_BYTES = 384 * 1024 * 1024
REPORT_DISTRIBUTION_MAX_MEMBERS = 4096
REPORT_SUPPLY_ARTIFACT_MAX_BYTES = 512 * 1024 * 1024
REPORT_TOOLCHAIN_REQUIRED_PLATFORMS = ("linux-x64", "macos-arm64")
REPORT_MIN_NON_COVER_CHARACTERS = 120
_REPORT_DECIMAL_PRECISION = 28
_REPORT_DECIMAL_FORMAT_PRECISION = 34
_REPORT_DECIMAL_EMIN = -999_999
_REPORT_DECIMAL_EMAX = 999_999
_DASH_TRANSLATION = str.maketrans(
    {
        "\u2010": "-",
        "\u2011": "-",
        "\u2012": "-",
        "\u2013": "-",
        "\u2014": "-",
        "\u2212": "-",
    }
)
_SAFE_ARTIFACT = re.compile(r"[a-z0-9][a-z0-9._/-]*\Z")
_PUBLICATION_DECIMAL_TEXT = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?\Z")
_CONTENT_PARAGRAPH_LIMIT = 48
_BASE_REPORT_SECTIONS = (
    ("decision_summary", "决策摘要", "Decision Summary"),
    ("sources_and_cutoff", "来源与截止", "Sources and Cutoff"),
    (
        "references_and_source_receipts",
        "参考文献与来源收据",
        "References and Source Receipts",
    ),
    ("business_and_moat", "业务模式与护城河", "Business Model and Moat"),
    (
        "financial_history_and_segments",
        "历史财务与分部",
        "Financial History and Segments",
    ),
    ("accounting_quality", "财务与会计质量", "Financial and Accounting Quality"),
    (
        "management_and_capital_allocation",
        "管理层与资本配置",
        "Management and Capital Allocation",
    ),
    ("risks_and_falsification", "风险与证伪条件", "Risks and Falsification"),
    ("evidence_audit_index", "证据审计索引", "Evidence Audit Index"),
)

_P = ParamSpec("_P")
_R = TypeVar("_R")


def _report_decimal_context(*, precision: int = _REPORT_DECIMAL_PRECISION) -> Context:
    """Return the complete deterministic context for report and publication arithmetic."""

    return Context(
        prec=precision,
        rounding=ROUND_HALF_EVEN,
        Emin=_REPORT_DECIMAL_EMIN,
        Emax=_REPORT_DECIMAL_EMAX,
        capitals=1,
        clamp=0,
        flags=[],
        traps=[InvalidOperation, DivisionByZero, Overflow],
    )


def _uses_report_decimal_context(function: Callable[_P, _R]) -> Callable[_P, _R]:
    """Isolate deterministic report work from the caller's ambient Decimal context."""

    @wraps(function)
    def wrapped(*args: _P.args, **kwargs: _P.kwargs) -> _R:
        with localcontext(_report_decimal_context()):
            return function(*args, **kwargs)

    return wrapped


_FULL_REPORT_SECTIONS = (
    ("futu_vendor_validation", "富途核验与市场参考", "Futu Validation and Market Reference"),
    ("scenarios", "三场景", "Three Scenarios"),
    ("mckinsey_dcf_and_reverse", "McKinsey DCF 与 Reverse Price", "McKinsey DCF and Reverse Price"),
    ("forward_reoi", "Forward ReOI 估值", "Forward ReOI Valuation"),
    ("comparables", "可比公司估值", "Comparable Valuation"),
    (
        "composite_value_target",
        "综合价值与12个月目标",
        "Composite Value and Twelve-Month Target",
    ),
    ("sensitivity", "敏感性分析", "Sensitivity Analysis"),
    ("scorecard", "四镜评分", "Four-Lens Scorecard"),
    ("market_expectations", "市场预期对照", "Market Expectations Comparison"),
)
_GRAPH_SECTION_MAP = {
    "documents": "references_and_source_receipts",
    "source_search_receipts": "sources_and_cutoff",
    "facts": "financial_history_and_segments",
    "calculations": "financial_history_and_segments",
    "periods": "financial_history_and_segments",
    "reconciliations": "financial_history_and_segments",
    "quarterly_updates": "financial_history_and_segments",
    "filing_artifacts": "financial_history_and_segments",
    "extraction_candidates": "financial_history_and_segments",
    "evidence_promotions": "financial_history_and_segments",
    "segment_definitions": "financial_history_and_segments",
    "segment_snapshots": "financial_history_and_segments",
    "footnote_reviews": "accounting_quality",
    "accounting_quality_findings": "accounting_quality",
    "accounting_quality_reviews": "accounting_quality",
    "context_observations": "business_and_moat",
    "competitive_context_snapshots": "business_and_moat",
    "analytical_claim_candidates": "business_and_moat",
    "analytical_claim_review_decisions": "business_and_moat",
    "business_model_snapshots": "business_and_moat",
    "competitive_advantage_hypotheses": "business_and_moat",
    "business_quality_reviews": "business_and_moat",
    "management_statements": "management_and_capital_allocation",
    "management_statement_candidates": "management_and_capital_allocation",
    "management_statement_review_decisions": "management_and_capital_allocation",
    "management_commitments": "management_and_capital_allocation",
    "management_outcomes": "management_and_capital_allocation",
    "capital_allocation_event_candidates": "management_and_capital_allocation",
    "capital_allocation_event_review_decisions": "management_and_capital_allocation",
    "capital_allocation_events": "management_and_capital_allocation",
    "capital_allocation_outcomes": "management_and_capital_allocation",
    "management_reviews": "management_and_capital_allocation",
    "capital_allocation_reviews": "management_and_capital_allocation",
    "claims": "risks_and_falsification",
    "assumptions": "risks_and_falsification",
}
_REVIEWED_DOMAIN_TABLES = (
    (
        "claims_assumptions",
        "risks_and_falsification",
        "主张、假设与证伪输入",
        "Claims, Assumptions, and Falsification Inputs",
        ("claims", "assumptions"),
    ),
    (
        "calculations_reconciliations",
        "financial_history_and_segments",
        "计算与勾稽复核",
        "Calculations and Reconciliations",
        ("calculations", "reconciliations"),
    ),
    (
        "quarterly_filings",
        "financial_history_and_segments",
        "季度更新与申报档案",
        "Quarterly Updates and Filing Artifacts",
        ("quarterly_updates", "filing_artifacts"),
    ),
    (
        "extraction_promotions",
        "financial_history_and_segments",
        "抽取候选与证据晋级",
        "Extraction Candidates and Evidence Promotions",
        ("extraction_candidates", "evidence_promotions"),
    ),
    (
        "footnotes_accounting",
        "accounting_quality",
        "附注与会计质量复核",
        "Footnotes and Accounting-Quality Reviews",
        ("footnote_reviews", "accounting_quality_findings", "accounting_quality_reviews"),
    ),
    (
        "competitive_context",
        "business_and_moat",
        "竞争环境与上下文快照",
        "Competitive Context and Snapshots",
        ("context_observations", "competitive_context_snapshots"),
    ),
    (
        "analytical_claims",
        "business_and_moat",
        "分析主张候选与人工裁决",
        "Analytical Claim Candidates and Human Decisions",
        ("analytical_claim_candidates", "analytical_claim_review_decisions"),
    ),
    (
        "business_moat_reviews",
        "business_and_moat",
        "业务模式、护城河与质量复核",
        "Business Model, Moat, and Quality Reviews",
        (
            "business_model_snapshots",
            "competitive_advantage_hypotheses",
            "business_quality_reviews",
        ),
    ),
    (
        "management_statements",
        "management_and_capital_allocation",
        "管理层陈述与人工核验",
        "Management Statements and Human Verification",
        (
            "management_statements",
            "management_statement_candidates",
            "management_statement_review_decisions",
        ),
    ),
    (
        "management_outcomes",
        "management_and_capital_allocation",
        "管理层承诺与结果",
        "Management Commitments and Outcomes",
        ("management_commitments", "management_outcomes"),
    ),
    (
        "capital_allocation_events",
        "management_and_capital_allocation",
        "资本配置事件与结果",
        "Capital-Allocation Events and Outcomes",
        (
            "capital_allocation_event_candidates",
            "capital_allocation_event_review_decisions",
            "capital_allocation_events",
            "capital_allocation_outcomes",
        ),
    ),
    (
        "management_capital_reviews",
        "management_and_capital_allocation",
        "管理层与资本配置总复核",
        "Management and Capital-Allocation Reviews",
        ("management_reviews", "capital_allocation_reviews"),
    ),
    (
        "source_search_receipts",
        "sources_and_cutoff",
        "来源检索收据",
        "Source Search Receipts",
        ("source_search_receipts",),
    ),
    (
        "valuation_freeze_authorities",
        "risks_and_falsification",
        "估值假设、冻结与交接口径",
        "Valuation Assumptions, Freeze, and Handoff Basis",
        (
            "valuation_assumption_candidates",
            "valuation_assumption_review_decisions",
            "valuation_handoffs",
            "price_blind_reference_closures",
            "market_reference_validation_contexts",
        ),
    ),
)
_PREFERRED_NARRATIVE_FIELDS = (
    "status",
    "statement",
    "concept",
    "value",
    "unit",
    "currency",
    "period",
    "as_of_date",
    "published_date",
    "document_type",
    "authority_level",
    "confidence",
    "current_intrinsic_value",
    "twelve_month_target",
    "market_price",
    "margin_of_safety",
    "twelve_month_upside",
    "contested",
    "recommendation",
    "overall_score",
    "confidence_percent",
    "valid_peer_count",
    "valid_multiple_count",
    "decision",
    "review_status",
    "rationale",
    "falsification_condition",
    "outcome_status",
    "missing_evidence",
    "issues",
)

def _source_document_apa7_metadata(document: object) -> dict[str, str]:
    """Expose only citation metadata the SourceDocument contract actually verifies."""

    if type(getattr(document, "published_date", None)) is not str or type(
        getattr(document, "source_url", None)
    ) is not str:
        raise ResearchReportError("source document lacks its typed date or URL metadata")
    return {
        "apa7_metadata_status": "partial",
        "verified_author": "Unknown",
        "verified_title": "Unknown",
        "missing_metadata": "verified_author;verified_title",
        "apa7_reference": "Unknown",
    }
_PROVENANCE_NARRATIVE_FIELDS = (
    "source_document_id",
    "document_id",
    "source_url",
    "source_locator",
    "form",
    "filing_date",
    "report_period",
    "period",
    "fact_ids",
    "claim_ids",
    "calculation_result_ids",
    "input_fact_ids",
    "parent_fact_ids",
    "policy_id",
    "policy_version",
    "reviewed_at",
    "reviewer_id",
    "methodology_id",
    "methodology_version",
    "content_sha256",
    "raw_sha256",
    "normalized_sha256",
)
_RESEARCH_ONLY_FORBIDDEN_TEXT = (
    "futu",
    "富途",
    "target price",
    "目标价",
    "market price",
    "市场价格",
    "market_price",
    "twelve_month_target",
    "margin_of_safety",
)

_DEFAULT_TEMPLATE = r"""% Clean-room Owner Equity Research report template.
% The build is intentionally network-free and shell escape must remain disabled.
\documentclass[11pt,a4paper,UTF8,fontset=none]{ctexart}
\setCJKmainfont[Path=./,AutoFakeBold=2.2,AutoFakeSlant=0.18]{NotoSansCJKsc-Regular.otf}
\setCJKsansfont[Path=./,AutoFakeBold=2.2,AutoFakeSlant=0.18]{NotoSansCJKsc-Regular.otf}
\setCJKmonofont[Path=./,AutoFakeBold=2.2,AutoFakeSlant=0.18]{NotoSansCJKsc-Regular.otf}
\usepackage[a4paper,top=22mm,bottom=22mm,left=21mm,right=21mm]{geometry}
\usepackage{booktabs}
\usepackage{longtable}
\usepackage{array}
\usepackage{xcolor}
\usepackage{hyperref}
\usepackage{fancyhdr}
\usepackage{lastpage}
\usepackage{microtype}
\definecolor{OwnerNavy}{HTML}{17324D}
\definecolor{OwnerBlue}{HTML}{2F6690}
\definecolor{OwnerRed}{HTML}{B0443E}
\definecolor{OwnerGreen}{HTML}{2F7D62}
\definecolor{OwnerGray}{HTML}{5B6573}
\hypersetup{hidelinks,pdfcreator={owner-equity-research}}
\setlength{\parindent}{2em}
\setlength{\parskip}{0.45em}
\setlength{\emergencystretch}{3em}
\renewcommand{\arraystretch}{1.24}
\clubpenalty=10000
\widowpenalty=10000
\displaywidowpenalty=10000
\pagestyle{fancy}
\fancyhf{}
\fancyhead[L]{\small\color{OwnerGray}所有者视角研究}
\fancyhead[R]{\small\color{OwnerGray}\ReportIssuer}
\fancyfoot[C]{\small\color{OwnerGray}第 \thepage/\pageref*{LastPage} 页}
\setcounter{secnumdepth}{2}
\begin{document}
\input{report-data.tex}
\end{document}
"""

_DEFAULT_FONT_MANIFEST = {
    "schema_version": "1.0.0",
    "artifact_type": "report-font-manifest",
    "policy": "bundled-open-font-license-assets-only",
    "primary_cjk_family": "Noto Sans CJK SC",
    "primary_latin_family": "TeX Gyre",
    "fallback_policy": "forbidden",
    "embedded_font_files": [
        {
            "path": "NotoSansCJKsc-Regular.otf",
            "sha256": "2c76254f6fc379fddfce0a7e84fb5385bb135d3e399294f6eeb6680d0365b74b",
            "size": 16437364,
            "source_url": "https://github.com/notofonts/noto-cjk/raw/main/Sans/OTF/SimplifiedChinese/NotoSansCJKsc-Regular.otf",
            "license_path": "NOTO-CJK-LICENSE.txt",
            "license_sha256": "6a73f9541c2de74158c0e7cf6b0a58ef774f5a780bf191f2d7ec9cc53efe2bf2",
        }
    ],
    "required_engine": "offline-xetex-compatible",
    "shell_escape": False,
    "network_access": False,
}

_PDF_QA_CHILD = r'''# Isolated, staged-tree PDF QA.
# Standard library plus two locked distributions only.
import hashlib
import importlib.metadata
import json
import os
import re
import stat
import sys
from decimal import Decimal, localcontext
from io import BytesIO
from pathlib import Path

site_root, pdf_path, result_path, pdf_limit, text_limit = sys.argv[1:]
os.umask(0o077)
sys.path.insert(0, site_root)
from pypdf import PdfReader
import pypdfium2 as pdfium

pdf_fd = os.open(
    pdf_path,
    os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
)
try:
    pdf_before = os.fstat(pdf_fd)
    if not stat.S_ISREG(pdf_before.st_mode) or not 1 <= pdf_before.st_size <= int(pdf_limit):
        raise RuntimeError("PDF byte limit")
    chunks = []
    consumed = 0
    while True:
        chunk = os.read(pdf_fd, min(1024 * 1024, int(pdf_limit) - consumed + 1))
        if not chunk:
            break
        consumed += len(chunk)
        if consumed > int(pdf_limit):
            raise RuntimeError("PDF byte limit")
        chunks.append(chunk)
    pdf_after = os.fstat(pdf_fd)
    if (
        consumed != pdf_before.st_size
        or (pdf_before.st_dev, pdf_before.st_ino, pdf_before.st_size, pdf_before.st_mtime_ns)
        != (pdf_after.st_dev, pdf_after.st_ino, pdf_after.st_size, pdf_after.st_mtime_ns)
    ):
        raise RuntimeError("PDF changed while read")
    pdf_bytes = b"".join(chunks)
finally:
    os.close(pdf_fd)
reader = PdfReader(BytesIO(pdf_bytes))
page_texts = tuple(page.extract_text() or "" for page in reader.pages)
text = "\n\f\n".join(page_texts)
if len(text.encode("utf-8")) > int(text_limit):
    raise RuntimeError("PDF text limit")
document = pdfium.PdfDocument(pdf_bytes)
rendered_hashes = []
non_white_ratios = []
try:
    if len(document) != len(page_texts):
        raise RuntimeError("PDF backend page-count mismatch")
    for page_number in range(len(document)):
        page = document[page_number]
        bitmap = None
        try:
            bitmap = page.render(
                scale=48 / 72,
                fill_color=(255, 255, 255, 255),
                rev_byteorder=True,
            )
            if len(bitmap.buffer) > 16 * 1024 * 1024:
                raise RuntimeError("rendered page byte limit")
            buffer = bytes(bitmap.buffer)
            if bitmap.n_channels not in {3, 4}:
                raise RuntimeError("rendered page pixel format")
            non_white = 0
            for row in range(bitmap.height):
                row_offset = row * bitmap.stride
                for column in range(bitmap.width):
                    offset = row_offset + column * bitmap.n_channels
                    if min(buffer[offset : offset + 3]) < 245:
                        non_white += 1
            with localcontext() as context:
                context.prec = 28
                ratio = Decimal(non_white) / Decimal(bitmap.width * bitmap.height)
            rendered_hashes.append(hashlib.sha256(buffer).hexdigest())
            non_white_ratios.append(format(ratio.quantize(Decimal("0.000001")), "f"))
        finally:
            if bitmap is not None:
                bitmap.close()
            page.close()
finally:
    document.close()
payload = {
    "page_count": len(page_texts),
    "extracted_text": text,
    "page_text_character_counts": [
        len(re.sub(r"\s+", "", page_text)) for page_text in page_texts
    ],
    "rendered_page_sha256": rendered_hashes,
    "page_non_white_ratios": non_white_ratios,
    "versions": {
        "pypdf": importlib.metadata.version("pypdf"),
        "pypdfium2": importlib.metadata.version("pypdfium2"),
    },
}
content = (
    json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    + "\n"
).encode("utf-8")
with open(result_path, "xb") as stream:
    stream.write(content)
    stream.flush()
'''


class ResearchReportError(ValueError):
    """Report inputs, rendering, or QA failed closed."""


def _research_input_file_bytes(result: ResearchBundleBuildResult) -> dict[str, bytes]:
    return {
        "research-bundle.json": _canonical_file(result.bundle.to_dict()),
        "run-manifest.json": _canonical_file(result.run_manifest.to_dict()),
    }


def _valuation_archive_file_bytes(archive: ValuationRunArchive) -> dict[str, bytes]:
    if type(archive) is not ValuationRunArchive:
        raise ResearchReportError("valuation input lacks an exact archive result")
    return {
        "valuation-handoff.json": _canonical_file(archive.handoff.to_dict()),
        "price-blind-input.json": _canonical_file(archive.price_blind_input.to_dict()),
        "market-reference.json": _canonical_file(archive.market_reference.to_dict()),
        "valuation-request.json": canonical_json(
            to_json_value(archive.request_payload)
        ).encode("utf-8"),
        "valuation-result.json": canonical_json(
            to_json_value(archive.result_payload)
        ).encode("utf-8"),
        "valuation-run-manifest.json": _canonical_file(to_json_value(archive.manifest)),
    }


def _validate_snapshot_limits(
    contents: Mapping[str, bytes],
    *,
    member_limit: int,
    total_limit: int,
    label: str,
) -> None:
    total = 0
    for name, raw in contents.items():
        if type(name) is not str or type(raw) is not bytes or len(raw) > member_limit:
            raise ResearchReportError(f"{label} member is untyped or exceeds its limit")
        total += len(raw)
        if total > total_limit:
            raise ResearchReportError(f"{label} exceeds its cumulative byte limit")


@dataclass(frozen=True, slots=True)
class ReloadedResearchInput:
    source_directory: Path
    result: ResearchBundleBuildResult
    file_bytes: FrozenMap
    file_sha256: FrozenMap

    def __post_init__(self) -> None:
        if type(self.result) is not ResearchBundleBuildResult:
            raise ResearchReportError("research input must contain an exact build result")
        source = Path(self.source_directory).absolute()
        captured = dict(self.file_bytes)
        hashes = dict(self.file_sha256)
        expected = _research_input_file_bytes(self.result)
        _validate_snapshot_limits(
            captured,
            member_limit=RESEARCH_ARTIFACT_MEMBER_MAX_BYTES,
            total_limit=RESEARCH_ARTIFACT_LOAD_MAX_BYTES,
            label="research input snapshot",
        )
        bundle = self.result.bundle
        manifest = self.result.run_manifest
        expected_hashes = {name: _sha256(raw) for name, raw in captured.items()}
        if (
            set(captured) != set(ARTIFACT_FILENAMES)
            or captured != expected
            or hashes != expected_hashes
            or bundle.bundle_fingerprint != bundle_payload_sha256(bundle.to_dict())
            or bundle.run_id != manifest.run_id
            or bundle.issuer_id != manifest.issuer_id
            or bundle.data_cutoff_date != manifest.data_cutoff_date
            or bundle.component_lock_sha256 != manifest.component_lock_sha256
            or manifest.output_artifact_hashes.get("research-bundle.json")
            != bundle.bundle_fingerprint
        ):
            raise ResearchReportError("research input typed snapshot does not replay")
        object.__setattr__(self, "source_directory", source)
        object.__setattr__(self, "file_bytes", freeze(captured))
        object.__setattr__(self, "file_sha256", freeze(hashes))


@dataclass(frozen=True, slots=True)
class ReloadedValuationInput:
    source_directory: Path
    archive: ValuationRunArchive
    file_bytes: FrozenMap
    file_sha256: FrozenMap

    def __post_init__(self) -> None:
        if type(self.archive) is not ValuationRunArchive:
            raise ResearchReportError("valuation input must contain an exact archive result")
        source = Path(self.source_directory).absolute()
        captured = dict(self.file_bytes)
        hashes = dict(self.file_sha256)
        expected = _valuation_archive_file_bytes(self.archive)
        _validate_snapshot_limits(
            captured,
            member_limit=VALUATION_RUN_MEMBER_MAX_BYTES,
            total_limit=VALUATION_RUN_ARCHIVE_MAX_BYTES,
            label="valuation input snapshot",
        )
        expected_hashes = {name: _sha256(raw) for name, raw in captured.items()}
        manifest = to_json_value(self.archive.manifest)
        fingerprint_payload = dict(manifest)
        manifest_fingerprint = fingerprint_payload.pop("manifest_fingerprint", None)
        content_hashes = {
            name: expected_hashes[name]
            for name in VALUATION_RUN_ARCHIVE_FILENAMES[:-1]
        }
        if (
            set(captured) != set(VALUATION_RUN_ARCHIVE_FILENAMES)
            or captured != expected
            or hashes != expected_hashes
            or dict(self.archive.file_sha256) != expected_hashes
            or source != self.archive.output_directory
            or manifest_fingerprint != canonical_sha256(fingerprint_payload)
            or manifest.get("file_sha256") != content_hashes
            or manifest.get("valuation_request_sha256")
            != content_hashes["valuation-request.json"]
            or manifest.get("valuation_result_sha256")
            != content_hashes["valuation-result.json"]
            or manifest.get("valuation_handoff_id") != self.archive.handoff.handoff_id
            or manifest.get("valuation_handoff_fingerprint")
            != self.archive.handoff.fingerprint
            or manifest.get("market_reference_snapshot_id")
            != self.archive.market_reference.snapshot_id
            or manifest.get("market_reference_snapshot_fingerprint")
            != self.archive.market_reference.fingerprint
            or manifest.get("price_blind_input_fingerprint")
            != self.archive.price_blind_input.fingerprint
        ):
            raise ResearchReportError("valuation input typed snapshot does not replay")
        object.__setattr__(self, "source_directory", source)
        object.__setattr__(self, "file_bytes", freeze(captured))
        object.__setattr__(self, "file_sha256", freeze(hashes))


@dataclass(frozen=True, slots=True)
class PdfRenderResult:
    pdf_bytes: bytes
    page_count: int
    extracted_text: str
    rendered_page_count: int
    renderer_id: str
    renderer_version: str
    engine: str
    toolchain_authority_id: str | None = None
    toolchain_authority_fingerprint: str | None = None
    page_text_character_counts: tuple[int, ...] = ()
    rendered_page_sha256: tuple[str, ...] = ()
    page_non_white_ratios: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PdfQaReplayResult:
    """All-page evidence recomputed in an isolated, snapshotted QA process."""

    page_count: int
    extracted_text: str
    page_text_character_counts: tuple[int, ...]
    rendered_page_sha256: tuple[str, ...]
    page_non_white_ratios: tuple[str, ...]
    backend_versions: FrozenMap


class ReportToolchainAuthority(Mapping[str, object]):
    """Pre-trusted, platform-specific renderer and PDF-QA identities."""

    __slots__ = ("_payload",)

    def __init__(
        self,
        payload: Mapping[str, object],
        *,
        require_current_platform: bool = True,
    ) -> None:
        frozen = freeze(payload)
        raw = to_json_value(frozen)
        if not isinstance(raw, dict):
            raise ResearchReportError("report toolchain authority must be an object")
        _validate_parallel_schema("report-toolchain-authority-entry", raw)
        identity = dict(raw)
        supplied_fingerprint = identity.pop("authority_fingerprint", None)
        supplied_id = identity.pop("authority_id", None)
        expected_fingerprint = canonical_sha256(identity)
        expected_id = (
            f"report-toolchain-authority:{raw['platform_target']}:{expected_fingerprint[:24]}"
        )
        if supplied_id != expected_id or supplied_fingerprint != expected_fingerprint:
            raise ResearchReportError("report toolchain authority identity does not replay")
        if require_current_platform and raw["platform_target"] != _platform_target():
            raise ResearchReportError("report toolchain authority targets another platform")
        supply_chain = raw["supply_chain"]
        if not isinstance(supply_chain, dict):
            raise ResearchReportError("report toolchain supply-chain evidence is invalid")
        status = raw["release_evidence_status"]
        components = supply_chain["components"]
        missing = supply_chain["missing_evidence_codes"]
        if (
            not isinstance(components, dict)
            or not isinstance(missing, list)
            or supply_chain["status"] != status
            or (
                status == "ready"
                and (missing or any(value is None for value in components.values()))
            )
            or (
                status == "blocked_missing_evidence"
                and (not missing or all(value is not None for value in components.values()))
            )
        ):
            raise ResearchReportError("report toolchain supply-chain status does not replay")
        for component_name in (
            "renderer",
            "offline_bundle",
            "pdf_text_backend",
            "pdf_render_backend",
        ):
            evidence = components[component_name]
            if evidence is None:
                continue
            if not isinstance(evidence, dict):
                raise ResearchReportError("report toolchain component evidence is invalid")
            if (
                evidence["component_name"] != component_name
                or evidence["runtime_identity_sha256"]
                != canonical_sha256(raw[component_name])
            ):
                raise ResearchReportError("report toolchain component evidence is rebound")
            for url_key in ("download_url", "source_url"):
                _validate_https_supply_url(str(evidence[url_key]))
            for path_key in ("sbom_path", "derivation_manifest_path"):
                _validate_relative_path(str(evidence[path_key]))
            license_inventory = evidence["license_inventory"]
            if (
                not isinstance(license_inventory, list)
                or not license_inventory
                or tuple(
                    str(item["component_scope"])
                    for item in license_inventory
                    if isinstance(item, dict)
                )
                != tuple(
                    sorted(
                        str(item["component_scope"])
                        for item in license_inventory
                        if isinstance(item, dict)
                    )
                )
                or len(
                    {
                        str(item["component_scope"])
                        for item in license_inventory
                        if isinstance(item, dict)
                    }
                )
                != len(license_inventory)
            ):
                raise ResearchReportError("report toolchain license inventory is invalid")
            for license_item in license_inventory:
                if not isinstance(license_item, dict):
                    raise ResearchReportError("report toolchain license entry is invalid")
                _validate_relative_path(str(license_item["license_path"]))
        object.__setattr__(self, "_payload", frozen)

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> ReportToolchainAuthority:
        return cls(payload)

    def __getitem__(self, key: str) -> object:
        return self._payload[key]

    def __iter__(self):
        return iter(self._payload)

    def __len__(self) -> int:
        return len(self._payload)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("ReportToolchainAuthority is immutable")

    def to_dict(self) -> dict[str, Any]:
        raw = to_json_value(self._payload)
        assert isinstance(raw, dict)
        return raw

    @property
    def fingerprint(self) -> str:
        return str(self._payload["authority_fingerprint"])

    @property
    def authority_id(self) -> str:
        return str(self._payload["authority_id"])


class ReportToolchainAuthorityRegistry(Mapping[str, object]):
    """Closed multi-platform registry; current-platform selection fails closed."""

    __slots__ = ("_authorities", "_payload")

    def __init__(self, payload: Mapping[str, object]) -> None:
        frozen = freeze(payload)
        raw = to_json_value(frozen)
        if not isinstance(raw, dict):
            raise ResearchReportError("report toolchain authority registry must be an object")
        _validate_parallel_schema("report-toolchain-authority", raw)
        identity = dict(raw)
        supplied_fingerprint = identity.pop("registry_fingerprint", None)
        supplied_id = identity.pop("registry_id", None)
        expected_fingerprint = canonical_sha256(identity)
        expected_id = f"report-toolchain-authority-registry:{expected_fingerprint[:24]}"
        if supplied_id != expected_id or supplied_fingerprint != expected_fingerprint:
            raise ResearchReportError("report toolchain registry identity does not replay")
        if tuple(raw["required_platform_targets"]) != REPORT_TOOLCHAIN_REQUIRED_PLATFORMS:
            raise ResearchReportError("report toolchain required platform set is not closed")
        authority_payloads = raw["authorities"]
        if not isinstance(authority_payloads, list):
            raise ResearchReportError("report toolchain registry authorities are invalid")
        authorities = tuple(
            ReportToolchainAuthority(item, require_current_platform=False)
            for item in authority_payloads
        )
        targets = tuple(str(item["platform_target"]) for item in authority_payloads)
        if targets != tuple(sorted(targets)) or len(targets) != len(set(targets)):
            raise ResearchReportError("report toolchain registry targets are not unique and sorted")
        missing = tuple(
            target for target in REPORT_TOOLCHAIN_REQUIRED_PLATFORMS if target not in set(targets)
        )
        expected_release = (
            "ready"
            if not missing
            and all(item["release_evidence_status"] == "ready" for item in authority_payloads)
            else "blocked"
        )
        if (
            tuple(raw["missing_platform_targets"]) != missing
            or raw["release_status"] != expected_release
        ):
            raise ResearchReportError("report toolchain registry release status does not replay")
        object.__setattr__(self, "_payload", frozen)
        object.__setattr__(self, "_authorities", authorities)

    @classmethod
    def from_dict(
        cls, payload: Mapping[str, object]
    ) -> ReportToolchainAuthorityRegistry:
        return cls(payload)

    def __getitem__(self, key: str) -> object:
        return self._payload[key]

    def __iter__(self):
        return iter(self._payload)

    def __len__(self) -> int:
        return len(self._payload)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("ReportToolchainAuthorityRegistry is immutable")

    def to_dict(self) -> dict[str, Any]:
        raw = to_json_value(self._payload)
        assert isinstance(raw, dict)
        return raw

    @property
    def fingerprint(self) -> str:
        return str(self._payload["registry_fingerprint"])

    @property
    def registry_id(self) -> str:
        return str(self._payload["registry_id"])

    def for_platform(self, platform_target: str) -> ReportToolchainAuthority:
        if platform_target not in REPORT_TOOLCHAIN_REQUIRED_PLATFORMS:
            raise ResearchReportError("report toolchain platform is not authorized")
        payload = next(
            (
                item.to_dict()
                for item in self._authorities
                if item["platform_target"] == platform_target
            ),
            None,
        )
        if payload is None:
            raise ResearchReportError(
                f"report toolchain authority is missing for {platform_target}"
            )
        return ReportToolchainAuthority(
            payload,
            require_current_platform=platform_target == _platform_target(),
        )


class ReportRenderer(Protocol):
    def render(self, tex_sources: Mapping[str, bytes]) -> PdfRenderResult: ...


@dataclass(frozen=True, slots=True)
class ReportArtifact:
    path: str
    media_type: str
    content: bytes

    def __post_init__(self) -> None:
        _validate_relative_path(self.path)
        if type(self.media_type) is not str or not self.media_type:
            raise ResearchReportError("report artifact media type is empty")
        if type(self.content) is not bytes or not self.content:
            raise ResearchReportError("report artifact content must be non-empty bytes")

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.content).hexdigest()


class ReportBuildReceipt(Mapping[str, object]):
    """Exact, schema-checked receipt for one deterministic report build."""

    __slots__ = ("_payload",)

    def __init__(self, payload: Mapping[str, object]) -> None:
        frozen = freeze(payload)
        raw = to_json_value(frozen)
        if not isinstance(raw, dict):
            raise ResearchReportError("report build receipt must be an object")
        _validate_parallel_schema("report-build-receipt", raw)
        supplied = raw.pop("receipt_fingerprint", None)
        if supplied != canonical_sha256(raw):
            raise ResearchReportError("report build receipt fingerprint does not replay")
        object.__setattr__(self, "_payload", frozen)

    def __getitem__(self, key: str) -> object:
        return self._payload[key]

    def __iter__(self):
        return iter(self._payload)

    def __len__(self) -> int:
        return len(self._payload)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("ReportBuildReceipt is immutable")

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Mapping) and to_json_value(self) == to_json_value(other)

    @property
    def fingerprint(self) -> str:
        return str(self._payload["receipt_fingerprint"])


class ResearchReportContent(Mapping[str, object]):
    """Closed, evidence-bound narrative/table/chart contract for one report."""

    __slots__ = ("_payload",)

    def __init__(self, payload: Mapping[str, object]) -> None:
        frozen = freeze(payload)
        raw = to_json_value(frozen)
        if not isinstance(raw, dict):
            raise ResearchReportError("report content must be an object")
        _validate_parallel_schema("research-report-content", raw)
        identity = dict(raw)
        supplied = identity.pop("content_fingerprint", None)
        if supplied != canonical_sha256(identity):
            raise ResearchReportError("report content fingerprint does not replay")
        _validate_report_content_semantics(raw)
        object.__setattr__(self, "_payload", frozen)

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> ResearchReportContent:
        return cls(payload)

    def __getitem__(self, key: str) -> object:
        return self._payload[key]

    def __iter__(self):
        return iter(self._payload)

    def __len__(self) -> int:
        return len(self._payload)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("ResearchReportContent is immutable")

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Mapping) and to_json_value(self) == to_json_value(other)

    def to_dict(self) -> dict[str, Any]:
        raw = to_json_value(self._payload)
        assert isinstance(raw, dict)
        return raw

    @property
    def fingerprint(self) -> str:
        return str(self._payload["content_fingerprint"])


class _SynthesisPublicationManifest(Mapping[str, object]):
    """Closed disk projection; it is never promoted back into live authority."""

    __slots__ = ("_payload",)

    ARTIFACT_TYPE = ""
    SOURCE_SCHEMA = ""
    SOURCE_TYPE: type[object]
    SOURCE_ID_FIELD = ""

    @_uses_report_decimal_context
    def __init__(self, payload: Mapping[str, object]) -> None:
        frozen = freeze(payload)
        raw = to_json_value(frozen)
        if not isinstance(raw, dict):
            raise ResearchReportError("synthesis publication manifest must be an object")
        _validate_parallel_schema("synthesis-publication-manifest", raw)
        if raw["artifact_type"] != self.ARTIFACT_TYPE or raw["source_schema"] != self.SOURCE_SCHEMA:
            raise ResearchReportError("synthesis publication manifest uses the wrong exact type")
        source = raw["source_payload"]
        if not isinstance(source, dict):
            raise ResearchReportError("synthesis publication source payload must be an object")
        try:
            validate_extension_payload(self.SOURCE_SCHEMA, source)
        except (JSONSchemaValidationError, KeyError, TypeError, ValueError) as exc:
            raise ResearchReportError("synthesis publication source schema is invalid") from exc
        source_id = source.get(self.SOURCE_ID_FIELD)
        if source_id != raw["source_object_id"]:
            raise ResearchReportError("synthesis publication source object ID was rebound")
        source_identity = dict(source)
        source_identity.pop(self.SOURCE_ID_FIELD, None)
        if (
            type(source_id) is not str
            or not source_id.endswith(f":{canonical_sha256(source_identity)[:24]}")
            or raw["source_fingerprint"] != canonical_sha256(source)
            or raw["issuer_id"] != source.get("issuer_id")
        ):
            raise ResearchReportError("synthesis publication source identity does not replay")
        identity = dict(raw)
        supplied_fingerprint = identity.pop("manifest_fingerprint", None)
        supplied_id = identity.pop("manifest_id", None)
        expected_fingerprint = canonical_sha256(identity)
        expected_id = f"{self.ARTIFACT_TYPE}:{raw['issuer_id']}:{expected_fingerprint[:24]}"
        if supplied_id != expected_id or supplied_fingerprint != expected_fingerprint:
            raise ResearchReportError("synthesis publication manifest identity does not replay")
        _validate_synthesis_projection_arithmetic(self.SOURCE_SCHEMA, source)
        object.__setattr__(self, "_payload", frozen)

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]):
        return cls(payload)

    @classmethod
    @_uses_report_decimal_context
    def from_source(cls, source: object):
        if type(source) is not cls.SOURCE_TYPE:
            raise ResearchReportError("synthesis publication requires an exact live source")
        try:
            source.__post_init__()  # type: ignore[attr-defined]
            source_payload = source.to_dict()  # type: ignore[attr-defined]
        except (OSError, TypeError, ValueError) as exc:
            raise ResearchReportError("live synthesis authority does not replay") from exc
        identity = {
            "schema_version": "1.0.0",
            "artifact_type": cls.ARTIFACT_TYPE,
            "issuer_id": source_payload["issuer_id"],
            "source_schema": cls.SOURCE_SCHEMA,
            "source_object_id": source_payload[cls.SOURCE_ID_FIELD],
            "source_fingerprint": canonical_sha256(source_payload),
            "source_payload": source_payload,
        }
        manifest_fingerprint = canonical_sha256(identity)
        return cls(
            {
                **identity,
                "manifest_id": (
                    f"{cls.ARTIFACT_TYPE}:{identity['issuer_id']}:{manifest_fingerprint[:24]}"
                ),
                "manifest_fingerprint": manifest_fingerprint,
            }
        )

    def __getitem__(self, key: str) -> object:
        return self._payload[key]

    def __iter__(self):
        return iter(self._payload)

    def __len__(self) -> int:
        return len(self._payload)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError(f"{type(self).__name__} is immutable")

    def __eq__(self, other: object) -> bool:
        return type(other) is type(self) and to_json_value(self) == to_json_value(other)

    def to_dict(self) -> dict[str, Any]:
        raw = to_json_value(self._payload)
        assert isinstance(raw, dict)
        return raw

    @property
    def fingerprint(self) -> str:
        return str(self._payload["manifest_fingerprint"])

    @property
    def source_fingerprint(self) -> str:
        return str(self._payload["source_fingerprint"])

    @property
    def source_payload(self) -> FrozenMap:
        return self._payload["source_payload"]


class ForwardReOIValuationPublicationManifest(_SynthesisPublicationManifest):
    ARTIFACT_TYPE = "forward-reoi-publication-manifest"
    SOURCE_SCHEMA = "forward-reoi-valuation-result"
    SOURCE_TYPE = ForwardReOIValuationResult
    SOURCE_ID_FIELD = "result_id"


class ComparableValuationPublicationManifest(_SynthesisPublicationManifest):
    ARTIFACT_TYPE = "comparable-valuation-publication-manifest"
    SOURCE_SCHEMA = "comparable-valuation-result"
    SOURCE_TYPE = ComparableValuationResult
    SOURCE_ID_FIELD = "result_id"


class CompositeValuationPublicationManifest(_SynthesisPublicationManifest):
    ARTIFACT_TYPE = "composite-valuation-publication-manifest"
    SOURCE_SCHEMA = "composite-valuation-result"
    SOURCE_TYPE = CompositeValuationResult
    SOURCE_ID_FIELD = "result_id"


class ScoreV2PublicationManifest(_SynthesisPublicationManifest):
    ARTIFACT_TYPE = "score-v2-publication-manifest"
    SOURCE_SCHEMA = "score-v2"
    SOURCE_TYPE = ScoreV2
    SOURCE_ID_FIELD = "score_id"

    @property
    def lens(self) -> str:
        return str(self.source_payload["lens"])


class OwnerScorecardPublicationManifest(_SynthesisPublicationManifest):
    ARTIFACT_TYPE = "owner-scorecard-publication-manifest"
    SOURCE_SCHEMA = "owner-scorecard"
    SOURCE_TYPE = OwnerScorecard
    SOURCE_ID_FIELD = "scorecard_id"


def _projection_decimal(value: object, label: str) -> Decimal:
    try:
        parsed = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ResearchReportError(f"{label} is not a finite decimal") from exc
    if not parsed.is_finite():
        raise ResearchReportError(f"{label} is not a finite decimal")
    if not extension_decimal_in_domain(parsed):
        raise ResearchReportError(f"{label} exceeds the bounded decimal domain")
    return parsed


def _projection_median(values: list[Decimal]) -> Decimal:
    ordered = sorted(values)
    if len(ordered) != 3:
        raise ResearchReportError("composite publication requires three panel values")
    return ordered[1]


def _bounded_projection_decimal(
    value: object,
    label: str,
    *,
    maximum: Decimal,
) -> Decimal:
    parsed = _projection_decimal(value, label)
    if not Decimal(0) <= parsed <= maximum:
        raise ResearchReportError(f"{label} is outside its closed range")
    return parsed


def _validate_publication_decimal_domain(
    value: object,
    *,
    path: str = "source_payload",
) -> None:
    """Fail closed on every decimal-shaped leaf before status-specific replay."""

    if isinstance(value, Mapping):
        for key, child in value.items():
            _validate_publication_decimal_domain(child, path=f"{path}.{key}")
        return
    if isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            _validate_publication_decimal_domain(child, path=f"{path}[{index}]")
        return
    if type(value) is str and _PUBLICATION_DECIMAL_TEXT.fullmatch(value) is not None:
        _projection_decimal(value, f"publication decimal {path}")


def _scorecard_publication_recommendation(payload: Mapping[str, Any]) -> str:
    if payload["status"] != "complete":
        return "无法评级"
    required = (
        payload["overall_score"],
        payload["confidence_percent"],
        payload["current_intrinsic_value"],
        payload["market_price"],
        payload["margin_of_safety"],
        payload["twelve_month_upside"],
    )
    if any(item is None for item in required):
        return "无法评级"
    overall = _bounded_projection_decimal(
        payload["overall_score"],
        "overall score",
        maximum=Decimal(100),
    )
    confidence = _bounded_projection_decimal(
        payload["confidence_percent"],
        "overall confidence",
        maximum=Decimal(100),
    )
    intrinsic = _projection_decimal(
        payload["current_intrinsic_value"],
        "current intrinsic value",
    )
    market = _projection_decimal(payload["market_price"], "market price")
    if intrinsic <= 0 or market <= 0:
        raise ResearchReportError("recommendation basis must be positive")
    margin = _projection_decimal(payload["margin_of_safety"], "margin of safety")
    upside = _projection_decimal(payload["twelve_month_upside"], "twelve-month upside")
    critical_flags = payload["critical_red_flags"]
    permanent_loss = any(item["severity"] == "permanent_loss" for item in critical_flags)
    if overall < 50 or _materially_overvalued(market, intrinsic) or permanent_loss:
        return "回避"
    if (
        overall >= 80
        and confidence >= 80
        and margin >= Decimal("0.25")
        and upside >= Decimal("0.20")
        and not critical_flags
    ):
        return "重点关注"
    if (
        overall >= 70
        and confidence >= 70
        and margin >= Decimal("0.15")
        and upside >= Decimal("0.10")
        and not critical_flags
    ):
        return "关注"
    return "观察"


@_uses_report_decimal_context
def _validate_synthesis_projection_arithmetic(
    schema_name: str,
    payload: Mapping[str, Any],
) -> None:
    _validate_publication_decimal_domain(payload)
    scenarios = payload.get("scenarios")
    if schema_name in {"forward-reoi-valuation-result", "comparable-valuation-result"}:
        if not isinstance(scenarios, list) or tuple(
            item.get("name") for item in scenarios if isinstance(item, dict)
        ) != ("black_swan", "base", "bull"):
            raise ResearchReportError("valuation publication scenario order is invalid")
    if schema_name == "comparable-valuation-result":
        metric_results = payload["metric_results"]
        input_receipt = payload["input_receipt"]
        if payload["valid_multiple_count"] != len(metric_results) or payload[
            "valid_peer_count"
        ] != len(input_receipt["peer_set"]):
            raise ResearchReportError("comparable publication counts do not replay")
    if schema_name == "composite-valuation-result" and payload["status"] != "blocked":
        panel_scenarios = payload["panel_scenarios"]
        if set(panel_scenarios) != {"mckinsey", "forward_reoi", "comparables"}:
            raise ResearchReportError("composite publication panel set is not closed")
        base_rows: list[Mapping[str, Any]] = []
        for rows in panel_scenarios.values():
            if not isinstance(rows, list) or tuple(item.get("name") for item in rows) != (
                "black_swan",
                "base",
                "bull",
            ):
                raise ResearchReportError("composite publication scenario order is invalid")
            base_rows.append(rows[1])
        current_values = [
            _projection_decimal(item["current_value_per_share"], "current panel value")
            for item in base_rows
        ]
        future_values = [
            _projection_decimal(
                item["twelve_month_value_per_share"],
                "twelve-month panel value",
            )
            for item in base_rows
        ]
        current = _projection_median(current_values)
        future = _projection_median(future_values)
        market = _projection_decimal(payload["market_price"], "market price")
        with localcontext(_report_decimal_context(precision=60)):
            current_dispersion = (max(current_values) - min(current_values)) / abs(current)
            future_dispersion = (max(future_values) - min(future_values)) / abs(future)
            margin = (current - market) / current
            upside = (future - market) / market
        if (
            _projection_decimal(
                payload["current_relative_dispersion"],
                "current composite dispersion",
            )
            != current_dispersion
            or _projection_decimal(
                payload["twelve_month_relative_dispersion"],
                "twelve-month composite dispersion",
            )
            != future_dispersion
        ):
            raise ResearchReportError("composite publication arithmetic does not replay")
        current_contested = current_dispersion > Decimal("0.50")
        twelve_month_contested = future_dispersion > Decimal("0.50")
        if current_contested:
            if (
                payload["current_intrinsic_value"] is not None
                or payload["margin_of_safety"] is not None
            ):
                raise ResearchReportError("contested current composite was published")
        elif (
            _projection_decimal(
                payload["current_intrinsic_value"],
                "current composite value",
            )
            != current
            or _projection_decimal(
                payload["margin_of_safety"],
                "composite margin of safety",
            )
            != margin
        ):
            raise ResearchReportError("current composite arithmetic does not replay")
        if twelve_month_contested:
            if (
                payload["twelve_month_target"] is not None
                or payload["twelve_month_upside"] is not None
            ):
                raise ResearchReportError("contested twelve-month composite was published")
        elif (
            _projection_decimal(
                payload["twelve_month_target"],
                "twelve-month composite value",
            )
            != future
            or _projection_decimal(
                payload["twelve_month_upside"],
                "twelve-month composite upside",
            )
            != upside
        ):
            raise ResearchReportError("twelve-month composite arithmetic does not replay")
        contested = current_contested or twelve_month_contested
        expected_issue_codes = [
            issue_code
            for is_contested, issue_code in (
                (
                    current_contested,
                    "current_panel_dispersion_exceeds_50_percent",
                ),
                (
                    twelve_month_contested,
                    "twelve_month_panel_dispersion_exceeds_50_percent",
                ),
            )
            if is_contested
        ]
        if (
            payload["contested"] is not contested
            or payload["recommendation_eligible"] is contested
            or payload["status"] != ("contested" if contested else "complete")
            or payload["issue_codes"] != expected_issue_codes
        ):
            raise ResearchReportError("composite publication status does not replay")
    if schema_name == "score-v2":
        components = payload["components"]
        lens = payload["lens"]
        if tuple(item["component_id"] for item in components) != LENS_COMPONENTS[lens]:
            raise ResearchReportError("Score 2.0 publication rubric identity drifted")
        component_statuses = tuple(item["status"] for item in components)
        expected_status = (
            "blocked"
            if "blocked" in component_statuses
            else "partial"
            if any(item != "complete" for item in component_statuses)
            else "complete"
        )
        if payload["status"] != expected_status:
            raise ResearchReportError("Score 2.0 publication status does not replay")
        for component in components:
            if component["max_score"] != "20":
                raise ResearchReportError("Score 2.0 component maximum drifted")
            if component["status"] == "complete":
                _bounded_projection_decimal(
                    component["score"],
                    "component score",
                    maximum=Decimal(20),
                )
                _bounded_projection_decimal(
                    component["confidence_percent"],
                    "component confidence",
                    maximum=Decimal(100),
                )
                if component["missing_evidence"] or not component["evidence_bindings"]:
                    raise ResearchReportError(
                        "complete Score 2.0 component evidence does not replay"
                    )
            elif (
                component["score"] is not None
                or component["confidence_percent"] is not None
                or not component["missing_evidence"]
            ):
                raise ResearchReportError(
                    "incomplete Score 2.0 component exposes a numeric score"
                )
        expected_missing = sorted(
            {
                code
                for component in components
                for code in component["missing_evidence"]
            }
        )
        expected_flags = [
            flag for component in components for flag in component["red_flags"]
        ]
        if (
            payload["missing_evidence"] != expected_missing
            or payload["red_flags"] != expected_flags
        ):
            raise ResearchReportError("Score 2.0 publication evidence summary does not replay")
        if expected_status == "complete":
            with localcontext(score_calculation_context()):
                total = sum(
                    (
                        _bounded_projection_decimal(
                            item["score"],
                            "component score",
                            maximum=Decimal(20),
                        )
                        for item in components
                    ),
                    Decimal(0),
                )
                confidence = sum(
                    (
                        _bounded_projection_decimal(
                            item["confidence_percent"],
                            "component confidence",
                            maximum=Decimal(100),
                        )
                        for item in components
                    ),
                    Decimal(0),
                ) / Decimal(5)
            if (
                _bounded_projection_decimal(
                    payload["total_score"],
                    "score total",
                    maximum=Decimal(100),
                )
                != total
                or _bounded_projection_decimal(
                    payload["confidence_percent"],
                    "score confidence",
                    maximum=Decimal(100),
                )
                != confidence
            ):
                raise ResearchReportError("Score 2.0 publication arithmetic does not replay")
        elif payload["total_score"] is not None or payload["confidence_percent"] is not None:
            raise ResearchReportError("partial Score 2.0 publication exposes a numeric total")
    if schema_name == "owner-scorecard":
        lens_scores = payload["lens_scores"]
        if tuple(item["lens"] for item in lens_scores) != (
            "graham",
            "buffett",
            "munger",
            "duan_yongping",
        ):
            raise ResearchReportError("OwnerScorecard publication lens order is invalid")
        for row in lens_scores:
            if row["status"] == "complete":
                _bounded_projection_decimal(
                    row["total_score"],
                    "lens score",
                    maximum=Decimal(100),
                )
                _bounded_projection_decimal(
                    row["confidence_percent"],
                    "lens confidence",
                    maximum=Decimal(100),
                )
            elif row["total_score"] is not None or row["confidence_percent"] is not None:
                raise ResearchReportError(
                    "incomplete OwnerScorecard lens exposes a numeric score"
                )
        lens_statuses = tuple(row["status"] for row in lens_scores)
        if (
            payload["status"] == "complete"
            and any(item != "complete" for item in lens_statuses)
        ) or (
            payload["status"] == "partial"
            and (
                "blocked" in lens_statuses
                or all(item == "complete" for item in lens_statuses)
            )
        ) or (
            payload["status"] == "blocked"
            and all(item == "complete" for item in lens_statuses)
        ):
            raise ResearchReportError("OwnerScorecard publication status does not replay")
        if payload["status"] == "complete":
            with localcontext(score_calculation_context()):
                overall = sum(
                    (
                        _bounded_projection_decimal(
                            item["total_score"],
                            "lens score",
                            maximum=Decimal(100),
                        )
                        for item in lens_scores
                    ),
                    Decimal(0),
                )
                overall /= Decimal(4)
                confidence = sum(
                    (
                        _bounded_projection_decimal(
                            item["confidence_percent"],
                            "lens confidence",
                            maximum=Decimal(100),
                        )
                        for item in lens_scores
                    ),
                    Decimal(0),
                ) / Decimal(4)
            if (
                _bounded_projection_decimal(
                    payload["overall_score"],
                    "overall score",
                    maximum=Decimal(100),
                )
                != overall
                or _bounded_projection_decimal(
                    payload["confidence_percent"],
                    "overall confidence",
                    maximum=Decimal(100),
                )
                != confidence
            ):
                raise ResearchReportError("OwnerScorecard publication arithmetic does not replay")
        elif payload["overall_score"] is not None or payload["confidence_percent"] is not None:
            raise ResearchReportError("partial OwnerScorecard publication exposes a numeric total")
        critical_flags = payload["critical_red_flags"]
        if any(
            item["severity"] not in {"critical", "permanent_loss"}
            for item in critical_flags
        ) or len(
            {
                (item["code"], item["severity"], canonical_sha256(item))
                for item in critical_flags
            }
        ) != len(critical_flags):
            raise ResearchReportError("OwnerScorecard critical flags do not replay")
        if payload["recommendation"] != _scorecard_publication_recommendation(payload):
            raise ResearchReportError("OwnerScorecard recommendation does not replay")


def _validate_downstream_publication_chain(
    *,
    research_bundle_fingerprint: str,
    contract_graph_fingerprint: str,
    valuation_archive_fingerprint: str,
    valuation_result_sha256: str,
    futu_session_manifest: FutuSessionPublicationManifest | None,
    futu_partial_session_manifest: FutuPartialSessionPublicationManifest | None,
    forward_manifest: ForwardReOIValuationPublicationManifest | None,
    comparable_manifest: ComparableValuationPublicationManifest | None,
    composite_manifest: CompositeValuationPublicationManifest,
    score_manifests: tuple[ScoreV2PublicationManifest, ...],
    scorecard_manifest: OwnerScorecardPublicationManifest,
    market_manifest: MarketExpectationsPublicationManifest | None,
    runtime_gap_manifest: RuntimeGapPublicationManifest | None,
) -> None:
    forward = None if forward_manifest is None else to_json_value(forward_manifest.source_payload)
    comparable = (
        None if comparable_manifest is None else to_json_value(comparable_manifest.source_payload)
    )
    composite = to_json_value(composite_manifest.source_payload)
    scorecard = to_json_value(scorecard_manifest.source_payload)
    scores = [to_json_value(item.source_payload) for item in score_manifests]
    if any(not isinstance(item, dict) for item in (composite, scorecard, *scores)):
        raise ResearchReportError("downstream publication projection is not an object")
    if forward is not None and not isinstance(forward, dict):
        raise ResearchReportError("forward ReOI publication projection is not an object")
    if comparable is not None and not isinstance(comparable, dict):
        raise ResearchReportError("comparable publication projection is not an object")
    basis = composite["basis_receipt"]
    if (
        basis["core_archive_fingerprint"] != valuation_archive_fingerprint
        or basis["core_result_sha256"] != valuation_result_sha256
        or composite["core_archive_fingerprint"] != valuation_archive_fingerprint
        or composite["core_result_sha256"] != valuation_result_sha256
        or composite["panel_fingerprints"]["forward_reoi"]
        != (None if forward_manifest is None else forward_manifest.source_fingerprint)
        or composite["panel_fingerprints"]["comparables"]
        != (None if comparable_manifest is None else comparable_manifest.source_fingerprint)
    ):
        raise ResearchReportError("downstream valuation manifests rebind their strict archive")
    for panel in (forward, comparable):
        if panel is not None and panel["basis_receipt"] != basis:
            raise ResearchReportError("downstream panel manifest rebinds the common basis")
    if comparable is not None:
        if futu_session_manifest is not None:
            futu_peer = futu_session_manifest.peer_evidence_set
        elif futu_partial_session_manifest is not None:
            futu_peer = futu_partial_session_manifest.peer_evidence_set
        else:
            raise ResearchReportError("comparable manifest lacks typed Futu peer evidence")
        if (
            comparable["input_receipt"]["futu_peer_evidence_set_fingerprint"]
            != futu_peer["fingerprint"]
        ):
            raise ResearchReportError("comparable manifest is rebound from Futu peer evidence")
    if (
        len(score_manifests) != 4
        or {item.lens for item in score_manifests}
        != {"graham", "buffett", "munger", "duan_yongping"}
        or any(item["issuer_id"] != composite["issuer_id"] for item in scores)
        or any(
            item["research_bundle_fingerprint"] != research_bundle_fingerprint
            or item["contract_graph_fingerprint"] != contract_graph_fingerprint
            or item["composite_valuation_fingerprint"] != composite_manifest.source_fingerprint
            or item["as_of_date"] != composite["basis_receipt"]["valuation_date"]
            for item in scores
        )
    ):
        raise ResearchReportError("Score 2.0 manifests rebind research or valuation authority")
    expected_lenses = {item.lens: item for item in score_manifests}
    expected_rows = [
        {
            "lens": lens,
            "score_id": expected_lenses[lens].source_payload["score_id"],
            "score_fingerprint": expected_lenses[lens].source_fingerprint,
            "status": expected_lenses[lens].source_payload["status"],
            "total_score": expected_lenses[lens].source_payload["total_score"],
            "confidence_percent": expected_lenses[lens].source_payload[
                "confidence_percent"
            ],
        }
        for lens in LENS_COMPONENTS
    ]
    expected_issues: list[str] = []
    if composite["status"] == "contested" or composite["contested"]:
        expected_issues.append("composite_valuation_contested")
    elif composite["status"] == "blocked" or not composite["recommendation_eligible"]:
        expected_issues.append("composite_valuation_blocked")
    for lens in LENS_COMPONENTS:
        score_status = expected_lenses[lens].source_payload["status"]
        if score_status != "complete":
            expected_issues.append(f"{lens}_score_{score_status}")
    if (
        composite["status"] in {"blocked", "contested"}
        or composite["contested"]
        or not composite["recommendation_eligible"]
        or any(item["status"] == "blocked" for item in scores)
    ):
        expected_scorecard_status = "blocked"
    elif any(item["status"] != "complete" for item in scores):
        expected_scorecard_status = "partial"
    else:
        expected_scorecard_status = "complete"
    critical_flags: list[dict[str, Any]] = []
    seen_flags: set[tuple[str, str, str]] = set()
    for lens in LENS_COMPONENTS:
        for flag in expected_lenses[lens].source_payload["red_flags"]:
            if flag["severity"] not in {"critical", "permanent_loss"}:
                continue
            raw_flag = to_json_value(flag)
            assert isinstance(raw_flag, dict)
            identity = (raw_flag["code"], raw_flag["severity"], canonical_sha256(raw_flag))
            if identity not in seen_flags:
                critical_flags.append(raw_flag)
                seen_flags.add(identity)
    critical_flags.sort(key=lambda item: (item["severity"], item["code"]))
    if (
        scorecard["issuer_id"] != composite["issuer_id"]
        or scorecard["as_of_date"] != composite["basis_receipt"]["valuation_date"]
        or scorecard["research_bundle_fingerprint"] != research_bundle_fingerprint
        or scorecard["composite_valuation_fingerprint"] != composite_manifest.source_fingerprint
        or scorecard["lens_scores"] != expected_rows
        or scorecard["status"] != expected_scorecard_status
        or scorecard["current_intrinsic_value"] != composite["current_intrinsic_value"]
        or scorecard["market_price"] != composite["market_price"]
        or scorecard["margin_of_safety"] != composite["margin_of_safety"]
        or scorecard["twelve_month_upside"] != composite["twelve_month_upside"]
        or scorecard["critical_red_flags"] != critical_flags
        or scorecard["issue_codes"] != sorted(set(expected_issues))
    ):
        raise ResearchReportError("OwnerScorecard manifest rebinds its four exact lenses")
    if composite["status"] == "complete":
        if (
            futu_session_manifest is None
            or futu_partial_session_manifest is not None
            or forward_manifest is None
            or comparable_manifest is None
            or market_manifest is None
            or runtime_gap_manifest is not None
        ):
            raise ResearchReportError("complete conclusion lacks its closed post-context chain")
        try:
            validate_market_expectations_publication_manifest(
                market_manifest,
                futu_session_manifest=futu_session_manifest,
            )
        except OwnerEquityTypeError as exc:
            raise ResearchReportError("market expectations publication does not replay") from exc
        market = market_manifest.to_dict()
        if (
            market["composite_valuation_fingerprint"] != composite_manifest.source_fingerprint
            or market["owner_scorecard_fingerprint"] != scorecard_manifest.source_fingerprint
        ):
            raise ResearchReportError("market expectations alter the frozen conclusion")
        return
    if composite["status"] not in {"blocked", "contested"}:
        raise ResearchReportError("downstream composite status is not closed")
    if (
        futu_session_manifest is not None
        or market_manifest is not None
        or futu_partial_session_manifest is None
        or runtime_gap_manifest is None
    ):
        raise ResearchReportError("ineligible conclusion exposes post-context data")
    try:
        validate_futu_partial_session_publication_manifest(futu_partial_session_manifest)
    except FutuSessionEvidenceError as exc:
        raise ResearchReportError("partial Futu session publication does not replay") from exc
    gap = runtime_gap_manifest.to_dict()
    if (
        gap["issuer_id"] != composite["issuer_id"]
        or gap["upstream_fingerprints"]["composite_valuation"]
        != composite_manifest.source_fingerprint
        or gap["upstream_fingerprints"]["owner_scorecard"] != scorecard_manifest.source_fingerprint
        or gap["upstream_fingerprints"]["sidecar_finalization"]
        != futu_partial_session_manifest.attested_finalization_fingerprint
    ):
        raise ResearchReportError("runtime gap rebinds partial-session authorities")


@dataclass(frozen=True, slots=True)
class ReportBuildResult:
    profile: str
    issuer_id: str
    data_cutoff_date: str
    artifacts: tuple[ReportArtifact, ...]
    receipt: ReportBuildReceipt
    content: ResearchReportContent
    research_source_index: ResearchSourceIndex | None = None
    research_source_manifest: ResearchSourceIndexPublicationManifest | None = None
    legacy_scores: tuple[Score, ...] = ()
    futu_session_evidence: FutuSessionEvidence | None = None
    futu_session_manifest: FutuSessionPublicationManifest | None = None
    futu_market_execution_evidence: FutuMarketExecutionEvidence | None = None
    futu_peer_evidence_set: FutuPeerEvidenceSet | None = None
    futu_partial_session_manifest: FutuPartialSessionPublicationManifest | None = None
    futu_optional_data_dispositions: tuple[FutuOptionalDataDisposition, ...] = ()
    futu_optional_data_disposition_manifests: tuple[
        FutuOptionalDataDispositionPublicationManifest, ...
    ] = ()
    forward_reoi: ForwardReOIValuationResult | None = None
    comparable_valuation: ComparableValuationResult | None = None
    composite_valuation: CompositeValuationResult | None = None
    score_v2: tuple[ScoreV2, ...] = ()
    owner_scorecard: OwnerScorecard | None = None
    forward_reoi_manifest: ForwardReOIValuationPublicationManifest | None = None
    comparable_valuation_manifest: ComparableValuationPublicationManifest | None = None
    composite_valuation_manifest: CompositeValuationPublicationManifest | None = None
    score_v2_manifests: tuple[ScoreV2PublicationManifest, ...] = ()
    owner_scorecard_manifest: OwnerScorecardPublicationManifest | None = None
    market_expectations: MarketExpectationsComparison | None = None
    market_expectations_manifest: MarketExpectationsPublicationManifest | None = None
    runtime_gap: RuntimeGapReceipt | None = None
    runtime_gap_manifest: RuntimeGapPublicationManifest | None = None

    def __post_init__(self) -> None:
        if self.profile not in REPORT_PROFILES:
            raise ResearchReportError("unknown report profile")
        if any(type(item) is not ReportArtifact for item in self.artifacts):
            raise ResearchReportError("report artifacts must use the exact typed artifact")
        if type(self.receipt) is not ReportBuildReceipt:
            raise ResearchReportError("report result requires an exact ReportBuildReceipt")
        if type(self.content) is not ResearchReportContent:
            raise ResearchReportError("report result requires exact ResearchReportContent")
        if (
            self.content["profile"] != self.profile
            or self.content["issuer_id"] != self.issuer_id
            or self.content["data_cutoff_date"] != self.data_cutoff_date
            or self.receipt["report_content_fingerprint"] != self.content.fingerprint
        ):
            raise ResearchReportError("report content identity differs from its build result")
        if (
            self.research_source_index is not None
            and type(self.research_source_index) is not ResearchSourceIndex
        ):
            raise ResearchReportError("report source index has the wrong exact type")
        if (
            self.research_source_manifest is not None
            and type(self.research_source_manifest) is not ResearchSourceIndexPublicationManifest
        ):
            raise ResearchReportError("report source manifest has the wrong exact type")
        paths = tuple(item.path for item in self.artifacts)
        if len(paths) != len(set(paths)):
            raise ResearchReportError("report artifact paths must be unique")
        if any(type(item) is not Score for item in self.legacy_scores):
            raise ResearchReportError("legacy report scores must use the exact Score type")
        if (
            self.futu_session_evidence is not None
            and type(self.futu_session_evidence) is not FutuSessionEvidence
        ):
            raise ResearchReportError("report Futu session evidence has the wrong exact type")
        if (
            self.futu_session_manifest is not None
            and type(self.futu_session_manifest) is not FutuSessionPublicationManifest
        ):
            raise ResearchReportError("report Futu manifest has the wrong exact type")
        if (
            self.futu_market_execution_evidence is not None
            and type(self.futu_market_execution_evidence) is not FutuMarketExecutionEvidence
        ):
            raise ResearchReportError("report Futu market evidence has the wrong exact type")
        if (
            self.futu_peer_evidence_set is not None
            and type(self.futu_peer_evidence_set) is not FutuPeerEvidenceSet
        ):
            raise ResearchReportError("report Futu peer evidence has the wrong exact type")
        if (
            self.futu_partial_session_manifest is not None
            and type(self.futu_partial_session_manifest)
            is not FutuPartialSessionPublicationManifest
        ):
            raise ResearchReportError("report partial Futu manifest has the wrong exact type")
        if any(
            type(item) is not FutuOptionalDataDisposition
            for item in self.futu_optional_data_dispositions
        ):
            raise ResearchReportError("report optional Futu dispositions have the wrong type")
        if any(
            type(item) is not FutuOptionalDataDispositionPublicationManifest
            for item in self.futu_optional_data_disposition_manifests
        ):
            raise ResearchReportError("report optional Futu manifests have the wrong type")
        if (
            self.forward_reoi is not None
            and type(self.forward_reoi) is not ForwardReOIValuationResult
        ):
            raise ResearchReportError("report forward ReOI result has the wrong exact type")
        if (
            self.comparable_valuation is not None
            and type(self.comparable_valuation) is not ComparableValuationResult
        ):
            raise ResearchReportError("report comparable result has the wrong exact type")
        if (
            self.composite_valuation is not None
            and type(self.composite_valuation) is not CompositeValuationResult
        ):
            raise ResearchReportError("report composite result has the wrong exact type")
        if any(type(item) is not ScoreV2 for item in self.score_v2):
            raise ResearchReportError("report Score 2.0 entries have the wrong exact type")
        if self.owner_scorecard is not None and type(self.owner_scorecard) is not OwnerScorecard:
            raise ResearchReportError("report owner scorecard has the wrong exact type")
        if (
            self.forward_reoi_manifest is not None
            and type(self.forward_reoi_manifest) is not ForwardReOIValuationPublicationManifest
        ):
            raise ResearchReportError("report forward ReOI manifest has the wrong exact type")
        if (
            self.comparable_valuation_manifest is not None
            and type(self.comparable_valuation_manifest)
            is not ComparableValuationPublicationManifest
        ):
            raise ResearchReportError("report comparable manifest has the wrong exact type")
        if (
            self.composite_valuation_manifest is not None
            and type(self.composite_valuation_manifest) is not CompositeValuationPublicationManifest
        ):
            raise ResearchReportError("report composite manifest has the wrong exact type")
        if any(type(item) is not ScoreV2PublicationManifest for item in self.score_v2_manifests):
            raise ResearchReportError("report Score 2.0 manifests have the wrong exact type")
        if (
            self.owner_scorecard_manifest is not None
            and type(self.owner_scorecard_manifest) is not OwnerScorecardPublicationManifest
        ):
            raise ResearchReportError("report scorecard manifest has the wrong exact type")
        live_values = (
            self.forward_reoi,
            self.comparable_valuation,
            self.composite_valuation,
            self.owner_scorecard,
        )
        manifests = (
            self.forward_reoi_manifest,
            self.comparable_valuation_manifest,
            self.composite_valuation_manifest,
            self.owner_scorecard_manifest,
        )
        if self.profile == "research_only" and (
            any(item is not None for item in (*live_values, *manifests))
            or self.score_v2
            or self.score_v2_manifests
            or self.futu_session_evidence is not None
            or self.futu_session_manifest is not None
            or self.futu_market_execution_evidence is not None
            or self.futu_peer_evidence_set is not None
            or self.futu_partial_session_manifest is not None
            or self.futu_optional_data_dispositions
            or self.futu_optional_data_disposition_manifests
            or self.market_expectations is not None
            or self.market_expectations_manifest is not None
            or self.runtime_gap is not None
            or self.runtime_gap_manifest is not None
        ):
            raise ResearchReportError("research_only report retains valuation or Score data")
        if self.profile == "full_valuation":
            if (
                self.composite_valuation_manifest is None
                or self.owner_scorecard_manifest is None
                or len(self.score_v2_manifests) != 4
                or tuple(
                    item.to_dict()["protocol_id"]
                    for item in self.futu_optional_data_disposition_manifests
                )
                != (3235, 3244, 3245, 3246)
            ):
                raise ResearchReportError("full report lacks disk-safe downstream manifests")
            if self.futu_optional_data_dispositions:
                if (
                    tuple(item.protocol_id for item in self.futu_optional_data_dispositions)
                    != (3235, 3244, 3245, 3246)
                    or tuple(
                        item.fingerprint for item in self.futu_optional_data_dispositions
                    )
                    != tuple(
                        item.fingerprint
                        for item in self.futu_optional_data_disposition_manifests
                    )
                ):
                    raise ResearchReportError(
                        "optional Futu manifests were rebound from live authority"
                    )
            if (
                tuple(
                    self.receipt[
                        "futu_optional_data_disposition_publication_manifest_fingerprints"
                    ]
                )
                != tuple(
                    item.fingerprint
                    for item in self.futu_optional_data_disposition_manifests
                )
                or (
                    self.futu_optional_data_dispositions
                    and tuple(
                        self.receipt["futu_optional_data_disposition_fingerprints"]
                    )
                    != tuple(
                        item.fingerprint
                        for item in self.futu_optional_data_dispositions
                    )
                )
            ):
                raise ResearchReportError("report receipt rebinds optional Futu dispositions")
            if any(item is not None for item in live_values) or self.score_v2:
                if (
                    self.composite_valuation is None
                    or self.owner_scorecard is None
                    or len(self.score_v2) != 4
                ):
                    raise ResearchReportError(
                        "full live report retains an incomplete authority chain"
                    )
                expected_pairs = (
                    (self.forward_reoi_manifest, self.forward_reoi),
                    (self.comparable_valuation_manifest, self.comparable_valuation),
                    (self.composite_valuation_manifest, self.composite_valuation),
                    (self.owner_scorecard_manifest, self.owner_scorecard),
                )
                if (
                    any(
                        (manifest is None) != (source is None)
                        for manifest, source in expected_pairs
                    )
                    or any(
                        manifest.source_fingerprint != source.fingerprint
                        for manifest, source in expected_pairs
                        if manifest is not None and source is not None
                    )
                    or {item.source_fingerprint for item in self.score_v2_manifests}
                    != {item.fingerprint for item in self.score_v2}
                ):
                    raise ResearchReportError(
                        "downstream manifests were rebound from live authority"
                    )
        if (
            self.market_expectations is not None
            and type(self.market_expectations) is not MarketExpectationsComparison
        ):
            raise ResearchReportError("report market expectations have the wrong exact type")
        if (
            self.market_expectations_manifest is not None
            and type(self.market_expectations_manifest) is not MarketExpectationsPublicationManifest
        ):
            raise ResearchReportError("report market manifest has the wrong exact type")
        if self.runtime_gap is not None and type(self.runtime_gap) is not RuntimeGapReceipt:
            raise ResearchReportError("report runtime gap has the wrong exact type")
        if (
            self.runtime_gap_manifest is not None
            and type(self.runtime_gap_manifest) is not RuntimeGapPublicationManifest
        ):
            raise ResearchReportError("report runtime-gap manifest has the wrong exact type")
        if self.profile == "full_valuation":
            complete_context = self.futu_session_manifest is not None
            partial_context = self.futu_partial_session_manifest is not None
            if complete_context == partial_context:
                raise ResearchReportError("full report must retain exactly one Futu context")
            if complete_context and (
                self.market_expectations_manifest is None
                or self.runtime_gap_manifest is not None
                or self.futu_market_execution_evidence is not None
                or self.futu_peer_evidence_set is not None
            ):
                raise ResearchReportError("complete full report has mixed partial context")
            if partial_context and (
                self.futu_session_evidence is not None
                or self.futu_session_manifest is not None
                or self.market_expectations is not None
                or self.market_expectations_manifest is not None
                or self.runtime_gap_manifest is None
            ):
                raise ResearchReportError("partial full report exposes post-context data")

    @property
    def fingerprint(self) -> str:
        return self.receipt.fingerprint


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _canonical_file(value: object) -> bytes:
    return (canonical_json(value) + "\n").encode("utf-8")


def _validate_relative_path(value: str) -> None:
    if type(value) is not str or _SAFE_ARTIFACT.fullmatch(value) is None:
        raise ResearchReportError(f"unsafe report artifact path: {value!r}")


def _validate_https_supply_url(value: str) -> None:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ResearchReportError("report toolchain supply URL is invalid") from exc
    if (
        type(value) is not str
        or len(value) > 2048
        or parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or port is not None
    ):
        raise ResearchReportError("report toolchain supply URL is not a closed HTTPS reference")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or "." in path.parts:
        raise ResearchReportError(f"unsafe report artifact path: {value!r}")


def _parallel_schema_directory() -> Path:
    packaged = Path(__file__).parent / "extension_schemas"
    if packaged.is_dir():
        return packaged
    repository = Path(__file__).parents[2] / "extension_schemas"
    if repository.is_dir():
        return repository
    raise ResearchReportError("parallel report schema directory is unavailable")


def _validate_parallel_schema(name: str, payload: Mapping[str, object]) -> None:
    path = _parallel_schema_directory() / f"{name}.schema.json"
    try:
        schema = json.loads(
            _read_bounded_regular_file(
                path,
                limit=REPORT_TEXT_MAX_BYTES,
                label=f"{name} packaged schema",
            ).decode("utf-8")
        )
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(
            to_json_value(payload)
        )
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        JSONSchemaValidationError,
        ValueError,
    ) as exc:
        raise ResearchReportError(f"{name} schema validation failed: {exc}") from exc


def _read_exact_flat_directory(
    path: Path,
    filenames: tuple[str, ...],
    *,
    member_limit: int,
    total_limit: int,
) -> dict[str, bytes]:
    """Capture a closed flat directory through stable no-follow descriptors."""

    absolute = Path(path).expanduser().absolute()
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        directory_fd = os.open(absolute, flags)
    except OSError as exc:
        raise ResearchReportError("strict input directory is unavailable") from exc
    try:
        before = os.fstat(directory_fd)
        if not stat.S_ISDIR(before.st_mode):
            raise ResearchReportError("strict input path is not a directory")
        names = tuple(sorted(os.listdir(directory_fd)))
        if names != tuple(sorted(filenames)):
            raise ResearchReportError("strict input directory has an unexpected member set")
        remaining = total_limit
        contents: dict[str, bytes] = {}
        for name in names:
            open_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            open_flags |= getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(name, open_flags, dir_fd=directory_fd)
            try:
                first = os.fstat(descriptor)
                maximum = min(member_limit, remaining)
                if (
                    not stat.S_ISREG(first.st_mode)
                    or first.st_nlink != 1
                    or first.st_size > maximum
                ):
                    raise ResearchReportError(f"strict input member is unsafe: {name}")
                chunks: list[bytes] = []
                consumed = 0
                while True:
                    chunk = os.read(descriptor, min(1024 * 1024, maximum - consumed + 1))
                    if not chunk:
                        break
                    consumed += len(chunk)
                    if consumed > maximum:
                        raise ResearchReportError(f"strict input member exceeds limit: {name}")
                    chunks.append(chunk)
                final = os.fstat(descriptor)
                identity = (
                    first.st_dev,
                    first.st_ino,
                    first.st_size,
                    first.st_mtime_ns,
                    first.st_ctime_ns,
                    first.st_mode,
                    first.st_nlink,
                    first.st_uid,
                    first.st_gid,
                )
                if consumed != first.st_size or identity != (
                    final.st_dev,
                    final.st_ino,
                    final.st_size,
                    final.st_mtime_ns,
                    final.st_ctime_ns,
                    final.st_mode,
                    final.st_nlink,
                    final.st_uid,
                    final.st_gid,
                ):
                    raise ResearchReportError(f"strict input member changed while read: {name}")
                contents[name] = b"".join(chunks)
                remaining -= consumed
            finally:
                os.close(descriptor)
        after = os.fstat(directory_fd)
        if tuple(sorted(os.listdir(directory_fd))) != names or (
            before.st_dev,
            before.st_ino,
            before.st_mtime_ns,
            before.st_ctime_ns,
            before.st_mode,
            before.st_uid,
            before.st_gid,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_mtime_ns,
            after.st_ctime_ns,
            after.st_mode,
            after.st_uid,
            after.st_gid,
        ):
            raise ResearchReportError("strict input directory changed while read")
        return contents
    except OSError as exc:
        raise ResearchReportError("strict input read failed") from exc
    finally:
        os.close(directory_fd)


def reload_research_input(
    input_directory: Path,
    *,
    graph: ContractGraph,
    maximum_total_bytes: int = RESEARCH_ARTIFACT_LOAD_MAX_BYTES,
    read_callback: ResearchArtifactReadCallback | None = None,
) -> ReloadedResearchInput:
    """Strictly reload the canonical research pair into an immutable typed input."""

    if type(graph) is not ContractGraph:
        raise ResearchReportError("research reload requires an exact ContractGraph")
    source = Path(input_directory).expanduser().absolute()
    result, contents = load_research_bundle_artifact_snapshot(
        source,
        graph=graph,
        maximum_total_bytes=maximum_total_bytes,
        read_callback=read_callback,
    )
    expected = _research_input_file_bytes(result)
    if contents != expected:
        raise ResearchReportError("research input changed after strict typed reload")
    return ReloadedResearchInput(
        source_directory=source,
        result=result,
        file_bytes=contents,
        file_sha256={name: _sha256(content) for name, content in contents.items()},
    )


def reload_valuation_input(
    input_directory: Path,
    *,
    component_lock_path: Path | None = None,
) -> ReloadedValuationInput:
    """Strictly reload the frozen six-file valuation archive into a typed input."""

    source = Path(input_directory).expanduser().absolute()
    archive = load_valuation_run_archive(source, component_lock_path=component_lock_path)
    contents = _valuation_archive_file_bytes(archive)
    if tuple(contents) != VALUATION_RUN_ARCHIVE_FILENAMES:
        raise ResearchReportError("valuation input canonical snapshot is incomplete")
    hashes = {name: _sha256(content) for name, content in contents.items()}
    if hashes != dict(archive.file_sha256):
        raise ResearchReportError("valuation input typed snapshot differs from verified bytes")
    return ReloadedValuationInput(
        source_directory=source,
        archive=archive,
        file_bytes=contents,
        file_sha256=hashes,
    )


def _clean_text(value: object) -> str:
    text = str(value).translate(_DASH_TRANSLATION)
    return " ".join(text.split())


_CJK_DIGIT_EXTRACTION_GAP = re.compile(r"(?<=[\u4e00-\u9fff0-9])\s+(?=[\u4e00-\u9fff0-9])")
_DISPLAY_DECIMAL = re.compile(r"[-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?")
_DISPLAY_DECIMAL_TOKEN = re.compile(
    r"(?<![0-9A-Za-z_.-])"
    r"[-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?"
    r"(?![0-9A-Za-z_]|\.(?=\d)|-(?=\d))"
)


@_uses_report_decimal_context
def _professional_decimal_text(value: object) -> str:
    """Summarize one visible decimal without changing the retained source value."""

    text = _clean_text(value)
    if _DISPLAY_DECIMAL.fullmatch(text) is None:
        return text
    # Digit-only strings may be identifiers (CIKs, protocol IDs, dates, or receipt
    # sequence numbers).  They have no binary-float artefact to remove, so retain
    # their exact spelling, including leading zeroes.
    if "." not in text:
        if "e" not in text.lower():
            return text
        # A digit-only exponent without an explicit sign is also a common SHA/ID
        # fragment (for example ``64e760343312``).  It is already compact and
        # must not be interpreted as a display number.
        exponent = text.lower().split("e", 1)[1]
        if not exponent.startswith(("+", "-")):
            return text
    try:
        parsed = Decimal(text)
    except InvalidOperation:
        return text
    if not parsed.is_finite():
        return text
    if parsed.is_zero():
        return "0"

    rounded = Decimal(format(parsed, ".6g"))
    if -4 <= rounded.adjusted() < 12:
        rendered = format(rounded, "f")
        if "." in rendered:
            rendered = rendered.rstrip("0").rstrip(".")
        return rendered

    scientific = format(rounded, "E")
    mantissa, exponent = scientific.split("E", 1)
    if "." in mantissa:
        mantissa = mantissa.rstrip("0").rstrip(".")
    return f"{mantissa}e{int(exponent)}"


def _professionalize_numeric_tokens(value: object) -> str:
    """Format standalone visible decimals while leaving IDs, dates, and URLs intact."""

    text = _clean_text(value)
    return _DISPLAY_DECIMAL_TOKEN.sub(
        lambda match: _professional_decimal_text(match.group()),
        text,
    )


def _pdf_section_search_text(value: object) -> str:
    """Normalize only the CJK/digit gaps that PDF text extraction inserts."""

    return _CJK_DIGIT_EXTRACTION_GAP.sub("", _clean_text(value))


def _latex_escaped(text: str) -> str:
    replacements = {
        "\\": r"\textbackslash{}",
        "&": r"\&",
        "%": r"\%",
        "$": r"\$",
        "#": r"\#",
        "_": r"\_",
        "{": r"\{",
        "}": r"\}",
        "~": r"\textasciitilde{}",
        "^": r"\textasciicircum{}",
    }
    return "".join(replacements.get(character, character) for character in text)


def _latex(value: object) -> str:
    return _latex_escaped(_clean_text(value))


def _latex_breakable(value: object, *, chunk_size: int = 12) -> str:
    """Escape an identifier while offering TeX safe, deterministic wrap points."""

    text = _clean_text(value)
    if chunk_size < 4:
        raise ResearchReportError("breakable LaTeX chunk size is unsafe")
    return r"\allowbreak{}".join(
        _latex(text[index : index + chunk_size])
        for index in range(0, len(text), chunk_size)
    )


def _latex_camel_breakable(value: object) -> str:
    """Keep report type names readable while permitting breaks at word boundaries."""

    text = _clean_text(value)
    parts = re.findall(r"[A-Z]+(?=[A-Z][a-z]|[0-9]|$)|[A-Z]?[a-z]+|[0-9]+", text)
    if not parts or "".join(parts) != text:
        return _latex_breakable(text, chunk_size=8)
    return r"\allowbreak{}".join(_latex(part) for part in parts)


_TABLE_CELL_MACHINE_DELIMITER = re.compile(r"([_:/@{}\[\].,;=()\-])")
_TABLE_CELL_PLAIN_WORD = re.compile(
    r'''[\("“‘]?[A-Za-z]+(?:['’][A-Za-z]+)*[.,;:!?\)]?["”’]?'''
)


def _latex_table_token(
    value: str,
    *,
    chunk_size: int,
    preserve_plain_words: bool = False,
) -> str:
    """Offer wrap points inside one machine token without changing its text."""

    if len(value) <= max(8, chunk_size):
        return _latex(value)
    if _TABLE_CELL_MACHINE_DELIMITER.search(value) is None:
        return _latex_breakable(value, chunk_size=chunk_size)
    rendered: list[str] = []
    for part in _TABLE_CELL_MACHINE_DELIMITER.split(value):
        if not part:
            continue
        if preserve_plain_words and _TABLE_CELL_PLAIN_WORD.fullmatch(part):
            rendered.append(_latex(part))
        else:
            rendered.append(
                _latex_breakable(part, chunk_size=chunk_size)
                if len(part) > max(12, chunk_size)
                else _latex(part)
            )
        if _TABLE_CELL_MACHINE_DELIMITER.fullmatch(part):
            rendered.append(r"\allowbreak{}")
    return "".join(rendered)


def _latex_table_cell(value: object, *, chunk_size: int = 8) -> str:
    text = _professionalize_numeric_tokens(value)
    if chunk_size < 4:
        raise ResearchReportError("table-cell LaTeX chunk size is unsafe")
    if len(text) <= max(8, chunk_size):
        return _latex(text)
    has_whitespace = re.search(r"\s", text) is not None
    rendered: list[str] = []
    for part in re.split(r"(\s+)", text):
        if not part:
            continue
        if part.isspace():
            rendered.append(" ")
            continue
        if has_whitespace and _TABLE_CELL_PLAIN_WORD.fullmatch(part):
            # Preserve natural prose wrapping and ordinary English words.  Machine
            # tokens embedded beside that prose still receive explicit safe breaks.
            rendered.append(_latex(part))
            continue
        rendered.append(
            _latex_table_token(
                part,
                chunk_size=chunk_size,
                preserve_plain_words=has_whitespace,
            )
        )
    return "".join(rendered)


_LONG_PROSE_TOKEN = re.compile(r"[0-9A-Za-z_:/@.{}\[\]-]{12,}")


def _latex_prose(value: object) -> str:
    """Escape prose while making embedded machine identifiers safely wrappable."""

    text = _professionalize_numeric_tokens(value)
    rendered: list[str] = []
    cursor = 0
    for match in _LONG_PROSE_TOKEN.finditer(text):
        rendered.append(_latex_escaped(text[cursor : match.start()]))
        rendered.append(_latex_breakable(match.group(), chunk_size=4))
        cursor = match.end()
    rendered.append(_latex_escaped(text[cursor:]))
    return "".join(rendered)


def _binding_label(binding: Mapping[str, object]) -> str:
    object_type = _clean_text(binding["object_type"])
    object_id = _clean_text(binding["object_id"])
    semantic = ":".join(object_id.split(":")[-2:])
    if len(semantic) > 34:
        semantic = semantic[:31] + "..."
    return f"{object_type} - {semantic} - {str(binding['fingerprint'])[:12]}"


def _report_evidence_bindings(
    content: ResearchReportContent,
) -> tuple[dict[str, str], ...]:
    unique: dict[tuple[str, str, str], dict[str, str]] = {}
    usages: dict[tuple[str, str, str], tuple[set[str], set[str]]] = {}

    def consume(
        binding: Mapping[str, object],
        *,
        section_id: str,
        surface: str,
    ) -> None:
        key = (
            str(binding["object_type"]),
            str(binding["object_id"]),
            str(binding["fingerprint"]),
        )
        unique[key] = {
            "object_type": key[0],
            "object_id": key[1],
            "fingerprint": key[2],
        }
        sections, surfaces = usages.setdefault(key, (set(), set()))
        sections.add(section_id)
        surfaces.add(surface)

    for section in content["sections"]:
        section_id = str(section["section_id"])
        for paragraph in section["paragraphs"]:
            for binding in paragraph["bindings"]:
                consume(binding, section_id=section_id, surface="narrative")
    for table in content["tables"]:
        for binding in table["bindings"]:
            consume(binding, section_id=str(table["section_id"]), surface="table")
    for chart in content["charts"]:
        for series in chart["series"]:
            for point in series["points"]:
                consume(
                    point["binding"],
                    section_id=str(chart["section_id"]),
                    surface="chart",
                )
    rows = []
    for key in sorted(unique):
        sections, surfaces = usages[key]
        rows.append(
            {
                **unique[key],
                "usage_sections": ", ".join(sorted(sections)),
                "usage_surfaces": ", ".join(sorted(surfaces)),
            }
        )
    return tuple(rows)


def _asset_directory() -> Path | None:
    packaged = Path(__file__).parent / "report_assets"
    if packaged.is_dir():
        return packaged
    repository = (
        Path(__file__).parents[2]
        / "plugins"
        / "owner-equity-research"
        / "skills"
        / "owner-equity-research"
        / "assets"
    )
    return repository if repository.is_dir() else None


def _read_bounded_regular_file(
    path: Path,
    *,
    limit: int,
    label: str,
    allow_empty: bool = False,
) -> bytes:
    absolute = Path(path).expanduser().absolute()
    # macOS exposes /tmp, /var, and /etc as fixed root-owned aliases into /private.
    # Normalize only that first platform component; all remaining components still
    # use the descriptor-based no-follow walk below.
    if sys.platform == "darwin" and len(absolute.parts) >= 2:
        root_alias = Path(absolute.anchor) / absolute.parts[1]
        expected_target = Path("/private") / absolute.parts[1]
        try:
            alias_details = root_alias.lstat()
            alias_target = root_alias.resolve(strict=True)
        except OSError:
            pass
        else:
            if (
                stat.S_ISLNK(alias_details.st_mode)
                and alias_details.st_uid == 0
                and alias_target == expected_target
                and alias_target.is_dir()
            ):
                absolute = alias_target.joinpath(*absolute.parts[2:])
    try:
        path_details = absolute.lstat()
    except OSError as exc:
        raise ResearchReportError(f"{label} is unavailable") from exc
    if stat.S_ISLNK(path_details.st_mode):
        raise ResearchReportError(f"{label} cannot be a symlink")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    # The installed wheel can live below an execute-only directory that permits
    # traversal but not listing.  Linux O_PATH keeps that normal traversal
    # behavior while O_DIRECTORY | O_NOFOLLOW still pins every ancestor to a
    # non-symlink directory.  Other platforms retain the portable O_RDONLY path.
    directory_flags = (
        getattr(os, "O_PATH", os.O_RDONLY)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    parent_descriptor = os.open("/", directory_flags)
    try:
        for part in absolute.parent.parts[1:]:
            next_descriptor = os.open(part, directory_flags, dir_fd=parent_descriptor)
            os.close(parent_descriptor)
            parent_descriptor = next_descriptor
        descriptor = os.open(absolute.name, flags, dir_fd=parent_descriptor)
    except OSError as exc:
        os.close(parent_descriptor)
        raise ResearchReportError(f"{label} is not no-follow readable") from exc
    os.close(parent_descriptor)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid not in {0, os.getuid()}
            or stat.S_IMODE(before.st_mode) & 0o022
            or before.st_size > limit
            or (before.st_size == 0 and not allow_empty)
        ):
            raise ResearchReportError(f"{label} is unsafe or exceeds its byte limit")
        chunks: list[bytes] = []
        consumed = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, limit - consumed + 1))
            if not chunk:
                break
            consumed += len(chunk)
            if consumed > limit:
                raise ResearchReportError(f"{label} exceeds its byte limit")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if consumed != before.st_size or (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_mode,
            before.st_uid,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_mode,
            after.st_uid,
        ):
            raise ResearchReportError(f"{label} changed while read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _asset_contents() -> tuple[str, dict[str, object]]:
    assets = _asset_directory()
    template = _DEFAULT_TEMPLATE
    font_manifest = dict(_DEFAULT_FONT_MANIFEST)
    if assets is not None:
        try:
            disk_template = _read_bounded_regular_file(
                assets / "report-template.tex",
                limit=REPORT_TEXT_MAX_BYTES,
                label="report template asset",
            ).decode("utf-8")
            disk_fonts = json.loads(
                _read_bounded_regular_file(
                    assets / "font-manifest.json",
                    limit=REPORT_TEXT_MAX_BYTES,
                    label="report font manifest asset",
                ).decode("utf-8")
            )
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ResearchReportError("report assets cannot be read") from exc
        if disk_template != _DEFAULT_TEMPLATE or disk_fonts != _DEFAULT_FONT_MANIFEST:
            raise ResearchReportError("report assets differ from the trusted clean-room defaults")
        template = disk_template
        font_manifest = disk_fonts
    return template, font_manifest


def _trusted_font_asset() -> tuple[str, bytes]:
    assets = _asset_directory()
    if assets is None:
        raise ResearchReportError("bundled Noto CJK report font is unavailable")
    font_manifest = _DEFAULT_FONT_MANIFEST["embedded_font_files"]
    if not isinstance(font_manifest, list) or len(font_manifest) != 1:
        raise ResearchReportError("trusted report font manifest is invalid")
    record = font_manifest[0]
    if not isinstance(record, dict):
        raise ResearchReportError("trusted report font receipt is invalid")
    name = str(record["path"])
    license_name = str(record["license_path"])
    try:
        font = _read_bounded_regular_file(
            assets / name,
            limit=REPORT_FONT_MAX_BYTES,
            label="trusted report font",
        )
        license_bytes = _read_bounded_regular_file(
            assets / license_name,
            limit=REPORT_LICENSE_MAX_BYTES,
            label="trusted report font license",
        )
    except ResearchReportError as exc:
        raise ResearchReportError("trusted report font assets cannot be read") from exc
    if (
        len(font) != record["size"]
        or _sha256(font) != record["sha256"]
        or _sha256(license_bytes) != record["license_sha256"]
    ):
        raise ResearchReportError("trusted report font or license bytes drifted")
    return name, font


@dataclass(frozen=True, slots=True)
class _TrustedExecutableSnapshot:
    source_path: str
    sha256: str
    size: int
    content: bytes


@dataclass(frozen=True, slots=True)
class _TrustedCacheEntry:
    relative_path: str
    is_directory: bool
    content: bytes


@dataclass(frozen=True, slots=True)
class _TrustedTectonicCacheSnapshot:
    source_path: str
    tree_sha256: str
    member_count: int
    total_bytes: int
    entries: tuple[_TrustedCacheEntry, ...]


@dataclass(frozen=True, slots=True)
class _TrustedDistributionEntry:
    relative_path: str
    content: bytes


@dataclass(frozen=True, slots=True)
class _TrustedDistributionSnapshot:
    distribution: str
    version: str
    tree_sha256: str
    member_count: int
    total_bytes: int
    entries: tuple[_TrustedDistributionEntry, ...]

    def identity(self) -> dict[str, object]:
        return {
            "distribution": self.distribution,
            "version": self.version,
            "tree_sha256": self.tree_sha256,
            "member_count": self.member_count,
            "total_bytes": self.total_bytes,
        }


def _trusted_executable(name: str) -> _TrustedExecutableSnapshot:
    located = shutil.which(name)
    if located is None:
        raise ResearchReportError(f"required report executable is unavailable: {name}")
    try:
        resolved = Path(located).resolve(strict=True)
    except OSError as exc:
        raise ResearchReportError(f"report executable cannot be resolved: {name}") from exc
    if not resolved.is_absolute():
        raise ResearchReportError("report executable path must be absolute")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(resolved, flags)
    except OSError as exc:
        raise ResearchReportError(f"report executable is not no-follow readable: {name}") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink < 1
            or before.st_uid not in {0, os.getuid()}
            or stat.S_IMODE(before.st_mode) & 0o022
            or not stat.S_IMODE(before.st_mode) & 0o111
            or before.st_size > REPORT_EXECUTABLE_MAX_BYTES
        ):
            raise ResearchReportError(f"report executable is unsafe: {name}")
        digest = hashlib.sha256()
        chunks: list[bytes] = []
        consumed = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            consumed += len(chunk)
            if consumed > REPORT_EXECUTABLE_MAX_BYTES:
                raise ResearchReportError(f"report executable exceeds its byte limit: {name}")
            digest.update(chunk)
            chunks.append(chunk)
        after = os.fstat(descriptor)
        identity = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_mode,
            before.st_uid,
        )
        if identity != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_mode,
            after.st_uid,
        ):
            raise ResearchReportError(f"report executable changed while hashed: {name}")
        return _TrustedExecutableSnapshot(
            source_path=str(resolved),
            sha256=digest.hexdigest(),
            size=consumed,
            content=b"".join(chunks),
        )
    finally:
        os.close(descriptor)


def _trusted_tectonic_cache() -> _TrustedTectonicCacheSnapshot:
    candidates = (
        Path.home() / "Library" / "Caches" / "Tectonic",
        Path.home() / ".cache" / "Tectonic",
        Path.home() / ".cache" / "tectonic",
    )
    root = next((item for item in candidates if item.is_dir()), None)
    if root is None:
        raise ResearchReportError("offline Tectonic cache is unavailable")
    root_details = root.lstat()
    if (
        not stat.S_ISDIR(root_details.st_mode)
        or root_details.st_uid not in {0, os.getuid()}
        or stat.S_IMODE(root_details.st_mode) & 0o022
    ):
        raise ResearchReportError("offline Tectonic cache root is unsafe")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    directory_flags = flags | getattr(os, "O_DIRECTORY", 0)
    try:
        root_descriptor = os.open(root, directory_flags)
    except OSError as exc:
        raise ResearchReportError("offline Tectonic cache is not no-follow readable") from exc
    digest = hashlib.sha256()
    entries: list[_TrustedCacheEntry] = []
    total = 0

    def walk(directory_fd: int, prefix: PurePosixPath) -> None:
        nonlocal total
        before = os.fstat(directory_fd)
        names = tuple(sorted(os.listdir(directory_fd)))
        for name in names:
            if type(name) is not str or name in {"", ".", ".."} or "/" in name or "\0" in name:
                raise ResearchReportError("Tectonic cache contains an unsafe member name")
            relative = (prefix / name).as_posix()
            try:
                details = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError as exc:
                raise ResearchReportError("Tectonic cache member cannot be inspected") from exc
            if len(entries) >= REPORT_TECTONIC_CACHE_MAX_MEMBERS:
                raise ResearchReportError("Tectonic cache exceeds its member limit")
            digest.update(relative.encode("utf-8"))
            digest.update(b"\0")
            if stat.S_ISDIR(details.st_mode):
                if details.st_uid not in {0, os.getuid()} or (
                    stat.S_IMODE(details.st_mode) & 0o022
                ):
                    raise ResearchReportError("Tectonic cache directory is unsafe")
                try:
                    child_fd = os.open(name, directory_flags, dir_fd=directory_fd)
                except OSError as exc:
                    raise ResearchReportError(
                        "Tectonic cache directory is not no-follow readable"
                    ) from exc
                entries.append(_TrustedCacheEntry(relative, True, b""))
                digest.update(b"directory\0")
                try:
                    walk(child_fd, PurePosixPath(relative))
                finally:
                    os.close(child_fd)
                continue
            if (
                not stat.S_ISREG(details.st_mode)
                or details.st_uid not in {0, os.getuid()}
                or stat.S_IMODE(details.st_mode) & 0o022
            ):
                raise ResearchReportError("Tectonic cache member is unsafe")
            try:
                descriptor = os.open(name, flags, dir_fd=directory_fd)
            except OSError as exc:
                raise ResearchReportError(
                    "Tectonic cache member is not no-follow readable"
                ) from exc
            try:
                first = os.fstat(descriptor)
                chunks: list[bytes] = []
                consumed = 0
                member_digest = hashlib.sha256()
                while True:
                    chunk = os.read(descriptor, 1024 * 1024)
                    if not chunk:
                        break
                    consumed += len(chunk)
                    total += len(chunk)
                    if total > REPORT_TECTONIC_CACHE_MAX_BYTES:
                        raise ResearchReportError("Tectonic cache exceeds its byte limit")
                    member_digest.update(chunk)
                    chunks.append(chunk)
                final = os.fstat(descriptor)
                identity = (
                    first.st_dev,
                    first.st_ino,
                    first.st_size,
                    first.st_mtime_ns,
                    first.st_mode,
                    first.st_uid,
                )
                if (
                    identity
                    != (
                        final.st_dev,
                        final.st_ino,
                        final.st_size,
                        final.st_mtime_ns,
                        final.st_mode,
                        final.st_uid,
                    )
                    or consumed != first.st_size
                ):
                    raise ResearchReportError("Tectonic cache changed while snapshotted")
                content = b"".join(chunks)
                entries.append(_TrustedCacheEntry(relative, False, content))
                digest.update(str(consumed).encode("ascii"))
                digest.update(b"\0")
                digest.update(member_digest.digest())
            finally:
                os.close(descriptor)
        after = os.fstat(directory_fd)
        if names != tuple(sorted(os.listdir(directory_fd))) or (
            before.st_dev,
            before.st_ino,
            before.st_mtime_ns,
            before.st_mode,
            before.st_uid,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_mtime_ns,
            after.st_mode,
            after.st_uid,
        ):
            raise ResearchReportError("Tectonic cache directory changed while snapshotted")

    try:
        walk(root_descriptor, PurePosixPath())
    finally:
        os.close(root_descriptor)
    return _TrustedTectonicCacheSnapshot(
        source_path=str(root.resolve(strict=True)),
        tree_sha256=digest.hexdigest(),
        member_count=len(entries),
        total_bytes=total,
        entries=tuple(entries),
    )


def _tectonic_cache_snapshot_for_authority(
    snapshot: _TrustedTectonicCacheSnapshot,
    expected: object,
) -> _TrustedTectonicCacheSnapshot:
    """Select the deterministic cache ordering recorded by an exact authority."""

    if not isinstance(expected, dict) or set(expected) != {
        "tree_sha256",
        "member_count",
        "total_bytes",
    }:
        return snapshot
    current_identity = {
        "tree_sha256": snapshot.tree_sha256,
        "member_count": snapshot.member_count,
        "total_bytes": snapshot.total_bytes,
    }
    if current_identity == expected:
        return snapshot
    entries = tuple(sorted(snapshot.entries, key=lambda item: item.relative_path))
    digest = hashlib.sha256()
    total = 0
    for entry in entries:
        digest.update(entry.relative_path.encode("utf-8"))
        digest.update(b"\0")
        if entry.is_directory:
            digest.update(b"directory\0")
            continue
        total += len(entry.content)
        digest.update(str(len(entry.content)).encode("ascii"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(entry.content).digest())
    candidate = _TrustedTectonicCacheSnapshot(
        source_path=snapshot.source_path,
        tree_sha256=digest.hexdigest(),
        member_count=len(entries),
        total_bytes=total,
        entries=entries,
    )
    candidate_identity = {
        "tree_sha256": candidate.tree_sha256,
        "member_count": candidate.member_count,
        "total_bytes": candidate.total_bytes,
    }
    return candidate if candidate_identity == expected else snapshot


def _write_private_snapshot(path: Path, content: bytes, *, mode: int) -> None:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags, mode)
    except OSError as exc:
        raise ResearchReportError("private toolchain snapshot cannot be created") from exc
    try:
        view = memoryview(content)
        written = 0
        while written < len(view):
            consumed = os.write(descriptor, view[written:])
            if consumed <= 0:
                raise ResearchReportError("private toolchain snapshot write was incomplete")
            written += consumed
        os.fsync(descriptor)
        os.fchmod(descriptor, mode)
        details = os.fstat(descriptor)
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_size != len(content)
            or stat.S_IMODE(details.st_mode) != mode
        ):
            raise ResearchReportError("private toolchain snapshot identity is invalid")
    finally:
        os.close(descriptor)


def _fsync_private_directory(path: Path) -> None:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _stage_report_toolchain(
    workspace: Path,
    executable: _TrustedExecutableSnapshot,
    cache: _TrustedTectonicCacheSnapshot,
) -> tuple[str, str]:
    workspace = workspace.resolve(strict=True)
    workspace_details = workspace.lstat()
    if (
        not stat.S_ISDIR(workspace_details.st_mode)
        or workspace_details.st_uid != os.getuid()
        or stat.S_IMODE(workspace_details.st_mode) & 0o077
    ):
        raise ResearchReportError("report workspace is not private")
    root = workspace / "trusted-toolchain"
    cache_root = root / "tectonic-cache"
    root.mkdir(mode=0o700)
    cache_root.mkdir(mode=0o700)
    executable_path = root / "tectonic"
    _write_private_snapshot(executable_path, executable.content, mode=0o500)
    directories: list[Path] = [cache_root]
    for entry in cache.entries:
        relative = PurePosixPath(entry.relative_path)
        if relative.is_absolute() or ".." in relative.parts or "." in relative.parts:
            raise ResearchReportError("toolchain cache snapshot path is unsafe")
        target = cache_root.joinpath(*relative.parts)
        if entry.is_directory:
            target.mkdir(mode=0o700)
            directories.append(target)
            continue
        if not target.parent.is_dir() or target.parent.is_symlink():
            raise ResearchReportError("toolchain cache snapshot parent is unsafe")
        _write_private_snapshot(target, entry.content, mode=0o400)
        if (
            _read_bounded_regular_file(
                target,
                limit=REPORT_TECTONIC_CACHE_MAX_BYTES,
                label="staged Tectonic cache member",
                allow_empty=True,
            )
            != entry.content
        ):
            raise ResearchReportError("staged Tectonic cache member differs from snapshot")
    if (
        _read_bounded_regular_file(
            executable_path,
            limit=REPORT_EXECUTABLE_MAX_BYTES,
            label="staged Tectonic executable",
        )
        != executable.content
    ):
        raise ResearchReportError("staged executable differs from its verified snapshot")
    for directory in sorted(directories, key=lambda item: len(item.parts), reverse=True):
        _fsync_private_directory(directory)
        directory.chmod(0o500)
    _fsync_private_directory(root)
    root.chmod(0o500)
    _fsync_private_directory(workspace)
    return str(executable_path), str(cache_root)


def _stage_pdf_qa_distributions(
    workspace: Path,
    snapshots: tuple[_TrustedDistributionSnapshot, ...],
) -> str:
    """Materialize only snapshotted dependency bytes for the isolated QA child."""

    if (
        type(snapshots) is not tuple
        or tuple(item.distribution for item in snapshots) != ("pypdf", "pypdfium2")
    ):
        raise ResearchReportError("PDF QA distribution snapshot set is not closed")
    root = workspace / "trusted-pdf-qa-site"
    root.mkdir(mode=0o700)
    directories: set[Path] = {root}
    seen: set[str] = set()
    for snapshot in snapshots:
        if snapshot.identity() != _distribution_identity_from_entries(snapshot):
            raise ResearchReportError("PDF QA distribution snapshot identity does not replay")
        for entry in snapshot.entries:
            relative = PurePosixPath(entry.relative_path)
            if (
                relative.is_absolute()
                or ".." in relative.parts
                or "." in relative.parts
                or entry.relative_path in seen
            ):
                raise ResearchReportError("PDF QA distribution snapshot path is unsafe")
            seen.add(entry.relative_path)
            target = root.joinpath(*relative.parts)
            parents: list[Path] = []
            parent = target.parent
            while parent != root and not parent.exists():
                parents.append(parent)
                parent = parent.parent
            if parent != root and (not parent.is_dir() or parent.is_symlink()):
                raise ResearchReportError("PDF QA distribution parent is unsafe")
            for directory in reversed(parents):
                directory.mkdir(mode=0o700)
                directories.add(directory)
            _write_private_snapshot(target, entry.content, mode=0o400)
            if (
                _read_bounded_regular_file(
                    target,
                    limit=REPORT_DISTRIBUTION_MAX_BYTES,
                    label="staged PDF QA distribution member",
                    allow_empty=True,
                )
                != entry.content
            ):
                raise ResearchReportError("staged PDF QA member differs from snapshot")
    for directory in sorted(directories, key=lambda item: len(item.parts), reverse=True):
        _fsync_private_directory(directory)
        directory.chmod(0o500)
    _fsync_private_directory(workspace)
    return str(root)


def _distribution_identity_from_entries(
    snapshot: _TrustedDistributionSnapshot,
) -> dict[str, object]:
    digest = hashlib.sha256()
    total = 0
    for entry in snapshot.entries:
        total += len(entry.content)
        digest.update(entry.relative_path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(len(entry.content)).encode("ascii"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(entry.content).digest())
    return {
        "distribution": snapshot.distribution,
        "version": snapshot.version,
        "tree_sha256": digest.hexdigest(),
        "member_count": len(snapshot.entries),
        "total_bytes": total,
    }


def _platform_target() -> str:
    operating_system = {"darwin": "macos"}.get(platform.system().lower(), platform.system().lower())
    machine = platform.machine().lower().replace("aarch64", "arm64").replace("x86_64", "x64")
    target = f"{operating_system}-{machine}"
    if re.fullmatch(r"[a-z0-9_-]+", target) is None:
        raise ResearchReportError("report platform target is invalid")
    return target


def _trusted_distribution_snapshot(
    distribution_name: str,
) -> _TrustedDistributionSnapshot:
    try:
        distribution = importlib.metadata.distribution(distribution_name)
    except importlib.metadata.PackageNotFoundError as exc:
        raise ResearchReportError(
            f"required PDF distribution is unavailable: {distribution_name}"
        ) from exc
    installer_generated = {
        "INSTALLER",
        "RECORD",
        "REQUESTED",
        "direct_url.json",
        "uv_cache.json",
    }
    files: list[tuple[object, str, int]] = []
    for item in distribution.files or ():
        relative = PurePosixPath(str(item))
        record_hash = getattr(item, "hash", None)
        record_size = getattr(item, "size", None)
        if (
            relative.name in installer_generated
            or "__pycache__" in relative.parts
            or relative.suffix == ".pyc"
            or ".." in relative.parts
            or record_hash is None
            or record_size is None
            or getattr(record_hash, "mode", None) != "sha256"
        ):
            continue
        record_sha256 = getattr(record_hash, "value", None)
        if (
            type(record_sha256) is not str
            or re.fullmatch(r"[A-Za-z0-9_-]{43}", record_sha256) is None
            or type(record_size) is not int
            or record_size < 0
        ):
            raise ResearchReportError("PDF distribution RECORD entry is invalid")
        files.append((item, record_sha256, record_size))
    files.sort(key=lambda item: str(item[0]))
    if not files or len(files) > REPORT_DISTRIBUTION_MAX_MEMBERS:
        raise ResearchReportError("PDF distribution member set is empty or oversized")
    digest = hashlib.sha256()
    total = 0
    entries: list[_TrustedDistributionEntry] = []
    for member, record_sha256, record_size in files:
        relative = PurePosixPath(str(member)).as_posix()
        if (
            PurePosixPath(relative).is_absolute()
            or ".." in PurePosixPath(relative).parts
            or not relative
        ):
            raise ResearchReportError("PDF distribution contains an unsafe member path")
        path = Path(distribution.locate_file(member)).absolute()
        try:
            if path.is_symlink() or not path.exists():
                raise ResearchReportError("PDF distribution member cannot be a symlink")
        except OSError as exc:
            raise ResearchReportError("PDF distribution member is unavailable") from exc
        content = _read_bounded_regular_file(
            path,
            limit=REPORT_DISTRIBUTION_MAX_BYTES - total,
            label=f"{distribution_name} distribution member",
            allow_empty=True,
        )
        if len(content) != record_size:
            raise ResearchReportError("PDF distribution member differs from RECORD size")
        content_record_sha256 = (
            base64.urlsafe_b64encode(hashlib.sha256(content).digest())
            .rstrip(b"=")
            .decode("ascii")
        )
        if content_record_sha256 != record_sha256:
            raise ResearchReportError("PDF distribution member differs from RECORD SHA-256")
        total += len(content)
        if total > REPORT_DISTRIBUTION_MAX_BYTES:
            raise ResearchReportError("PDF distribution exceeds its cumulative byte limit")
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(len(content)).encode("ascii"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(content).digest())
        entries.append(_TrustedDistributionEntry(relative, content))
    return _TrustedDistributionSnapshot(
        distribution=distribution_name,
        version=distribution.version,
        tree_sha256=digest.hexdigest(),
        member_count=len(files),
        total_bytes=total,
        entries=tuple(entries),
    )


def _distribution_tree_identity(distribution_name: str) -> dict[str, object]:
    return _trusted_distribution_snapshot(distribution_name).identity()


def build_report_toolchain_authority_registry(
    authorities: tuple[ReportToolchainAuthority, ...],
) -> ReportToolchainAuthorityRegistry:
    """Build the canonical closed registry without granting new runtime authority."""

    if type(authorities) is not tuple or any(
        type(item) is not ReportToolchainAuthority for item in authorities
    ):
        raise ResearchReportError("report toolchain registry requires exact authority entries")
    ordered = tuple(sorted(authorities, key=lambda item: str(item["platform_target"])))
    targets = tuple(str(item["platform_target"]) for item in ordered)
    if len(targets) != len(set(targets)) or any(
        target not in REPORT_TOOLCHAIN_REQUIRED_PLATFORMS for target in targets
    ):
        raise ResearchReportError("report toolchain registry entry set is invalid")
    missing = tuple(
        target for target in REPORT_TOOLCHAIN_REQUIRED_PLATFORMS if target not in set(targets)
    )
    identity: dict[str, object] = {
        "schema_version": "1.0.0",
        "artifact_type": "report-toolchain-authority-registry",
        "required_platform_targets": list(REPORT_TOOLCHAIN_REQUIRED_PLATFORMS),
        "authorities": [item.to_dict() for item in ordered],
        "missing_platform_targets": list(missing),
        "release_status": (
            "ready"
            if not missing and all(item["release_evidence_status"] == "ready" for item in ordered)
            else "blocked"
        ),
    }
    fingerprint = canonical_sha256(identity)
    return ReportToolchainAuthorityRegistry(
        {
            **identity,
            "registry_id": f"report-toolchain-authority-registry:{fingerprint[:24]}",
            "registry_fingerprint": fingerprint,
        }
    )


def _bootstrap_evidence_file(
    evidence_root: Path,
    relative_path: object,
    *,
    label: str,
    limit: int,
) -> tuple[str, bytes]:
    if type(relative_path) is not str:
        raise ResearchReportError(f"{label} path must be a relative string")
    _validate_relative_path(relative_path)
    return (
        relative_path,
        _read_bounded_regular_file(
            evidence_root / PurePosixPath(relative_path),
            limit=limit,
            label=label,
        ),
    )


def bootstrap_report_toolchain_authority_entry(
    *,
    platform_target: str,
    evidence_root: Path,
    components: Mapping[str, object],
) -> dict[str, Any]:
    """Read-only audit of one exact platform toolchain and its provenance files."""

    if platform_target != _platform_target() or platform_target not in (
        REPORT_TOOLCHAIN_REQUIRED_PLATFORMS
    ):
        raise ResearchReportError("bootstrap target differs from the running platform")
    root = Path(evidence_root).expanduser().absolute()
    try:
        details = root.lstat()
    except OSError as exc:
        raise ResearchReportError("toolchain bootstrap evidence root is unavailable") from exc
    if (
        not stat.S_ISDIR(details.st_mode)
        or stat.S_ISLNK(details.st_mode)
        or details.st_uid not in {0, os.getuid()}
        or stat.S_IMODE(details.st_mode) & 0o022
    ):
        raise ResearchReportError("toolchain bootstrap evidence root is unsafe")
    expected_names = {
        "renderer",
        "offline_bundle",
        "pdf_text_backend",
        "pdf_render_backend",
    }
    if not isinstance(components, Mapping) or set(components) != expected_names:
        raise ResearchReportError("toolchain bootstrap component set is not closed")

    executable = _trusted_executable("tectonic")
    cache = _trusted_tectonic_cache()
    with tempfile.TemporaryDirectory(prefix="owner-report-toolchain-audit-") as temporary:
        workspace = Path(temporary).resolve(strict=True)
        workspace.chmod(0o700)
        executable_path, cache_path = _stage_report_toolchain(workspace, executable, cache)
        try:
            version_result = _run_private_subprocess(
                [executable_path, "--version"],
                check=True,
                capture_output=True,
                text=True,
                timeout=30,
                env=_closed_renderer_environment(
                    workspace,
                    executable_path,
                    tectonic_cache=cache_path,
                ),
            )
        except (OSError, subprocess.SubprocessError, UnicodeError) as exc:
            raise ResearchReportError("toolchain bootstrap renderer version audit failed") from exc
    renderer_version = version_result.stdout.strip().splitlines()[0]
    technical: dict[str, dict[str, object]] = {
        "renderer": {
            "engine": "tectonic",
            "basename": "tectonic",
            "sha256": executable.sha256,
            "size": executable.size,
            "version": renderer_version,
        },
        "offline_bundle": {
            "tree_sha256": cache.tree_sha256,
            "member_count": cache.member_count,
            "total_bytes": cache.total_bytes,
        },
        "pdf_text_backend": _distribution_tree_identity("pypdf"),
        "pdf_render_backend": _distribution_tree_identity("pypdfium2"),
    }
    supply_components: dict[str, object] = {}
    expected_input_fields = {
        "download_url",
        "download_artifact_path",
        "source_url",
        "source_artifact_path",
        "license_inventory",
        "sbom_path",
        "derivation_manifest_path",
    }
    for component_name in sorted(expected_names):
        source = components[component_name]
        if not isinstance(source, Mapping) or set(source) != expected_input_fields:
            raise ResearchReportError(
                f"toolchain bootstrap evidence for {component_name} is not closed"
            )
        download_url = source["download_url"]
        source_url = source["source_url"]
        if type(download_url) is not str or type(source_url) is not str:
            raise ResearchReportError("toolchain bootstrap URLs must be strings")
        _validate_https_supply_url(download_url)
        _validate_https_supply_url(source_url)
        download_path, download = _bootstrap_evidence_file(
            root,
            source["download_artifact_path"],
            label=f"{component_name} download artifact",
            limit=REPORT_SUPPLY_ARTIFACT_MAX_BYTES,
        )
        source_path, source_bytes = _bootstrap_evidence_file(
            root,
            source["source_artifact_path"],
            label=f"{component_name} source artifact",
            limit=REPORT_SUPPLY_ARTIFACT_MAX_BYTES,
        )
        license_inventory = source["license_inventory"]
        if (
            not isinstance(license_inventory, list)
            or not license_inventory
            or len(license_inventory) > 512
        ):
            raise ResearchReportError("toolchain bootstrap license inventory is invalid")
        license_evidence: list[dict[str, str]] = []
        seen_license_scopes: set[str] = set()
        for index, license_item in enumerate(license_inventory):
            if not isinstance(license_item, Mapping) or set(license_item) != {
                "component_scope",
                "spdx_license_id",
                "license_path",
            }:
                raise ResearchReportError("toolchain bootstrap license entry is not closed")
            component_scope = license_item["component_scope"]
            spdx = license_item["spdx_license_id"]
            if (
                type(component_scope) is not str
                or re.fullmatch(r"[a-z0-9][a-z0-9._/-]{0,255}", component_scope) is None
                or component_scope in seen_license_scopes
                or type(spdx) is not str
                or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+-]{0,127}", spdx) is None
            ):
                raise ResearchReportError("toolchain bootstrap license entry is invalid")
            seen_license_scopes.add(component_scope)
            license_path, license_bytes = _bootstrap_evidence_file(
                root,
                license_item["license_path"],
                label=f"{component_name} license {index + 1}",
                limit=REPORT_LICENSE_MAX_BYTES,
            )
            license_evidence.append(
                {
                    "component_scope": component_scope,
                    "spdx_license_id": spdx,
                    "license_path": license_path,
                    "license_sha256": _sha256(license_bytes),
                }
            )
        sbom_path, sbom_bytes = _bootstrap_evidence_file(
            root,
            source["sbom_path"],
            label=f"{component_name} SBOM",
            limit=REPORT_TEXT_MAX_BYTES,
        )
        derivation_path, derivation_bytes = _bootstrap_evidence_file(
            root,
            source["derivation_manifest_path"],
            label=f"{component_name} derivation manifest",
            limit=REPORT_TEXT_MAX_BYTES,
        )
        supply_components[component_name] = {
            "component_name": component_name,
            "runtime_identity_sha256": canonical_sha256(technical[component_name]),
            "download_url": download_url,
            "download_sha256": _sha256(download),
            "source_url": source_url,
            "source_sha256": _sha256(source_bytes),
            "license_inventory": sorted(
                license_evidence,
                key=lambda item: item["component_scope"],
            ),
            "sbom_path": sbom_path,
            "sbom_sha256": _sha256(sbom_bytes),
            "derivation_manifest_path": derivation_path,
            "derivation_manifest_sha256": _sha256(derivation_bytes),
        }
        _ = (download_path, source_path)
    identity: dict[str, object] = {
        "schema_version": "1.0.0",
        "artifact_type": "report-toolchain-authority-entry",
        "platform_target": platform_target,
        "release_evidence_status": "ready",
        **technical,
        "supply_chain": {
            "status": "ready",
            "components": supply_components,
            "missing_evidence_codes": [],
        },
    }
    fingerprint = canonical_sha256(identity)
    payload = {
        **identity,
        "authority_id": (
            f"report-toolchain-authority:{platform_target}:{fingerprint[:24]}"
        ),
        "authority_fingerprint": fingerprint,
    }
    return ReportToolchainAuthority.from_dict(payload).to_dict()


def bootstrap_report_toolchain_authority_entry_from_manifest(path: Path) -> dict[str, Any]:
    """Audit a canonical bootstrap manifest without writing to the source tree."""

    content = _read_bounded_regular_file(
        Path(path),
        limit=REPORT_TEXT_MAX_BYTES,
        label="report toolchain bootstrap manifest",
    )
    try:
        payload = json.loads(content.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ResearchReportError("report toolchain bootstrap manifest is invalid JSON") from exc
    if not isinstance(payload, dict) or content != _canonical_file(payload):
        raise ResearchReportError("report toolchain bootstrap manifest is not canonical JSON")
    if set(payload) != {
        "schema_version",
        "artifact_type",
        "platform_target",
        "evidence_root",
        "components",
    } or payload["schema_version"] != "1.0.0" or payload["artifact_type"] != (
        "report-toolchain-bootstrap-input"
    ):
        raise ResearchReportError("report toolchain bootstrap manifest contract is invalid")
    evidence_root = payload["evidence_root"]
    if type(evidence_root) is not str or not Path(evidence_root).is_absolute():
        raise ResearchReportError("toolchain bootstrap evidence root must be absolute")
    return bootstrap_report_toolchain_authority_entry(
        platform_target=str(payload["platform_target"]),
        evidence_root=Path(evidence_root),
        components=payload["components"],
    )


def load_report_toolchain_authority_registry() -> ReportToolchainAuthorityRegistry:
    path = Path(__file__).parent / "resources" / "report" / "report-toolchain-authority-v1.json"
    try:
        content = _read_bounded_regular_file(
            path,
            limit=REPORT_TEXT_MAX_BYTES,
            label="report toolchain authority",
        )
        payload = json.loads(content.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ResearchReportError("report toolchain authority is invalid JSON") from exc
    if not isinstance(payload, dict) or content != _canonical_file(payload):
        raise ResearchReportError("report toolchain authority is not canonical JSON")
    return ReportToolchainAuthorityRegistry.from_dict(payload)


def load_report_toolchain_authority() -> ReportToolchainAuthority:
    return load_report_toolchain_authority_registry().for_platform(_platform_target())


def replay_report_pdf_qa(
    pdf_bytes: bytes,
    *,
    authority: ReportToolchainAuthority | None = None,
) -> PdfQaReplayResult:
    """Recompute PDF text and visual evidence from bytes in an isolated process."""

    if type(pdf_bytes) is not bytes or not 1 <= len(pdf_bytes) <= REPORT_PDF_MAX_BYTES:
        raise ResearchReportError("PDF QA input is empty or exceeds its byte limit")
    packaged_authority = load_report_toolchain_authority()
    selected = packaged_authority if authority is None else authority
    if type(selected) is not ReportToolchainAuthority or (
        selected.to_dict() != packaged_authority.to_dict()
    ):
        raise ResearchReportError("PDF QA authority differs from the packaged authority")
    snapshots = (
        _trusted_distribution_snapshot("pypdf"),
        _trusted_distribution_snapshot("pypdfium2"),
    )
    expected_identities = (
        to_json_value(selected["pdf_text_backend"]),
        to_json_value(selected["pdf_render_backend"]),
    )
    if tuple(item.identity() for item in snapshots) != expected_identities:
        raise ResearchReportError("PDF QA distributions differ from trusted authority")
    with tempfile.TemporaryDirectory(prefix="owner-report-pdf-qa-") as temporary:
        workspace = Path(temporary).resolve(strict=True)
        workspace.chmod(0o700)
        site_root = _stage_pdf_qa_distributions(workspace, snapshots)
        pdf_path = workspace / "report.pdf"
        result_path = workspace / "qa-result.json"
        _write_private_snapshot(pdf_path, pdf_bytes, mode=0o400)
        environment = {
            "PATH": os.pathsep.join(
                sorted(
                    {
                        str(Path(sys.executable).resolve(strict=True).parent),
                        "/usr/bin",
                        "/bin",
                        "/usr/sbin",
                        "/sbin",
                    }
                )
            ),
            "HOME": str(workspace),
            "TMPDIR": str(workspace),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PYTHONHASHSEED": "0",
            "TZ": "UTC",
        }
        completed = _run_private_subprocess(
            [
                sys.executable,
                "-I",
                "-S",
                "-c",
                _PDF_QA_CHILD,
                site_root,
                str(pdf_path),
                str(result_path),
                str(REPORT_PDF_MAX_BYTES),
                str(REPORT_TEXT_MAX_BYTES),
            ],
            cwd=workspace,
            env=environment,
            check=False,
            capture_output=True,
            timeout=180,
        )
        if completed.returncode != 0:
            diagnostic = (completed.stdout + completed.stderr)[-32768:]
            raise ResearchReportError(
                "isolated PDF QA failed "
                f"(exit={completed.returncode}, diagnostic_sha256={_sha256(diagnostic)})"
            )
        try:
            raw_result = _read_bounded_regular_file(
                result_path,
                limit=REPORT_TEXT_MAX_BYTES * 2,
                label="isolated PDF QA result",
            )
            payload = json.loads(raw_result.decode("utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ResearchReportError("isolated PDF QA returned invalid JSON") from exc
        if not isinstance(payload, dict) or raw_result != _canonical_file(payload):
            raise ResearchReportError("isolated PDF QA result is not canonical JSON")
    if set(payload) != {
        "page_count",
        "extracted_text",
        "page_text_character_counts",
        "rendered_page_sha256",
        "page_non_white_ratios",
        "versions",
    }:
        raise ResearchReportError("isolated PDF QA result has an open field set")
    page_count = payload["page_count"]
    extracted_text = payload["extracted_text"]
    counts = payload["page_text_character_counts"]
    hashes = payload["rendered_page_sha256"]
    ratios = payload["page_non_white_ratios"]
    versions = payload["versions"]
    if (
        type(page_count) is not int
        or not 1 <= page_count <= REPORT_MAX_PAGES
        or type(extracted_text) is not str
        or len(extracted_text.encode("utf-8")) > REPORT_TEXT_MAX_BYTES
        or not isinstance(counts, list)
        or len(counts) != page_count
        or any(type(item) is not int or item < 0 for item in counts)
        or not isinstance(hashes, list)
        or len(hashes) != page_count
        or any(
            type(item) is not str or re.fullmatch(r"[a-f0-9]{64}", item) is None
            for item in hashes
        )
        or not isinstance(ratios, list)
        or len(ratios) != page_count
        or any(
            type(item) is not str
            or re.fullmatch(r"(?:0\.[0-9]{6}|1\.000000)", item) is None
            for item in ratios
        )
        or not isinstance(versions, dict)
        or set(versions) != {"pypdf", "pypdfium2"}
        or versions.get("pypdf") != snapshots[0].version
        or versions.get("pypdfium2") != snapshots[1].version
    ):
        raise ResearchReportError("isolated PDF QA result is malformed")
    return PdfQaReplayResult(
        page_count=page_count,
        extracted_text=extracted_text,
        page_text_character_counts=tuple(counts),
        rendered_page_sha256=tuple(hashes),
        page_non_white_ratios=tuple(ratios),
        backend_versions=freeze(versions),
    )


def _closed_renderer_environment(
    workspace: Path,
    executable: str,
    *,
    tectonic_cache: str | None = None,
) -> dict[str, str]:
    search_directories = {
        str(Path(executable).parent),
        "/usr/bin",
        "/bin",
        "/usr/sbin",
        "/sbin",
    }
    environment = {
        "PATH": os.pathsep.join(sorted(search_directories)),
        "HOME": str(workspace),
        "TMPDIR": str(workspace),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "SOURCE_DATE_EPOCH": "946684800",
        "TZ": "UTC",
        "openin_any": "p",
        "openout_any": "p",
        "shell_escape": "0",
    }
    if tectonic_cache is not None:
        environment["TECTONIC_CACHE_DIR"] = tectonic_cache
    return environment


def _run_private_subprocess(
    *popenargs: Any,
    **kwargs: Any,
) -> subprocess.CompletedProcess[Any]:
    if "umask" in kwargs:
        raise ResearchReportError("report subprocess umask is fixed")
    return subprocess.run(*popenargs, umask=0o077, **kwargs)


def _verify_research(result: ResearchBundleBuildResult) -> None:
    if type(result) is not ResearchBundleBuildResult:
        raise ResearchReportError("report requires an exact ResearchBundleBuildResult")
    bundle = result.bundle
    manifest = result.run_manifest
    if (
        bundle.bundle_fingerprint != bundle_payload_sha256(bundle.to_dict())
        or bundle.run_id != manifest.run_id
        or bundle.issuer_id != manifest.issuer_id
        or bundle.data_cutoff_date != manifest.data_cutoff_date
        or bundle.component_lock_sha256 != manifest.component_lock_sha256
        or manifest.output_artifact_hashes.get("research-bundle.json") != bundle.bundle_fingerprint
    ):
        raise ResearchReportError("research bundle and run manifest do not replay")


def _verify_inputs(
    profile: str,
    research: ReloadedResearchInput,
    valuation: ReloadedValuationInput | None,
    report_spec: ReportSpec,
    research_source_index: ResearchSourceIndex | None,
    research_source_manifest: ResearchSourceIndexPublicationManifest | None,
    legacy_scores: tuple[Score, ...],
    futu_session_evidence: FutuSessionEvidence | None,
    futu_session_manifest: FutuSessionPublicationManifest | None,
    futu_market_execution_evidence: FutuMarketExecutionEvidence | None,
    futu_peer_evidence_set: FutuPeerEvidenceSet | None,
    futu_partial_session_manifest: FutuPartialSessionPublicationManifest | None,
    futu_optional_data_dispositions: tuple[FutuOptionalDataDisposition, ...],
    futu_optional_data_disposition_manifests: tuple[
        FutuOptionalDataDispositionPublicationManifest, ...
    ],
    futu_verifier: SignatureVerifier | None,
    forward_reoi: ForwardReOIValuationResult | None,
    comparable_valuation: ComparableValuationResult | None,
    composite_valuation: CompositeValuationResult | None,
    score_v2: tuple[ScoreV2, ...],
    owner_scorecard: OwnerScorecard | None,
    market_expectations: MarketExpectationsComparison | None,
    market_expectations_manifest: MarketExpectationsPublicationManifest | None,
    runtime_gap: RuntimeGapReceipt | None,
    runtime_gap_manifest: RuntimeGapPublicationManifest | None,
) -> None:
    if profile not in REPORT_PROFILES:
        raise ResearchReportError("profile must be research_only or full_valuation")
    if type(research) is not ReloadedResearchInput:
        raise ResearchReportError("report requires a strictly reloaded research input")
    _verify_research(research.result)
    if type(report_spec) is not ReportSpec:
        raise ResearchReportError("report specification must be an exact ReportSpec")
    if report_spec.language != "zh-CN" or "latex_pdf" not in report_spec.output_formats:
        raise ResearchReportError("report specification must request zh-CN latex_pdf output")
    if not report_spec.partial_and_blocked_states_required:
        raise ResearchReportError("report must disclose partial and blocked states")
    bundle = research.result.bundle
    if type(research_source_manifest) is not ResearchSourceIndexPublicationManifest:
        raise ResearchReportError("report requires an exact source-index publication manifest")
    try:
        reloaded_source_manifest = ResearchSourceIndexPublicationManifest.from_dict(
            research_source_manifest.to_dict()
        )
        if research_source_index is not None:
            if type(research_source_index) is not ResearchSourceIndex:
                raise ResearchReportError("report source index has the wrong exact type")
            expected_source_manifest = build_research_source_index_publication_manifest(
                research_source_index
            )
            if (
                research_source_index.research != research.result
                or expected_source_manifest.to_dict() != research_source_manifest.to_dict()
            ):
                raise ResearchReportError("source index is rebound from the research input")
    except OwnerEquityTypeError as exc:
        raise ResearchReportError("source index does not replay") from exc
    source_payload = reloaded_source_manifest.to_dict()
    if (
        source_payload["issuer_id"] != bundle.issuer_id
        or source_payload["data_cutoff_date"] != bundle.data_cutoff_date
        or source_payload["research_bundle_id"] != bundle.bundle_id
        or source_payload["research_bundle_fingerprint"] != bundle.bundle_fingerprint
    ):
        raise ResearchReportError("source index identity differs from the research bundle")
    if profile == "research_only":
        if valuation is not None:
            raise ResearchReportError("research_only forbids valuation input")
        if (
            any(
                value is not None
                for value in (
                    forward_reoi,
                    comparable_valuation,
                    composite_valuation,
                    owner_scorecard,
                    futu_session_evidence,
                    futu_session_manifest,
                    futu_market_execution_evidence,
                    futu_peer_evidence_set,
                    futu_partial_session_manifest,
                    market_expectations,
                    market_expectations_manifest,
                    runtime_gap,
                    runtime_gap_manifest,
                )
            )
            or score_v2
            or futu_optional_data_dispositions
            or futu_optional_data_disposition_manifests
        ):
            raise ResearchReportError(
                "research_only forbids market-derived valuation and Score 2.0 inputs"
            )
        if any(type(score) is not Score for score in legacy_scores):
            raise ResearchReportError("research_only legacy scores must use the exact Score type")
        if any(score.issuer_id != bundle.issuer_id for score in legacy_scores):
            raise ResearchReportError("legacy score issuer differs from the research bundle")
        if len({score.score_id for score in legacy_scores}) != len(legacy_scores):
            raise ResearchReportError("legacy score IDs must be unique")
    if profile == "full_valuation":
        if legacy_scores:
            raise ResearchReportError("full_valuation forbids legacy Score v1 inputs")
        if type(valuation) is not ReloadedValuationInput:
            raise ResearchReportError("full_valuation requires a strictly reloaded archive")
        archive = valuation.archive
        if (
            archive.manifest["issuer_id"] != bundle.issuer_id
            or archive.manifest["data_cutoff_date"] != bundle.data_cutoff_date
            or archive.manifest["component_lock_sha256"] != bundle.component_lock_sha256
        ):
            raise ResearchReportError("valuation archive identity differs from research input")
        if forward_reoi is not None and type(forward_reoi) is not ForwardReOIValuationResult:
            raise ResearchReportError("full_valuation forward ReOI result has the wrong exact type")
        if (
            comparable_valuation is not None
            and type(comparable_valuation) is not ComparableValuationResult
        ):
            raise ResearchReportError("full_valuation comparable result has the wrong exact type")
        if type(composite_valuation) is not CompositeValuationResult:
            raise ResearchReportError("full_valuation requires an exact composite result")
        if len(score_v2) != 4 or any(type(item) is not ScoreV2 for item in score_v2):
            raise ResearchReportError("full_valuation requires exactly four exact ScoreV2 results")
        if type(owner_scorecard) is not OwnerScorecard:
            raise ResearchReportError("full_valuation requires an exact OwnerScorecard")
        if {item.lens for item in score_v2} != {
            "graham",
            "buffett",
            "munger",
            "duan_yongping",
        }:
            raise ResearchReportError("full_valuation ScoreV2 lens set is not closed")
        if len({item.score_id for item in score_v2}) != 4:
            raise ResearchReportError("full_valuation ScoreV2 IDs must be unique")
        if (
            (
                futu_optional_data_dispositions
                and tuple(item.protocol_id for item in futu_optional_data_dispositions)
                != (3235, 3244, 3245, 3246)
            )
            or tuple(
                item.to_dict()["protocol_id"]
                for item in futu_optional_data_disposition_manifests
            )
            != (3235, 3244, 3245, 3246)
        ):
            raise ResearchReportError(
                "full_valuation requires four exact optional Futu dispositions"
            )
        if futu_optional_data_dispositions:
            try:
                expected_optional_manifests = (
                    build_futu_optional_data_disposition_publication_manifests(
                        futu_optional_data_dispositions
                    )
                )
            except (KeyError, OSError, TypeError, ValueError, OwnerEquityTypeError) as exc:
                raise ResearchReportError("optional Futu dispositions do not replay") from exc
            if tuple(item.to_dict() for item in expected_optional_manifests) != tuple(
                item.to_dict() for item in futu_optional_data_disposition_manifests
            ):
                raise ResearchReportError(
                    "optional Futu dispositions were rebound on publication"
                )
        try:
            if forward_reoi is not None:
                forward_reoi.__post_init__()
            if comparable_valuation is not None:
                comparable_valuation.__post_init__()
            composite_valuation.__post_init__()
            for item in score_v2:
                item.__post_init__()
            owner_scorecard.__post_init__()
        except (KeyError, OSError, TypeError, ValueError) as exc:
            raise ResearchReportError(
                "full_valuation downstream valuation chain does not replay"
            ) from exc
        retained_run = composite_valuation._run_result
        if (
            composite_valuation._forward_authority != forward_reoi
            or composite_valuation._comparable_authority != comparable_valuation
            or retained_run.archive.fingerprint != archive.fingerprint
            or retained_run.archive.file_sha256 != archive.file_sha256
        ):
            raise ResearchReportError(
                "composite valuation is rebound from the strict archive or panel results"
            )
        for panel in (forward_reoi, comparable_valuation):
            if panel is not None and (
                panel._run_result != retained_run
                or panel._basis_authority != composite_valuation._basis_authority
            ):
                raise ResearchReportError("valuation panel is rebound from the strict archive")
        if (
            composite_valuation.issuer_id != bundle.issuer_id
            or any(item.issuer_id != bundle.issuer_id for item in score_v2)
            or any(
                item.research_bundle_fingerprint != bundle.bundle_fingerprint for item in score_v2
            )
        ):
            raise ResearchReportError("valuation or ScoreV2 identity differs from research")
        valuation_before = composite_valuation.to_dict()
        valuation_fingerprint = composite_valuation.fingerprint
        try:
            replayed_scorecard = build_owner_scorecard(
                composite_valuation=composite_valuation,
                lens_scores=score_v2,
            )
        except (KeyError, TypeError, ValueError, OwnerScorecardError) as exc:
            raise ResearchReportError("OwnerScorecard inputs do not replay") from exc
        if (
            replayed_scorecard.to_dict() != owner_scorecard.to_dict()
            or owner_scorecard.research_bundle_fingerprint != bundle.bundle_fingerprint
            or owner_scorecard.composite_valuation_fingerprint != valuation_fingerprint
            or composite_valuation.to_dict() != valuation_before
            or composite_valuation.fingerprint != valuation_fingerprint
        ):
            raise ResearchReportError(
                "OwnerScorecard is rebound or changes the composite valuation"
            )
        if composite_valuation.status == "complete":
            if (
                forward_reoi is None
                or comparable_valuation is None
                or type(futu_session_manifest) is not FutuSessionPublicationManifest
                or futu_partial_session_manifest is not None
                or runtime_gap is not None
                or runtime_gap_manifest is not None
                or type(market_expectations_manifest) is not MarketExpectationsPublicationManifest
            ):
                raise ResearchReportError(
                    "complete full_valuation lacks its exact post-context chain"
                )
            if (
                futu_session_evidence is not None
                and type(futu_session_evidence) is not FutuSessionEvidence
            ):
                raise ResearchReportError("full_valuation Futu session has the wrong exact type")
            try:
                validate_futu_session_publication_manifest(
                    futu_session_manifest,
                    source_session=futu_session_evidence,
                    verifier=futu_verifier,
                )
                replayed_market_manifest = MarketExpectationsPublicationManifest.from_dict(
                    market_expectations_manifest.to_dict()
                )
                if market_expectations is not None:
                    if type(market_expectations) is not MarketExpectationsComparison:
                        raise ResearchReportError(
                            "full_valuation market expectations have the wrong exact type"
                        )
                    expected_market_manifest = build_market_expectations_publication_manifest(
                        market_expectations,
                        futu_session_manifest=futu_session_manifest,
                    )
                    if (
                        market_expectations.session != futu_session_evidence
                        or market_expectations.composite_valuation != composite_valuation
                        or market_expectations.owner_scorecard != owner_scorecard
                        or expected_market_manifest.to_dict()
                        != market_expectations_manifest.to_dict()
                    ):
                        raise ResearchReportError(
                            "market expectations are rebound from frozen conclusions"
                        )
            except (FutuSessionEvidenceError, OwnerEquityTypeError) as exc:
                raise ResearchReportError("complete Futu post-context does not replay") from exc
            market_payload = replayed_market_manifest.to_dict()
            if (
                futu_session_manifest.issuer_id != bundle.issuer_id
                or (
                    futu_session_evidence is not None
                    and futu_session_evidence.issuer_id != bundle.issuer_id
                )
                or market_payload["issuer_id"] != bundle.issuer_id
                or market_payload["futu_session_id"] != futu_session_manifest.session_id
                or market_payload["futu_session_fingerprint"]
                != futu_session_manifest.session_fingerprint
                or market_payload["composite_valuation_fingerprint"]
                != composite_valuation.fingerprint
                or market_payload["owner_scorecard_fingerprint"] != owner_scorecard.fingerprint
            ):
                raise ResearchReportError("market expectations change frozen conclusion identity")
        elif composite_valuation.status in {"blocked", "contested"}:
            if (
                futu_session_evidence is not None
                or futu_session_manifest is not None
                or market_expectations is not None
                or market_expectations_manifest is not None
                or type(futu_partial_session_manifest) is not FutuPartialSessionPublicationManifest
                or type(runtime_gap_manifest) is not RuntimeGapPublicationManifest
            ):
                raise ResearchReportError(
                    "ineligible full_valuation must use a typed no-post-context gap"
                )
            live_partial = (
                futu_market_execution_evidence,
                futu_peer_evidence_set,
                runtime_gap,
            )
            if any(item is not None for item in live_partial) and any(
                item is None for item in live_partial
            ):
                raise ResearchReportError("partial Futu live authority chain is incomplete")
            try:
                validate_futu_partial_session_publication_manifest(
                    futu_partial_session_manifest,
                    market_execution_evidence=futu_market_execution_evidence,
                    peer_evidence_set=futu_peer_evidence_set,
                    attested_finalization=(
                        None if runtime_gap is None else runtime_gap.attested_finalization
                    ),
                    verifier=futu_verifier,
                )
                reloaded_gap = RuntimeGapPublicationManifest.from_dict(
                    runtime_gap_manifest.to_dict()
                )
                if runtime_gap is not None:
                    runtime_gap.__post_init__()
                    expected_gap = build_runtime_gap_publication_manifest(runtime_gap)
                    if (
                        runtime_gap.composite_valuation != composite_valuation
                        or runtime_gap.owner_scorecard != owner_scorecard
                        or expected_gap.to_dict() != runtime_gap_manifest.to_dict()
                    ):
                        raise ResearchReportError("runtime gap rebinds frozen conclusions")
            except (FutuSessionEvidenceError, OwnerEquityTypeError) as exc:
                raise ResearchReportError("partial Futu authority does not replay") from exc
            gap_payload = reloaded_gap.to_dict()
            if (
                futu_partial_session_manifest.issuer_id != bundle.issuer_id
                or gap_payload["issuer_id"] != bundle.issuer_id
                or gap_payload["upstream_fingerprints"]["composite_valuation"]
                != composite_valuation.fingerprint
                or gap_payload["upstream_fingerprints"]["owner_scorecard"]
                != owner_scorecard.fingerprint
                or gap_payload["upstream_fingerprints"]["sidecar_finalization"]
                != futu_partial_session_manifest.attested_finalization_fingerprint
            ):
                raise ResearchReportError("runtime gap changes partial-session identity")
            if comparable_valuation is not None and futu_peer_evidence_set is not None:
                peer_authority = comparable_valuation._input_authority._peer_authority
                if peer_authority.futu_peer_evidence_set != futu_peer_evidence_set:
                    raise ResearchReportError(
                        "comparable valuation rebinds the exact Futu peer evidence"
                    )
        else:
            raise ResearchReportError("full_valuation composite status is not closed")
        context_manifest = futu_session_manifest or futu_partial_session_manifest
        if context_manifest is None:
            raise ResearchReportError("optional Futu dispositions lack session context")
        context_payload = context_manifest.to_dict()
        execution_bundle = context_payload["execution_bundles"][0]
        optional_payloads = tuple(
            item.to_dict() for item in futu_optional_data_disposition_manifests
        )
        source_execution = (
            futu_session_evidence.executions[0]
            if futu_session_evidence is not None
            else futu_market_execution_evidence.executions[0]
            if futu_market_execution_evidence is not None
            else None
        )
        if (
            any(item["issuer_id"] != bundle.issuer_id for item in optional_payloads)
            or any(
                item["data_cutoff_date"] != bundle.data_cutoff_date
                for item in optional_payloads
            )
            or any(item["execution_bundle"] != execution_bundle for item in optional_payloads)
            or len({item["review_authority"]["fingerprint"] for item in optional_payloads}) != 1
            or (
                futu_optional_data_dispositions
                and (
                    source_execution is None
                    or any(
                        item.execution != source_execution
                        for item in futu_optional_data_dispositions
                    )
                    or len(
                        {
                            item.review_authority.fingerprint
                            for item in futu_optional_data_dispositions
                        }
                    )
                    != 1
                )
            )
        ):
            raise ResearchReportError(
                "optional Futu dispositions rebind issuer, pre-price execution, or review"
            )


def _validate_report_content_semantics(payload: Mapping[str, Any]) -> None:
    profile = payload["profile"]
    sections = payload["sections"]
    tables = payload["tables"]
    charts = payload["charts"]
    required = {item[0] for item in _BASE_REPORT_SECTIONS}
    if profile == "full_valuation":
        required.update(item[0] for item in _FULL_REPORT_SECTIONS)
    section_ids = [str(item["section_id"]) for item in sections]
    if len(section_ids) != len(set(section_ids)) or not required.issubset(section_ids):
        raise ResearchReportError("report content lacks the closed required section set")
    table_ids = [str(item["table_id"]) for item in tables]
    chart_ids = [str(item["chart_id"]) for item in charts]
    if len(table_ids) != len(set(table_ids)) or len(chart_ids) != len(set(chart_ids)):
        raise ResearchReportError("report content repeats a table or chart ID")
    section_set = set(section_ids)
    if any(item["section_id"] not in section_set for item in (*tables, *charts)):
        raise ResearchReportError("report table or chart is rebound to an absent section")
    if profile == "full_valuation":
        scorecard_status = next(
            str(item["status"])
            for item in sections
            if item["section_id"] == "scorecard"
        )
        if (
            scorecard_status == "blocked"
            and payload["status"] != "blocked"
        ) or (
            scorecard_status != "complete"
            and payload["status"] == "complete"
        ):
            raise ResearchReportError(
                "report content status overstates the retained scorecard"
            )

    paragraph_ids: set[str] = set()
    paragraph_values: dict[str, str] = {}
    paragraph_text_values: set[str] = set()
    binding_fingerprints: set[str] = set()
    human_text: list[str] = []
    paragraph_count = 0
    row_count = 0
    point_count = 0
    section_binding_types: dict[str, set[str]] = {item: set() for item in section_ids}

    def consume_binding(binding: Mapping[str, Any], section_id: str) -> None:
        fingerprint = str(binding["fingerprint"])
        binding_fingerprints.add(fingerprint)
        section_binding_types[section_id].add(str(binding["object_type"]))

    for section in sections:
        section_id = str(section["section_id"])
        human_text.extend((str(section["title_zh"]), str(section["title_en"])))
        for paragraph in section["paragraphs"]:
            paragraph_id = str(paragraph["paragraph_id"])
            if paragraph_id in paragraph_ids:
                raise ResearchReportError("report content repeats a paragraph ID")
            paragraph_ids.add(paragraph_id)
            duplicate_key = canonical_json(
                {
                    "text_zh": paragraph["text_zh"],
                    "text_en": paragraph["text_en"],
                    "bindings": paragraph["bindings"],
                }
            )
            if duplicate_key in paragraph_values:
                raise ResearchReportError(
                    "report content repeats a substantive paragraph: "
                    f"{paragraph_values[duplicate_key]} and {paragraph['paragraph_id']}"
                )
            paragraph_values[duplicate_key] = paragraph_id
            text_key = canonical_json(
                {
                    "text_zh": _clean_text(paragraph["text_zh"]),
                    "text_en": _clean_text(paragraph["text_en"]),
                }
            )
            if text_key in paragraph_text_values:
                raise ResearchReportError(
                    "report content repeats narrative under a different evidence binding"
                )
            paragraph_text_values.add(text_key)
            human_text.extend((str(paragraph["text_zh"]), str(paragraph["text_en"])))
            for binding in paragraph["bindings"]:
                consume_binding(binding, section_id)
            paragraph_count += 1
    for table in tables:
        section_id = str(table["section_id"])
        human_text.extend((str(table["title_zh"]), str(table["title_en"])))
        human_text.extend(str(cell) for row in table["rows"] for cell in row)
        if any(len(row) != len(table["columns"]) for row in table["rows"]):
            raise ResearchReportError("report table row width differs from its columns")
        for binding in table["bindings"]:
            consume_binding(binding, section_id)
        row_count += len(table["rows"])
    for chart in charts:
        section_id = str(chart["section_id"])
        human_text.extend((str(chart["title_zh"]), str(chart["title_en"])))
        if chart["unit"] is None or not _clean_text(chart["unit"]):
            raise ResearchReportError("report chart lacks a single compatible unit")
        for series in chart["series"]:
            human_text.append(str(series["name"]))
            if len(series["points"]) < 2:
                raise ResearchReportError("report chart needs two compatible numeric points")
            for point in series["points"]:
                human_text.extend((str(point["label"]), str(point["value"])))
                try:
                    parsed_value = Decimal(str(point["value"]))
                except (InvalidOperation, TypeError) as exc:
                    raise ResearchReportError(
                        "report chart contains a non-numeric or Unknown point"
                    ) from exc
                if not parsed_value.is_finite():
                    raise ResearchReportError("report chart contains a non-finite point")
                consume_binding(point["binding"], section_id)
                point_count += 1
    expected_units = paragraph_count + row_count + point_count
    if payload["substantive_unit_count"] != expected_units:
        raise ResearchReportError("report substantive-unit count does not replay")
    if (
        payload["paragraph_count"] != paragraph_count
        or payload["distinct_paragraph_count"] != len(paragraph_text_values)
        or payload["anti_padding_method"] != "unique-evidence-bound-narrative-v1"
        or paragraph_count < 30
        or paragraph_count != len(paragraph_text_values)
    ):
        raise ResearchReportError("report anti-padding narrative counts do not replay")
    if payload["binding_fingerprints"] != sorted(binding_fingerprints):
        raise ResearchReportError("report binding-fingerprint set does not replay")
    if len(binding_fingerprints) < 16:
        raise ResearchReportError("report content has insufficient independent bindings")
    normalized_text = "\n".join(human_text).lower()
    if "本附录仅重复" in normalized_text or "audit padding" in normalized_text:
        raise ResearchReportError("report content contains a prohibited padding marker")
    if profile == "research_only":
        if payload["valuation_archive_fingerprint"] is not None:
            raise ResearchReportError("research_only content binds a valuation archive")
        forbidden_types = {
            object_type
            for types in section_binding_types.values()
            for object_type in types
            if any(
                marker in object_type.lower()
                for marker in ("futu", "valuation", "scorev2", "ownerscorecard", "marketexpect")
            )
        }
        if forbidden_types or any(
            item in normalized_text for item in _RESEARCH_ONLY_FORBIDDEN_TEXT
        ):
            raise ResearchReportError(
                "research_only content contains market, target, Futu, or Score data"
            )
    else:
        required_bindings = {
            "decision_summary": {"CompositeValuationResult", "OwnerScorecard"},
            "mckinsey_dcf_and_reverse": {"ValuationRunArchive"},
            "composite_value_target": {"CompositeValuationResult"},
            "scorecard": {"ScoreV2", "OwnerScorecard"},
        }
        for section_id, object_types in required_bindings.items():
            if not object_types.issubset(section_binding_types[section_id]):
                raise ResearchReportError(
                    f"full report section {section_id} lacks its exact typed binding"
                )
        full_futu = (
            "FutuSessionPublicationManifest" in section_binding_types["futu_vendor_validation"]
        )
        partial_futu = (
            "FutuPartialSessionPublicationManifest"
            in section_binding_types["futu_vendor_validation"]
        )
        if full_futu == partial_futu:
            raise ResearchReportError("full report does not bind exactly one Futu context")
        if (
            "FutuOptionalDataDispositionPublicationManifest"
            not in section_binding_types["futu_vendor_validation"]
        ):
            raise ResearchReportError("full report omits optional Futu data dispositions")
        if full_futu:
            complete_bindings = {
                "forward_reoi": "ForwardReOIValuationResult",
                "comparables": "ComparableValuationResult",
                "market_expectations": "MarketExpectationsPublicationManifest",
            }
            if any(
                object_type not in section_binding_types[section_id]
                for section_id, object_type in complete_bindings.items()
            ):
                raise ResearchReportError("complete report lacks a typed downstream section")
        elif "RuntimeGapPublicationManifest" not in section_binding_types["market_expectations"]:
            raise ResearchReportError("partial report lacks a typed runtime-gap disclosure")


def _typed_payload(value: object) -> dict[str, Any]:
    if type(value) is ValuationRunArchive:
        payload = to_json_value(value.manifest)
    else:
        to_dict = getattr(value, "to_dict", None)
        payload = to_dict() if callable(to_dict) else None
    if payload is None and isinstance(value, Mapping):
        payload = to_json_value(value)
    if payload is None:
        raise ResearchReportError("report content received an untyped evidence object")
    if not isinstance(payload, dict):
        raise ResearchReportError("report evidence payload must be an object")
    return payload


def _typed_binding(
    value: object,
    *,
    object_type: str | None = None,
    object_id: str | None = None,
    fingerprint: str | None = None,
) -> dict[str, str]:
    payload = _typed_payload(value)
    if fingerprint is None:
        candidate = getattr(value, "fingerprint", None)
        fingerprint = candidate if type(candidate) is str else None
    if fingerprint is None:
        for key in (
            "bundle_fingerprint",
            "manifest_fingerprint",
            "receipt_fingerprint",
            "result_fingerprint",
            "comparison_fingerprint",
            "index_fingerprint",
            "snapshot_fingerprint",
        ):
            if type(payload.get(key)) is str and re.fullmatch(r"[a-f0-9]{64}", payload[key]):
                fingerprint = payload[key]
                break
    if fingerprint is None:
        fingerprint = canonical_sha256(payload)
    if object_id is None:
        for key in (
            "document_id",
            "fact_id",
            "claim_id",
            "assumption_id",
            "calculation_id",
            "period_id",
            "bundle_id",
            "run_id",
            "report_spec_id",
            "archive_id",
            "manifest_id",
            "result_id",
            "score_id",
            "scorecard_id",
            "comparison_id",
            "index_id",
            "session_id",
            "receipt_id",
        ):
            candidate = payload.get(key)
            if type(candidate) is str and candidate:
                object_id = candidate
                break
    if object_id is None:
        for key, candidate in payload.items():
            if key.endswith("_id") and type(candidate) is str and candidate:
                object_id = candidate
                break
    if (
        type(object_id) is not str
        or not object_id
        or type(fingerprint) is not str
        or re.fullmatch(r"[a-f0-9]{64}", fingerprint) is None
    ):
        raise ResearchReportError("report evidence binding lacks an exact ID or fingerprint")
    return {
        "object_type": object_type or type(value).__name__,
        "object_id": object_id,
        "fingerprint": fingerprint,
    }


def _compact_json(value: object, *, limit: int = 280) -> str:
    text = (
        canonical_json(value) if isinstance(value, (Mapping, list, tuple)) else _clean_text(value)
    )
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _missing_evidence(payload: Mapping[str, Any]) -> list[str]:
    missing: set[str] = set()
    for key in ("missing_evidence", "issue_codes", "issues", "validation_issues"):
        value = payload.get(key)
        if isinstance(value, (list, tuple)):
            missing.update(_clean_text(item) for item in value if _clean_text(item))
    return sorted(missing)


def _paragraph(
    section_id: str,
    *,
    text_zh: str,
    text_en: str,
    bindings: list[dict[str, str]],
    missing_evidence: list[str] | None = None,
) -> dict[str, object]:
    base = {
        "text_zh": _clean_text(text_zh),
        "text_en": _clean_text(text_en),
        "bindings": sorted(bindings, key=lambda item: (item["object_type"], item["object_id"])),
        "missing_evidence": sorted(set(missing_evidence or ())),
    }
    if len(base["text_zh"]) < 24 or len(base["text_en"]) < 12:
        raise ResearchReportError("report paragraph is not substantive")
    return {
        "paragraph_id": f"paragraph:{section_id}:{canonical_sha256(base)[:16]}",
        **base,
    }


def _object_paragraph(section_id: str, collection: str, value: object) -> dict[str, object]:
    payload = _typed_payload(value)
    binding = _typed_binding(value)
    disclosed: list[str] = []
    for key in _PREFERRED_NARRATIVE_FIELDS:
        if key in payload and payload[key] not in (None, "", [], ()):
            disclosed.append(f"{key}={_compact_json(payload[key])}")
        if len(disclosed) == 14:
            break
    for key in _PROVENANCE_NARRATIVE_FIELDS:
        if len(disclosed) == 14:
            break
        if (
            key in payload
            and key not in _PREFERRED_NARRATIVE_FIELDS
            and payload[key]
            not in (
                None,
                "",
                [],
                (),
            )
        ):
            disclosed.append(f"{key}={_compact_json(payload[key], limit=180)}")
    if disclosed:
        details = "；".join(disclosed)
        details_en = "; ".join(disclosed)
    else:
        details = "Unknown：该类型未披露额外的可发布叙事字段"
        details_en = "Unknown: this type exposes no additional publishable narrative fields"
    visible_label = _binding_label(binding)
    apa_metadata_note_zh = ""
    apa_metadata_note_en = ""
    missing_evidence = _missing_evidence(payload)
    if binding["object_type"] == "SourceDocument":
        citation_metadata = _source_document_apa7_metadata(value)
        apa_metadata_note_zh = (
            " APA 7 元数据状态为 partial：SourceDocument 未披露经过核验的作者和标题，"
            "因此两项及 APA 7 引用均保持 Unknown；文档类型不会被当作标题。"
        )
        apa_metadata_note_en = (
            " APA 7 metadata status is partial: SourceDocument discloses neither a verified "
            "author nor a verified title, so both fields and the APA 7 reference remain "
            "Unknown; document type is not substituted for title."
        )
        missing_evidence = sorted(
            {
                *missing_evidence,
                *citation_metadata["missing_metadata"].split(";"),
            }
        )
    return _paragraph(
        section_id,
        text_zh=(
            f"冻结集合 {collection} 中的已审阅对象 {visible_label} 记录如下："
            f"{details}。完整对象标识与哈希见证据绑定附录；未披露项目保持 Unknown。"
            f"{apa_metadata_note_zh}"
        ),
        text_en=(
            f"Reviewed object {visible_label} from the frozen {collection} collection records: "
            f"{details_en}. The complete object ID and hash are retained in the evidence-binding "
            f"appendix; undisclosed items remain Unknown.{apa_metadata_note_en}"
        ),
        bindings=[binding],
        missing_evidence=missing_evidence,
    )


def _report_value(value: object) -> str:
    """Render zero as disclosed data and reserve Unknown exclusively for null."""

    return "Unknown" if value is None else _clean_text(value)


@_uses_report_decimal_context
def _report_decimal(
    value: object,
    *,
    places: int = 2,
    trim: bool = False,
) -> str:
    """Format a disclosed report number without changing its retained exact authority."""

    if value is None:
        return "Unknown"
    try:
        parsed = Decimal(str(value))
    except InvalidOperation:
        return _clean_text(value)
    if not parsed.is_finite() or places < 0 or places > 8:
        return "Unknown"
    digits = len(parsed.as_tuple().digits)
    precision = max(
        _REPORT_DECIMAL_FORMAT_PRECISION,
        digits + abs(parsed.as_tuple().exponent) + places + 4,
    )
    with localcontext(_report_decimal_context(precision=precision)):
        rounded = parsed.quantize(Decimal(1).scaleb(-places))
    if rounded == 0:
        rounded = abs(rounded)
    rendered = format(rounded, f",.{places}f")
    return rendered.rstrip("0").rstrip(".") if trim and "." in rendered else rendered


@_uses_report_decimal_context
def _report_ratio_percent(value: object, *, places: int = 1) -> str:
    if value is None:
        return "Unknown"
    try:
        parsed = Decimal(str(value))
    except InvalidOperation:
        return _clean_text(value)
    if not parsed.is_finite():
        return "Unknown"
    digits = len(parsed.as_tuple().digits)
    precision = max(
        _REPORT_DECIMAL_FORMAT_PRECISION,
        digits + abs(parsed.as_tuple().exponent) + places + 6,
    )
    with localcontext(_report_decimal_context(precision=precision)):
        scaled = parsed * Decimal(100)
    rendered = _report_decimal(scaled, places=places, trim=True)
    return rendered if rendered == "Unknown" else f"{rendered}%"


def _humanized_machine_label(value: object) -> str:
    text = _clean_text(value)
    text = re.sub(r"^(?:Qot|Trd)_Get", "", text)
    text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", text)
    return re.sub(r"[_-]+", " ", text).strip()


@dataclass(frozen=True, slots=True)
class _CompositeHorizonPublication:
    current_value: str
    current_status: str
    twelve_month_value: str
    twelve_month_status: str


def _composite_horizon_publication(
    composite_valuation: CompositeValuationResult,
) -> _CompositeHorizonPublication:
    current_issue = "current_panel_dispersion_exceeds_50_percent"
    twelve_month_issue = "twelve_month_panel_dispersion_exceeds_50_percent"
    issue_codes = set(composite_valuation.issue_codes)

    if composite_valuation.status == "blocked":
        current_suppressed = True
        twelve_month_suppressed = True
        current_status = "blocked"
        twelve_month_status = "blocked"
    elif composite_valuation.status == "contested":
        current_suppressed = current_issue in issue_codes
        twelve_month_suppressed = twelve_month_issue in issue_codes
        current_status = "contested" if current_suppressed else "complete"
        twelve_month_status = "contested" if twelve_month_suppressed else "complete"
    elif composite_valuation.status == "complete":
        current_suppressed = False
        twelve_month_suppressed = False
        current_status = "complete"
        twelve_month_status = "complete"
    else:
        raise ResearchReportError("composite valuation status is not closed")

    def rendered_value(value: str | None, *, suppressed: bool, label: str) -> str:
        if suppressed:
            if value is not None:
                raise ResearchReportError(
                    f"{label} must be null when its publication horizon is suppressed"
                )
            return "Unknown"
        if value is None:
            raise ResearchReportError(
                f"{label} cannot be null when its publication horizon is available"
            )
        rendered = _report_decimal(value)
        if rendered == "Unknown":
            raise ResearchReportError(f"{label} could not be rendered")
        return rendered

    return _CompositeHorizonPublication(
        current_value=rendered_value(
            composite_valuation.current_intrinsic_value,
            suppressed=current_suppressed,
            label="current intrinsic value",
        ),
        current_status=current_status,
        twelve_month_value=rendered_value(
            composite_valuation.twelve_month_target,
            suppressed=twelve_month_suppressed,
            label="twelve-month target",
        ),
        twelve_month_status=twelve_month_status,
    )


def _composite_ineligible_narrative(
    composite_valuation: CompositeValuationResult,
    *,
    section_title_zh: str,
    section_title_en: str,
) -> tuple[str, str]:
    publication = _composite_horizon_publication(composite_valuation)
    if composite_valuation.status == "blocked":
        return (
            f"{section_title_zh}绑定的综合估值状态为 blocked；"
            "当前综合值与12个月目标价均因估值面板不完整而保持 Unknown；"
            "研究建议固定为无法评级，不读取冻结结论后的市场预期。",
            f"{section_title_en} is bound to a blocked composite. Current composite value "
            "and the twelve-month target remain Unknown because the valuation panels are "
            "incomplete; the recommendation is Unrated and no post-conclusion market "
            "context is read.",
        )

    current_zh = (
        "当前综合值因当前估值面板离散度超过50%以 Unknown 展示"
        if publication.current_status == "contested"
        else f"未受影响的当前综合值为 {publication.current_value}"
    )
    target_zh = (
        "12个月目标价因12个月估值面板离散度超过50%以 Unknown 展示"
        if publication.twelve_month_status == "contested"
        else f"未受影响的12个月目标价为 {publication.twelve_month_value}"
    )
    current_en = (
        "the current composite value is shown as Unknown because current-panel dispersion "
        "exceeds 50%"
        if publication.current_status == "contested"
        else f"the unaffected current composite value is {publication.current_value}"
    )
    target_en = (
        "the twelve-month target is shown as Unknown because twelve-month panel dispersion "
        "exceeds 50%"
        if publication.twelve_month_status == "contested"
        else f"the unaffected twelve-month target is {publication.twelve_month_value}"
    )
    return (
        f"{section_title_zh}绑定的综合估值状态为 contested；{current_zh}；{target_zh}；"
        "研究建议固定为无法评级，不读取冻结结论后的市场预期。",
        f"{section_title_en} is bound to a contested composite; {current_en}; "
        f"{target_en}. The recommendation is Unrated and no post-conclusion market "
        "context is read.",
    )


def _full_valuation_decision_summary(
    composite_valuation: CompositeValuationResult,
    owner_scorecard: OwnerScorecard,
    *,
    effective_recommendation: str | None = None,
    recommendation_authority: object | None = None,
) -> dict[str, object]:
    composite_binding = _typed_binding(
        composite_valuation,
        object_type="CompositeValuationResult",
    )
    scorecard_binding = _typed_binding(owner_scorecard, object_type="OwnerScorecard")
    if effective_recommendation is None:
        effective_recommendation = owner_scorecard.recommendation
    if effective_recommendation not in {
        "重点关注",
        "关注",
        "观察",
        "回避",
        "无法评级",
    }:
        raise ResearchReportError("effective recommendation is not closed")
    recommendation_binding = (
        None if recommendation_authority is None else _typed_binding(recommendation_authority)
    )
    composite_publication = _composite_horizon_publication(composite_valuation)
    values = {
        "recommendation": _report_value(effective_recommendation),
        "frozen_score_recommendation": _report_value(owner_scorecard.recommendation),
        "overall_score": _report_decimal(owner_scorecard.overall_score, places=1, trim=True),
        "confidence_percent": _report_decimal(
            owner_scorecard.confidence_percent, places=1, trim=True
        ),
        "market_price": _report_decimal(composite_valuation.market_price),
        "current_intrinsic_value": composite_publication.current_value,
        "twelve_month_target": composite_publication.twelve_month_value,
        "margin_of_safety": _report_ratio_percent(composite_valuation.margin_of_safety),
        "twelve_month_upside": _report_ratio_percent(
            composite_valuation.twelve_month_upside
        ),
        "composite_status": _report_value(composite_valuation.status),
    }
    missing = sorted(
        {
            *tuple(composite_valuation.issue_codes),
            *tuple(owner_scorecard.issue_codes),
            *(
                ()
                if recommendation_authority is None
                else tuple(getattr(recommendation_authority, "issue_codes", ()))
            ),
        }
    )
    return _paragraph(
        "decision_summary",
        text_zh=(
            "完整估值决策摘要严格绑定综合估值与四镜总评："
            f"研究建议={values['recommendation']}；"
            f"冻结评分建议={values['frozen_score_recommendation']}；"
            f"总评={values['overall_score']}/100；"
            f"评分置信度={values['confidence_percent']}%；市场价格={values['market_price']}；"
            f"当前内在价值={values['current_intrinsic_value']}；"
            f"12个月目标价={values['twelve_month_target']}；"
            f"安全边际={values['margin_of_safety']}；"
            f"12个月上涨空间={values['twelve_month_upside']}；"
            f"综合估值状态={values['composite_status']}。"
        ),
        text_en=(
            "The full-valuation decision summary is bound to the composite valuation and "
            f"four-lens aggregate: recommendation={values['recommendation']}; "
            f"frozen score recommendation={values['frozen_score_recommendation']}; "
            f"overall score={values['overall_score']}/100; score confidence="
            f"{values['confidence_percent']}%; market price={values['market_price']}; "
            f"current intrinsic value={values['current_intrinsic_value']}; twelve-month "
            f"target={values['twelve_month_target']}; margin of safety="
            f"{values['margin_of_safety']}; twelve-month upside="
            f"{values['twelve_month_upside']}; composite status="
            f"{values['composite_status']}."
        ),
        bindings=[
            composite_binding,
            scorecard_binding,
            *([] if recommendation_binding is None else [recommendation_binding]),
        ],
        missing_evidence=missing,
    )


def _decision_summary_paragraphs(
    *,
    profile: str,
    bundle: object,
    composite_valuation: CompositeValuationResult | None,
    owner_scorecard: OwnerScorecard | None,
    market_expectations_manifest: MarketExpectationsPublicationManifest | None = None,
    runtime_gap_manifest: RuntimeGapPublicationManifest | None = None,
) -> list[dict[str, object]]:
    paragraphs = [_object_paragraph("decision_summary", "research_bundles", bundle)]
    if profile == "research_only":
        if composite_valuation is not None or owner_scorecard is not None:
            raise ResearchReportError("research_only decision summary received valuation data")
        return paragraphs
    if profile != "full_valuation":
        raise ResearchReportError("report decision summary profile is not closed")
    if composite_valuation is None or owner_scorecard is None:
        raise ResearchReportError("full_valuation decision summary lacks typed results")
    recommendation_authority: object | None = market_expectations_manifest
    if recommendation_authority is None:
        recommendation_authority = runtime_gap_manifest
    effective_recommendation = (
        owner_scorecard.recommendation
        if (
            composite_valuation.status == "complete"
            and market_expectations_manifest is not None
            and market_expectations_manifest.status == "complete"
            and runtime_gap_manifest is None
        )
        else "无法评级"
    )
    paragraphs.append(
        _full_valuation_decision_summary(
            composite_valuation,
            owner_scorecard,
            effective_recommendation=effective_recommendation,
            recommendation_authority=recommendation_authority,
        )
    )
    return paragraphs


def _gap_paragraph(
    section_id: str,
    title_zh: str,
    title_en: str,
    binding: dict[str, str],
) -> dict[str, object]:
    return _paragraph(
        section_id,
        text_zh=(
            f"{title_zh}所需的额外已审阅对象在冻结输入中未披露；本节明确保留 Unknown，"
            "不以推测、模板文字或外部未绑定资料补足。"
        ),
        text_en=(
            f"No additional reviewed object for {title_en} is disclosed by the frozen input. "
            "The section remains Unknown and is not filled with inference or unbound material."
        ),
        bindings=[binding],
        missing_evidence=[f"unknown:{section_id}"],
    )


def _table(
    table_id: str,
    section_id: str,
    title_zh: str,
    title_en: str,
    columns: list[str],
    rows: list[list[str]],
    bindings: list[dict[str, str]],
) -> dict[str, object]:
    if not rows:
        rows = [["Unknown" for _ in columns]]
    if any(len(row) != len(columns) for row in rows):
        raise ResearchReportError("generated report table has an invalid row width")
    return {
        "table_id": f"table:{table_id}",
        "section_id": section_id,
        "title_zh": title_zh,
        "title_en": title_en,
        "columns": columns,
        "rows": [[_clean_text(cell) for cell in row] for row in rows],
        "bindings": sorted(
            {canonical_json(item): item for item in bindings}.values(),
            key=lambda item: (item["object_type"], item["object_id"]),
        ),
    }


def _chart(
    chart_id: str,
    section_id: str,
    title_zh: str,
    title_en: str,
    unit: str | None,
    series: list[dict[str, object]],
) -> dict[str, object]:
    return {
        "chart_id": f"chart:{chart_id}",
        "section_id": section_id,
        "title_zh": title_zh,
        "title_en": title_en,
        "unit": unit,
        "series": series,
    }


def _point(label: object, value: object, binding: dict[str, str]) -> dict[str, object]:
    value_text = None if value is None else _clean_text(value)
    if value_text is not None:
        try:
            parsed = Decimal(value_text)
        except InvalidOperation:
            value_text = None
        else:
            if not parsed.is_finite():
                value_text = None
    return {"label": _clean_text(label), "value": value_text, "binding": binding}


def _flatten_scalars(value: object, prefix: str = "") -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    if isinstance(value, Mapping):
        for key, child in sorted(value.items(), key=lambda item: str(item[0])):
            path = f"{prefix}.{key}" if prefix else str(key)
            rows.extend(_flatten_scalars(child, path))
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            rows.extend(_flatten_scalars(child, f"{prefix}[{index}]"))
    elif isinstance(value, (str, int, float, bool)) or value is None:
        rows.append((prefix, "Unknown" if value is None else _clean_text(value)))
    return rows


def _reviewed_domain_tables(graph: ContractGraph) -> list[dict[str, object]]:
    """Render unique reviewed domain records; omit unavailable domains instead of padding."""

    tables: list[dict[str, object]] = []
    for table_id, section_id, title_zh, title_en, collections in _REVIEWED_DOMAIN_TABLES:
        objects = [
            (collection, item)
            for collection in collections
            for item in tuple(getattr(graph, collection))
        ]
        if not objects:
            continue
        rows: list[list[str]] = []
        bindings: list[dict[str, str]] = []
        for collection, item in objects:
            binding = _typed_binding(item)
            bindings.append(binding)
            payload = _typed_payload(item)
            disclosed = {
                field: payload[field]
                for field in _PREFERRED_NARRATIVE_FIELDS
                if field in payload and payload[field] not in (None, "", [], ())
            }
            rows.append(
                [
                    type(item).__name__,
                    binding["object_id"],
                    collection,
                    _compact_json(disclosed or {"status": "Unknown"}, limit=640),
                ]
            )
        tables.append(
            _table(
                table_id,
                section_id,
                title_zh,
                title_en,
                ["object_type", "object_id", "field", "reviewed_value"],
                rows,
                bindings,
            )
        )
    return tables


def _report_content_tables(
    research_source_index: ResearchSourceIndex,
    research_source_manifest: ResearchSourceIndexPublicationManifest,
    research: ReloadedResearchInput,
    valuation: ReloadedValuationInput | None,
    forward_reoi: ForwardReOIValuationResult | None,
    comparable_valuation: ComparableValuationResult | None,
    composite_valuation: CompositeValuationResult | None,
    score_v2: tuple[ScoreV2, ...],
    owner_scorecard: OwnerScorecard | None,
    market_expectations_manifest: MarketExpectationsPublicationManifest | None,
    runtime_gap_manifest: RuntimeGapPublicationManifest | None,
    futu_optional_data_disposition_manifests: tuple[
        FutuOptionalDataDispositionPublicationManifest, ...
    ],
) -> list[dict[str, object]]:
    graph = research_source_index.graph
    bundle = research.result.bundle
    bundle_binding = _typed_binding(bundle)
    source_payload = research_source_manifest.to_dict()
    document_bindings = [_typed_binding(item) for item in graph.documents]
    tables = [
        _table(
            "source_index",
            "sources_and_cutoff",
            "正式来源索引",
            "Official Source Index",
            ["document_id", "type", "published", "authority", "source_url"],
            [
                [
                    str(item["document_id"]),
                    str(item["document_type"]),
                    str(item["published_date"]),
                    str(item["authority_level"]),
                    str(item["source_url"]),
                ]
                for item in source_payload["sources"]
            ],
            document_bindings or [_typed_binding(research_source_manifest)],
        ),
        _table(
            "references_and_source_receipts",
            "references_and_source_receipts",
            "APA 7 元数据状态、正式来源与内容收据",
            "APA 7 Metadata Status, Official Sources, and Content Receipts",
            [
                "document_id",
                "apa7_metadata_status",
                "verified_author",
                "verified_title",
                "missing_metadata",
                "apa7_reference",
                "source_url",
                "content_sha256",
            ],
            [
                [
                    item.document_id,
                    _source_document_apa7_metadata(item)["apa7_metadata_status"],
                    _source_document_apa7_metadata(item)["verified_author"],
                    _source_document_apa7_metadata(item)["verified_title"],
                    _source_document_apa7_metadata(item)["missing_metadata"],
                    _source_document_apa7_metadata(item)["apa7_reference"],
                    item.source_url,
                    item.content_sha256,
                ]
                for item in graph.documents
            ],
            document_bindings or [_typed_binding(research_source_manifest)],
        ),
        _table(
            "module_status",
            "decision_summary",
            "研究模块状态",
            "Research Module Status",
            ["module", "status", "as_of", "freshness", "missing"],
            [
                [
                    str(item["module_type"]),
                    str(item["module_status"]),
                    str(item["as_of_date"]),
                    str(item["freshness"]["status"]),
                    "；".join(item["missing_evidence"]) or "None",
                ]
                for item in bundle.module_references
            ],
            [bundle_binding],
        ),
        _table(
            "financial_facts",
            "financial_history_and_segments",
            "历史财务事实",
            "Historical Financial Facts",
            ["fact_id", "concept", "value", "unit", "period", "confidence"],
            [
                [
                    item.fact_id,
                    item.concept,
                    _compact_json(item.value),
                    str(item.unit or "Unknown"),
                    _compact_json(item.period),
                    item.confidence,
                ]
                for item in graph.facts
            ],
            [_typed_binding(item) for item in graph.facts] or [bundle_binding],
        ),
        _table(
            "segments",
            "financial_history_and_segments",
            "分部定义与快照",
            "Segment Definitions and Snapshots",
            ["object_id", "object_type", "status_or_name", "period_or_as_of"],
            [
                [
                    _typed_binding(item)["object_id"],
                    type(item).__name__,
                    _compact_json(
                        _typed_payload(item).get("segment_name")
                        or _typed_payload(item).get("status")
                        or "Unknown"
                    ),
                    _compact_json(
                        _typed_payload(item).get("period")
                        or _typed_payload(item).get("as_of_date")
                        or "Unknown"
                    ),
                ]
                for item in (*graph.segment_definitions, *graph.segment_snapshots)
            ],
            [
                _typed_binding(item)
                for item in (*graph.segment_definitions, *graph.segment_snapshots)
            ]
            or [bundle_binding],
        ),
        _table(
            "source_integrity",
            "sources_and_cutoff",
            "来源期间、检索与完整性",
            "Source Period, Retrieval, and Integrity",
            ["document_id", "period", "retrieved_at", "content_sha256"],
            [
                [
                    item.document_id,
                    _compact_json(item.period),
                    item.retrieved_at,
                    item.content_sha256,
                ]
                for item in graph.documents
            ],
            document_bindings,
        ),
        _table(
            "fact_provenance",
            "accounting_quality",
            "事实来源、定位与推导链",
            "Fact Provenance, Locator, and Derivation Chain",
            ["fact_id", "source_document", "source_locator", "parent_facts"],
            [
                [
                    item.fact_id,
                    item.source_document_id,
                    item.source_locator,
                    "；".join(item.parent_fact_ids) or "Direct disclosed fact",
                ]
                for item in graph.facts
            ],
            [_typed_binding(item) for item in graph.facts],
        ),
        _table(
            "module_artifact_lineage",
            "evidence_audit_index",
            "模块对象、工件哈希与证据缺口",
            "Module Objects, Artifact Hashes, and Evidence Gaps",
            ["module", "object_ids", "artifact_sha256", "missing_evidence"],
            [
                [
                    str(item["module_type"]),
                    "；".join(item["object_ids"]) or "Unknown",
                    str(item["artifact_sha256"]),
                    "；".join(item["missing_evidence"]) or "None",
                ]
                for item in bundle.module_references
            ],
            [bundle_binding],
        ),
        _table(
            "research_bundle_lineage",
            "evidence_audit_index",
            "研究包、运行与组件锁谱系",
            "Research Bundle, Run, and Component-Lock Lineage",
            ["authority", "identifier", "fingerprint", "cutoff"],
            [
                [
                    "ResearchBundle",
                    bundle.bundle_id,
                    bundle.bundle_fingerprint,
                    bundle.data_cutoff_date,
                ],
                [
                    "RunManifest",
                    research.result.run_manifest.run_id,
                    research.result.run_manifest.fingerprint,
                    research.result.run_manifest.data_cutoff_date,
                ],
                [
                    "ComponentLock",
                    "component-lock.json",
                    bundle.component_lock_sha256,
                    bundle.data_cutoff_date,
                ],
            ],
            [bundle_binding, _typed_binding(research.result.run_manifest)],
        ),
    ]
    tables.extend(_reviewed_domain_tables(graph))
    if valuation is None:
        return tables
    assert composite_valuation is not None
    assert owner_scorecard is not None
    archive_binding = _typed_binding(
        valuation.archive,
        object_type="ValuationRunArchive",
        object_id=str(valuation.archive.manifest["archive_id"]),
    )
    composite_binding = _typed_binding(composite_valuation)
    scorecard_binding = _typed_binding(owner_scorecard)
    gap_binding = None if runtime_gap_manifest is None else _typed_binding(runtime_gap_manifest)
    flattened = _flatten_scalars(to_json_value(valuation.archive.result_payload))
    sensitivity = [
        row
        for row in flattened
        if any(marker in row[0].lower() for marker in ("wacc", "growth", "sensitivity", "reverse"))
    ]
    panel_rows: list[list[str]] = []
    for panel, scenarios in sorted(composite_valuation.to_dict()["panel_scenarios"].items()):
        for scenario in scenarios:
            panel_rows.append(
                [
                    str(panel),
                    str(scenario["name"]),
                    _report_decimal(scenario["current_value_per_share"]),
                    _report_decimal(scenario["twelve_month_value_per_share"]),
                ]
            )
    composite_publication = _composite_horizon_publication(composite_valuation)
    tables.extend(
        [
            _table(
                "kernel_result",
                "mckinsey_dcf_and_reverse",
                "固定内核结果与 Reverse Price",
                "Fixed Kernel Result and Reverse Price",
                ["path", "value"],
                [[path, value] for path, value in flattened[:80]],
                [archive_binding],
            ),
            _table(
                "three_panel_scenarios",
                "scenarios",
                "三个估值面板的三场景",
                "Three Scenarios Across Three Panels",
                ["panel", "scenario", "current_value", "twelve_month_value"],
                panel_rows,
                [composite_binding],
            ),
            _table(
                "composite_value_target",
                "composite_value_target",
                "综合价值、目标价与建议资格",
                "Composite Value, Target, and Recommendation Eligibility",
                ["metric", "value", "publication_status"],
                [
                    [
                        "current_intrinsic_value",
                        composite_publication.current_value,
                        composite_publication.current_status,
                    ],
                    [
                        "twelve_month_target",
                        composite_publication.twelve_month_value,
                        composite_publication.twelve_month_status,
                    ],
                    [
                        "recommendation",
                        owner_scorecard.recommendation,
                        owner_scorecard.status,
                    ],
                ],
                [composite_binding, scorecard_binding],
            ),
            _table(
                "sensitivity",
                "sensitivity",
                "敏感性与 Reverse 参数",
                "Sensitivity and Reverse Inputs",
                ["path", "value"],
                [[path, value] for path, value in sensitivity[:80]]
                or [["Unknown", "冻结内核结果未披露额外敏感性网格"]],
                [archive_binding],
            ),
            _table(
                "owner_scorecard",
                "scorecard",
                "四镜评分与总评",
                "Four-Lens Scores and Aggregate",
                ["lens", "status", "score", "confidence", "fingerprint"],
                [
                    [
                        item.lens,
                        item.status,
                        _report_value(item.total_score),
                        _report_value(item.confidence_percent),
                        item.fingerprint,
                    ]
                    for item in score_v2
                ]
                + [
                    [
                        "overall",
                        owner_scorecard.status,
                        _report_value(owner_scorecard.overall_score),
                        _report_value(owner_scorecard.confidence_percent),
                        owner_scorecard.fingerprint,
                    ]
                ],
                [_typed_binding(item) for item in score_v2] + [scorecard_binding],
            ),
        ]
    )
    optional_bindings = [
        _typed_binding(item) for item in futu_optional_data_disposition_manifests
    ]
    tables.append(
        _table(
            "futu_optional_data_dispositions",
            "futu_vendor_validation",
            "富途非价格可选数据处置",
            "Futu Optional Non-Price Data Dispositions",
            ["protocol", "data_family", "status", "reason", "evidence_counts"],
            [
                [
                    (
                        f"{payload['protocol_id']} / "
                        f"{_humanized_machine_label(payload['protocol_name'])}"
                    ),
                    _humanized_machine_label(payload["data_family"]),
                    _humanized_machine_label(payload["status"]),
                    _humanized_machine_label(payload["reason_code"]),
                    (
                        f"requests={len(payload['requests'])}; "
                        f"responses={len(payload['responses'])}; "
                        f"observations={len(payload['observations'])}"
                    ),
                ]
                for payload in (
                    item.to_dict()
                    for item in futu_optional_data_disposition_manifests
                )
            ],
            optional_bindings,
        )
    )
    if forward_reoi is not None:
        tables.append(
            _table(
                "forward_reoi",
                "forward_reoi",
                "Forward ReOI 场景结果",
                "Forward ReOI Scenario Results",
                ["scenario", "current_value", "twelve_month_value", "issues"],
                [
                    [
                        str(item["name"]),
                        _report_decimal(item["current_value_per_share"]),
                        _report_decimal(item["twelve_month_value_per_share"]),
                        "；".join(item.get("issue_codes", ())) or "None",
                    ]
                    for item in forward_reoi.to_dict()["scenarios"]
                ],
                [_typed_binding(forward_reoi)],
            )
        )
    else:
        assert gap_binding is not None
        tables.append(
            _table(
                "forward_reoi",
                "forward_reoi",
                "Forward ReOI 场景结果",
                "Forward ReOI Scenario Results",
                ["scenario", "current_value", "twelve_month_value", "issues"],
                [["Unknown", "Unknown", "Unknown", "missing_forward_reoi_panel"]],
                [gap_binding],
            )
        )
    if comparable_valuation is not None:
        tables.append(
            _table(
                "comparables",
                "comparables",
                "人工确认同行与倍数结果",
                "Human-Confirmed Peers and Multiples",
                ["path", "value"],
                [
                    [path, value]
                    for path, value in _flatten_scalars(comparable_valuation.to_dict())
                    if any(marker in path for marker in ("peer", "metric", "scenario"))
                ][:100],
                [_typed_binding(comparable_valuation)],
            )
        )
    else:
        assert gap_binding is not None
        tables.append(
            _table(
                "comparables",
                "comparables",
                "人工确认同行与倍数结果",
                "Human-Confirmed Peers and Multiples",
                ["path", "value"],
                [["status", "Unknown: missing_comparable_panel"]],
                [gap_binding],
            )
        )
    if market_expectations_manifest is not None:
        market_binding = _typed_binding(market_expectations_manifest)
        tables.append(
            _table(
                "market_expectations",
                "market_expectations",
                "冻结结论后的市场预期对照",
                "Post-Conclusion Market Expectations",
                ["family", "field", "value", "scope"],
                [
                    [
                        str(item["data_family"]),
                        str(item["field_id"]),
                        _compact_json(item.get("value")),
                        str(item["use_scope"]),
                    ]
                    for item in market_expectations_manifest.to_dict()["observations"]
                ],
                [market_binding],
            )
        )
    else:
        assert gap_binding is not None
        tables.append(
            _table(
                "market_expectations",
                "market_expectations",
                "冻结结论后的市场预期对照",
                "Post-Conclusion Market Expectations",
                ["status", "value", "reason", "scope"],
                [
                    [
                        "not_run",
                        "Unknown",
                        "post-context suppressed because the conclusion was ineligible",
                        "none",
                    ]
                ],
                [gap_binding],
            )
        )
    return tables


def _chart_period_kind(period: Mapping[str, object]) -> str:
    explicit = period.get("period_kind", period.get("kind"))
    if type(explicit) is str and explicit.strip():
        return f"explicit:{explicit.strip().lower()}"
    start = period.get("start")
    end = period.get("end")
    if start is None and type(end) is str and end:
        return "instant"
    if type(start) is not str or type(end) is not str or not start or not end:
        return "unspecified"
    try:
        days = (date.fromisoformat(end) - date.fromisoformat(start)).days + 1
    except ValueError:
        return "duration:invalid"
    if days <= 100:
        bucket = "quarter"
    elif days <= 200:
        bucket = "half_year"
    elif days <= 300:
        bucket = "nine_month"
    else:
        bucket = "annual"
    return f"duration:{bucket}"


def _report_content_charts(
    research_source_index: ResearchSourceIndex,
    research: ReloadedResearchInput,
    valuation: ReloadedValuationInput | None,
    composite_valuation: CompositeValuationResult | None,
    score_v2: tuple[ScoreV2, ...],
    market_expectations_manifest: MarketExpectationsPublicationManifest | None,
    runtime_gap_manifest: RuntimeGapPublicationManifest | None,
) -> list[dict[str, object]]:
    graph = research_source_index.graph
    fact_groups: dict[str, tuple[dict[str, object], list[object]]] = {}
    for fact in graph.facts:
        if fact.value_type != "number":
            continue
        period = to_json_value(fact.period)
        assert isinstance(period, dict)
        scope = {
            "issuer_id": fact.issuer_id,
            "concept": fact.concept,
            "unit": fact.unit,
            "currency": fact.currency,
            "period_kind": _chart_period_kind(period),
            "derivation": fact.derivation or "reported",
        }
        key = canonical_json(scope)
        if key not in fact_groups:
            fact_groups[key] = (scope, [])
        fact_groups[key][1].append(fact)
    charts: list[dict[str, object]] = []
    for _, (scope, facts) in sorted(fact_groups.items()):
        if len(facts) < 2 or len(charts) >= 12:
            continue
        ordered = sorted(
            facts,
            key=lambda fact: (canonical_json(to_json_value(fact.period)), fact.fact_id),
        )
        unit = str(scope["unit"] or "unitless")
        if scope["currency"] is not None:
            unit = f"{scope['currency']} {unit}"
        charts.append(
            _chart(
                f"reviewed_fact_{canonical_sha256(scope)[:12]}",
                "financial_history_and_segments",
                f"已审阅财务趋势：{scope['concept']}",
                f"Reviewed Financial Trend: {scope['concept']}",
                unit,
                [
                    {
                        "name": f"{scope['concept']} [{canonical_sha256(scope)[:12]}]",
                        "points": [
                            _point(
                                _compact_json(to_json_value(fact.period)),
                                fact.value,
                                _typed_binding(fact),
                            )
                            for fact in ordered
                        ],
                    }
                ],
            )
        )
    if valuation is None:
        return charts
    assert composite_valuation is not None
    composite_binding = _typed_binding(composite_valuation)
    panel_points: list[dict[str, object]] = []
    for panel, scenarios in sorted(composite_valuation.to_dict()["panel_scenarios"].items()):
        for scenario in scenarios:
            panel_points.append(
                _point(
                    f"{panel}/{scenario['name']}/current",
                    scenario["current_value_per_share"],
                    composite_binding,
                )
            )
            panel_points.append(
                _point(
                    f"{panel}/{scenario['name']}/12m",
                    scenario["twelve_month_value_per_share"],
                    composite_binding,
                )
            )
    score_points = [
        _point(item.lens, item.total_score, _typed_binding(item))
        for item in score_v2
        if item.total_score is not None
    ]
    valuation_charts = [
        chart
        for chart in (
            _chart(
                "three_panel_values",
                "scenarios",
                "三面板三场景价值分布",
                "Three-Panel Scenario Value Distribution",
                str(composite_valuation.basis_receipt["currency"]),
                [
                    {
                        "name": "value_per_share",
                        "points": panel_points,
                    }
                ],
            ),
            (
                _chart(
                    "four_lens_scores",
                    "scorecard",
                    "四镜评分图",
                    "Four-Lens Score Chart",
                    "score/100",
                    [{"name": "lens_scores", "points": score_points}],
                )
                if len(score_points) == len(score_v2) == 4
                else None
            ),
        )
        if chart is not None and len(chart["series"][0]["points"]) >= 2
    ]
    charts.extend(valuation_charts)
    if market_expectations_manifest is not None:
        market_binding = _typed_binding(market_expectations_manifest)
        grouped: dict[str, tuple[dict[str, object], list[dict[str, object]]]] = {}
        for observation in market_expectations_manifest.to_dict()["observations"]:
            if observation["value_type"] != "number" or observation.get("value") is None:
                continue
            period = observation.get("period") or {}
            qualifiers = observation.get("qualifiers") or {}
            scope = {
                "data_family": observation["data_family"],
                "concept": observation.get("canonical_concept") or observation["field_id"],
                "unit": observation.get("unit"),
                "currency": observation.get("currency"),
                "period_kind": _chart_period_kind(period),
                "qualifiers": qualifiers,
            }
            key = canonical_json(scope)
            if key not in grouped:
                grouped[key] = (scope, [])
            grouped[key][1].append(observation)
        for _, (scope, observations) in sorted(grouped.items()):
            if len(observations) < 2 or len(charts) >= 16:
                continue
            ordered = sorted(
                observations,
                key=lambda item: (
                    canonical_json(item.get("period") or {}),
                    str(item["observation_id"]),
                ),
            )
            unit = str(scope["unit"] or "unitless")
            if scope["currency"] is not None:
                unit = f"{scope['currency']} {unit}"
            charts.append(
                _chart(
                    f"market_{canonical_sha256(scope)[:12]}",
                    "market_expectations",
                    f"市场预期同口径序列：{scope['concept']}",
                    f"Compatible Market-Expectation Series: {scope['concept']}",
                    unit,
                    [
                        {
                            "name": f"{scope['concept']} [{canonical_sha256(scope)[:12]}]",
                            "points": [
                                _point(
                                    _compact_json(item.get("period") or {}),
                                    item["value"],
                                    market_binding,
                                )
                                for item in ordered
                            ],
                        }
                    ],
                )
            )
    return charts


def _retained_scorecard_status(
    score_v2: tuple[ScoreV2, ...],
    owner_scorecard: OwnerScorecard,
) -> str:
    retained_statuses = (
        owner_scorecard.status,
        *(score.status for score in score_v2),
    )
    if "blocked" in retained_statuses:
        return "blocked"
    if any(status != "complete" for status in retained_statuses):
        return "partial"
    return "complete"


def _content_status_with_scorecard(
    content_status: str,
    scorecard_status: str,
) -> str:
    if scorecard_status == "blocked":
        return "blocked"
    if scorecard_status != "complete" and content_status == "complete":
        return "partial"
    return content_status


def _build_report_content(
    *,
    profile: str,
    research: ReloadedResearchInput,
    report_spec: ReportSpec,
    research_source_index: ResearchSourceIndex,
    research_source_manifest: ResearchSourceIndexPublicationManifest,
    valuation: ReloadedValuationInput | None,
    futu_session_manifest: FutuSessionPublicationManifest | None,
    futu_partial_session_manifest: FutuPartialSessionPublicationManifest | None,
    forward_reoi: ForwardReOIValuationResult | None,
    comparable_valuation: ComparableValuationResult | None,
    composite_valuation: CompositeValuationResult | None,
    score_v2: tuple[ScoreV2, ...],
    owner_scorecard: OwnerScorecard | None,
    market_expectations_manifest: MarketExpectationsPublicationManifest | None,
    runtime_gap_manifest: RuntimeGapPublicationManifest | None,
    futu_optional_data_disposition_manifests: tuple[
        FutuOptionalDataDispositionPublicationManifest, ...
    ],
) -> ResearchReportContent:
    bundle = research.result.bundle
    bundle_binding = _typed_binding(bundle)
    section_specs = list(_BASE_REPORT_SECTIONS)
    if profile == "full_valuation":
        section_specs.extend(_FULL_REPORT_SECTIONS)
    sections: dict[str, dict[str, object]] = {
        section_id: {
            "section_id": section_id,
            "title_zh": title_zh,
            "title_en": title_en,
            "status": "complete",
            "paragraphs": [],
        }
        for section_id, title_zh, title_en in section_specs
    }
    sections["decision_summary"]["paragraphs"].extend(
        _decision_summary_paragraphs(
            profile=profile,
            bundle=bundle,
            composite_valuation=composite_valuation,
            owner_scorecard=owner_scorecard,
            market_expectations_manifest=market_expectations_manifest,
            runtime_gap_manifest=runtime_gap_manifest,
        )
    )
    sections["sources_and_cutoff"]["paragraphs"].append(
        _object_paragraph("sources_and_cutoff", "source_index", research_source_manifest)
    )
    sections["evidence_audit_index"]["paragraphs"].append(
        _object_paragraph("evidence_audit_index", "run_manifests", research.result.run_manifest)
    )
    graph = research_source_index.graph
    paragraph_count = 2 + len(sections["decision_summary"]["paragraphs"])
    records: list[tuple[str, str, object]] = []
    for graph_field in fields(graph):
        if graph_field.name == "component_lock_path":
            continue
        for value in tuple(getattr(graph, graph_field.name)):
            section_id = _GRAPH_SECTION_MAP.get(graph_field.name, "evidence_audit_index")
            records.append((section_id, graph_field.name, value))
    prioritized: list[tuple[str, str, object]] = []
    selected: set[tuple[str, str]] = {
        (
            _typed_binding(value)["object_type"],
            _typed_binding(value)["object_id"],
        )
        for value in (bundle, research.result.run_manifest)
    }
    for section_id, _, _ in _BASE_REPORT_SECTIONS:
        match = next(
            (
                (candidate_section, collection, value)
                for candidate_section, collection, value in records
                if candidate_section == section_id
            ),
            None,
        )
        if match is not None:
            binding = _typed_binding(match[2])
            selected.add((binding["object_type"], binding["object_id"]))
            prioritized.append(match)
    for record in records:
        binding = _typed_binding(record[2])
        identity = (binding["object_type"], binding["object_id"])
        if identity not in selected:
            prioritized.append(record)
            selected.add(identity)
    record_sections = {section_id for section_id, _, _ in records}
    reserved_gap_paragraphs = sum(
        1
        for section_id, _, _ in _BASE_REPORT_SECTIONS
        if not sections[section_id]["paragraphs"] and section_id not in record_sections
    )
    reserved_full_paragraphs = (
        len(_FULL_REPORT_SECTIONS) + len(score_v2) if profile == "full_valuation" else 0
    )
    required_spec_paragraphs = sum(
        len(section["required_input_types"]) for section in report_spec.sections
    )
    base_paragraph_limit = (
        _CONTENT_PARAGRAPH_LIMIT
        - required_spec_paragraphs
        - reserved_full_paragraphs
        - reserved_gap_paragraphs
    )
    if base_paragraph_limit < 30:
        raise ResearchReportError("report specification leaves no substantive narrative capacity")
    for section_id, collection, value in prioritized:
        if paragraph_count >= base_paragraph_limit:
            break
        sections[section_id]["paragraphs"].append(_object_paragraph(section_id, collection, value))
        paragraph_count += 1
    for section_id, title_zh, title_en in _BASE_REPORT_SECTIONS:
        if not sections[section_id]["paragraphs"]:
            sections[section_id]["status"] = "partial"
            sections[section_id]["paragraphs"].append(
                _gap_paragraph(section_id, title_zh, title_en, bundle_binding)
            )
            paragraph_count += 1
    typed_records: dict[str, list[tuple[str, object]]] = {}
    for _, collection, value in records:
        typed_records.setdefault(type(value).__name__, []).append((collection, value))
    report_spec_statuses: list[str] = []
    for spec_section in report_spec.sections:
        raw_id = re.sub(r"[^a-z0-9_-]", "_", str(spec_section["section_id"]).lower())
        section_id = f"report_spec_{raw_id}"
        if section_id in sections:
            raise ResearchReportError("report specification section ID collides")
        title_zh = _clean_text(spec_section["title"])
        title_en = f"Report Specification: {raw_id}"
        spec_paragraphs: list[dict[str, object]] = []
        missing_required_types: list[str] = []
        for required_type in spec_section["required_input_types"]:
            required_type_name = str(required_type)
            matches = typed_records.get(required_type_name, ())
            if matches:
                collection, value = matches[0]
                spec_paragraphs.append(
                    _object_paragraph(
                        section_id,
                        f"report_spec_{raw_id}_{collection}",
                        value,
                    )
                )
                continue
            missing_required_types.append(required_type_name)
            spec_paragraphs.append(
                _paragraph(
                    section_id,
                    text_zh=(
                        f"报告规范要求本节包含 {required_type_name}，但冻结研究图截至 "
                        f"{bundle.data_cutoff_date} 未提供可验证对象；该输入保持 Unknown，"
                        "不得由其他类型或推断替代。"
                    ),
                    text_en=(
                        f"The report specification requires {required_type_name} in this "
                        f"section, but the frozen research graph provides no verifiable object "
                        f"through {bundle.data_cutoff_date}. The input remains Unknown and cannot "
                        "be replaced by another type or an inference."
                    ),
                    bindings=[_typed_binding(report_spec), bundle_binding],
                    missing_evidence=[f"required_input_type:{required_type_name}"],
                )
            )
        spec_status = "partial" if missing_required_types else "complete"
        report_spec_statuses.append(spec_status)
        sections[section_id] = {
            "section_id": section_id,
            "title_zh": title_zh,
            "title_en": title_en,
            "status": spec_status,
            "paragraphs": spec_paragraphs,
        }
        paragraph_count += len(spec_paragraphs)
    narrative_target = _CONTENT_PARAGRAPH_LIMIT - reserved_full_paragraphs
    if paragraph_count < narrative_target:
        for reference in bundle.module_references:
            if paragraph_count >= narrative_target:
                break
            sections["evidence_audit_index"]["paragraphs"].append(
                _paragraph(
                    "evidence_audit_index",
                    text_zh=(
                        f"研究模块 {_clean_text(reference['module_type'])} 的冻结状态为 "
                        f"{_clean_text(reference['module_status'])}，截止日为 "
                        f"{_clean_text(reference['as_of_date'])}，证据新鲜度为 "
                        f"{_clean_text(reference['freshness']['status'])}。"
                    ),
                    text_en=(
                        f"Frozen module {_clean_text(reference['module_type'])} has status "
                        f"{_clean_text(reference['module_status'])}, cutoff "
                        f"{_clean_text(reference['as_of_date'])}, and freshness "
                        f"{_clean_text(reference['freshness']['status'])}."
                    ),
                    bindings=[bundle_binding],
                    missing_evidence=list(reference["missing_evidence"]),
                )
            )
            paragraph_count += 1
    if paragraph_count < 30:
        raise ResearchReportError(
            "reviewed inputs cannot support 30 substantive report units without padding"
        )
    if profile == "full_valuation":
        assert valuation is not None
        assert composite_valuation is not None
        assert owner_scorecard is not None
        futu_context = futu_session_manifest or futu_partial_session_manifest
        assert futu_context is not None
        market_context = market_expectations_manifest or runtime_gap_manifest
        assert market_context is not None
        full_objects = (
            (
                "futu_vendor_validation",
                "futu_context_publication",
                futu_context,
            ),
            (
                "mckinsey_dcf_and_reverse",
                "valuation_run_archive",
                valuation.archive,
            ),
            (
                "forward_reoi",
                "forward_reoi_results",
                forward_reoi or runtime_gap_manifest,
            ),
            (
                "comparables",
                "comparable_results",
                comparable_valuation or runtime_gap_manifest,
            ),
            ("scenarios", "composite_scenarios", composite_valuation),
            ("composite_value_target", "composite_results", composite_valuation),
            ("sensitivity", "valuation_run_archive", valuation.archive),
            ("scorecard", "owner_scorecard", owner_scorecard),
            ("market_expectations", "market_expectations", market_context),
        )
        for section_id, collection, value in full_objects:
            assert value is not None
            if paragraph_count >= _CONTENT_PARAGRAPH_LIMIT:
                raise ResearchReportError("full report exceeds the substantive paragraph limit")
            if value is valuation.archive:
                binding = _typed_binding(
                    value,
                    object_type="ValuationRunArchive",
                    object_id=str(valuation.archive.manifest["archive_id"]),
                )
                section_title_zh = str(sections[section_id]["title_zh"])
                section_title_en = str(sections[section_id]["title_en"])
                text_zh = (
                    f"严格重载的六文件估值档案 {binding['object_id']} 已通过逐字节校验；"
                    f"{section_title_zh}只展示其冻结结果和计算路径，不重新计算或重绑输入。"
                )
                text_en = (
                    f"Strictly reloaded six-file valuation archive {binding['object_id']} passed "
                    f"byte-exact validation; {section_title_en} does not recalculate or rebind it."
                )
                paragraph = _paragraph(
                    section_id,
                    text_zh=text_zh,
                    text_en=text_en,
                    bindings=[binding],
                )
            elif value is composite_valuation and composite_valuation.status != "complete":
                binding = _typed_binding(composite_valuation)
                gap_binding = (
                    [] if runtime_gap_manifest is None else [_typed_binding(runtime_gap_manifest)]
                )
                section_title_zh = str(sections[section_id]["title_zh"])
                section_title_en = str(sections[section_id]["title_en"])
                text_zh, text_en = _composite_ineligible_narrative(
                    composite_valuation,
                    section_title_zh=section_title_zh,
                    section_title_en=section_title_en,
                )
                paragraph = _paragraph(
                    section_id,
                    text_zh=text_zh,
                    text_en=text_en,
                    bindings=[binding, *gap_binding],
                    missing_evidence=list(composite_valuation.issue_codes),
                )
            else:
                paragraph = _object_paragraph(section_id, collection, value)
            sections[section_id]["paragraphs"].append(paragraph)
            paragraph_count += 1
        if forward_reoi is None:
            sections["forward_reoi"]["status"] = "blocked"
        if comparable_valuation is None:
            sections["comparables"]["status"] = "blocked"
        if (
            market_expectations_manifest is None
            or market_expectations_manifest.status != "complete"
        ):
            sections["market_expectations"]["status"] = "partial"
            sections["composite_value_target"]["status"] = "partial"
        for score in sorted(score_v2, key=lambda item: item.lens):
            if paragraph_count >= _CONTENT_PARAGRAPH_LIMIT:
                raise ResearchReportError("full report exceeds the substantive paragraph limit")
            sections["scorecard"]["paragraphs"].append(
                _object_paragraph("scorecard", f"score_v2_{score.lens}", score)
            )
            paragraph_count += 1
        sections["scorecard"]["status"] = _retained_scorecard_status(
            score_v2,
            owner_scorecard,
        )
    status = bundle.status if bundle.status in {"complete", "partial", "blocked"} else "partial"
    if status == "complete" and any(item != "complete" for item in report_spec_statuses):
        status = "partial"
    if profile == "full_valuation" and composite_valuation is not None:
        if composite_valuation.status == "blocked":
            status = "blocked"
        elif composite_valuation.status != "complete" and status == "complete":
            status = "partial"
        elif (
            market_expectations_manifest is None
            or market_expectations_manifest.status != "complete"
        ) and status == "complete":
            status = "partial"
    if profile == "full_valuation":
        status = _content_status_with_scorecard(
            status,
            str(sections["scorecard"]["status"]),
        )
    tables = _report_content_tables(
        research_source_index,
        research_source_manifest,
        research,
        valuation,
        forward_reoi,
        comparable_valuation,
        composite_valuation,
        score_v2,
        owner_scorecard,
        market_expectations_manifest,
        runtime_gap_manifest,
        futu_optional_data_disposition_manifests,
    )
    charts = _report_content_charts(
        research_source_index,
        research,
        valuation,
        composite_valuation,
        score_v2,
        market_expectations_manifest,
        runtime_gap_manifest,
    )
    section_rows = list(sections.values())
    all_bindings = [
        binding
        for section in section_rows
        for paragraph in section["paragraphs"]
        for binding in paragraph["bindings"]
    ]
    all_bindings.extend(binding for table in tables for binding in table["bindings"])
    all_bindings.extend(
        point["binding"]
        for chart in charts
        for series in chart["series"]
        for point in series["points"]
    )
    substantive_units = (
        sum(len(section["paragraphs"]) for section in section_rows)
        + sum(len(table["rows"]) for table in tables)
        + sum(len(series["points"]) for chart in charts for series in chart["series"])
    )
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "artifact_type": "research-report-content",
        "profile": profile,
        "status": status,
        "issuer_id": bundle.issuer_id,
        "data_cutoff_date": bundle.data_cutoff_date,
        "research_source_index_fingerprint": research_source_index.fingerprint,
        "valuation_archive_fingerprint": (
            None if valuation is None else valuation.archive.fingerprint
        ),
        "sections": section_rows,
        "tables": tables,
        "charts": charts,
        "paragraph_count": sum(len(section["paragraphs"]) for section in section_rows),
        "distinct_paragraph_count": len(
            {
                canonical_json(
                    {
                        "text_zh": paragraph["text_zh"],
                        "text_en": paragraph["text_en"],
                    }
                )
                for section in section_rows
                for paragraph in section["paragraphs"]
            }
        ),
        "anti_padding_method": "unique-evidence-bound-narrative-v1",
        "substantive_unit_count": substantive_units,
        "binding_fingerprints": sorted({item["fingerprint"] for item in all_bindings}),
    }
    payload["content_fingerprint"] = canonical_sha256(payload)
    return ResearchReportContent(payload)


def _score_table(
    legacy_scores: tuple[Score, ...],
    score_v2: tuple[ScoreV2, ...] = (),
) -> str:
    rows = [
        r"\begin{longtable}{>{\raggedright\arraybackslash}p{0.23\textwidth}rrp{0.42\textwidth}}",
        r"\toprule",
        r"维度 & 得分 & 满分 & 依据与限制 \\",
        r"\midrule",
        r"\endhead",
    ]
    if score_v2:
        for score in sorted(score_v2, key=lambda item: item.lens):
            for component in score.components:
                score_text = "Unknown" if component["score"] is None else component["score"]
                rationale = str(component["rationale"])
                if component["missing_evidence"]:
                    rationale += "；缺口：" + "；".join(component["missing_evidence"])
                if component["red_flags"]:
                    rationale += "；红旗：" + "；".join(
                        str(item["code"]) for item in component["red_flags"]
                    )
                rows.append(
                    f"{_latex(score.lens + '/' + component['component_id'])} & "
                    f"{_latex(score_text)} & 20 & {_latex(rationale)} \\\\"
                )
    elif legacy_scores:
        for score in sorted(
            legacy_scores,
            key=lambda item: (item.framework, item.component, item.score_id),
        ):
            rationale = score.rationale
            if score.missing_evidence:
                rationale += "；缺口：" + "；".join(score.missing_evidence)
            if score.red_flags:
                rationale += "；红旗：" + "；".join(score.red_flags)
            rows.append(
                f"{_latex(score.component)} & {score.score:g} & {score.max_score:g} & "
                f"{_latex(rationale)} \\\\"
            )
    else:
        rows.append(r"未执行评分 & Unknown & 100 & 仅研究报告不生成四镜评分。 \\")
    rows.extend((r"\bottomrule", r"\end{longtable}"))
    return "\n".join(rows) + "\n"


def _score_chart(
    legacy_scores: tuple[Score, ...],
    score_v2: tuple[ScoreV2, ...] = (),
) -> str:
    lines = [r"\begin{center}", r"\begin{tabular}{p{0.28\textwidth}p{0.58\textwidth}}"]
    if score_v2:
        for score in sorted(score_v2, key=lambda item: item.lens):
            total = Decimal(score.total_score) if score.total_score is not None else None
            width = round(9.0 * float(total / Decimal(100)), 3) if total is not None else 0
            label = "Unknown/100" if total is None else f"{score.total_score}/100"
            lines.append(
                f"{_latex(score.lens)} & "
                f"{{\\color{{OwnerBlue}}\\rule{{{width}cm}}{{2.6mm}}}} "
                f"{_latex(label)} \\\\"
            )
    elif legacy_scores:
        for score in sorted(
            legacy_scores,
            key=lambda item: (item.framework, item.component, item.score_id),
        ):
            ratio = min(1.0, max(0.0, score.score / score.max_score))
            width = round(9.0 * ratio, 3)
            lines.append(
                f"{_latex(score.component)} & "
                f"{{\\color{{OwnerBlue}}\\rule{{{width}cm}}{{2.6mm}}}} "
                f"{score.score:g}/{score.max_score:g} \\\\"
            )
    else:
        lines.append(r"未评分 & {\color{OwnerBlue}\rule{0cm}{2.6mm}} 未生成 \\")
    lines.extend((r"\end{tabular}", r"\end{center}"))
    return "\n".join(lines) + "\n"


def _report_payload(
    profile: str,
    research: ReloadedResearchInput,
    valuation: ReloadedValuationInput | None,
    report_spec: ReportSpec,
    content: ResearchReportContent,
    research_source_manifest: ResearchSourceIndexPublicationManifest,
    legacy_scores: tuple[Score, ...],
    futu_session_manifest: FutuSessionPublicationManifest | None,
    futu_partial_session_manifest: FutuPartialSessionPublicationManifest | None,
    forward_reoi: ForwardReOIValuationResult | None,
    comparable_valuation: ComparableValuationResult | None,
    composite_valuation: CompositeValuationResult | None,
    score_v2: tuple[ScoreV2, ...],
    owner_scorecard: OwnerScorecard | None,
    market_expectations_manifest: MarketExpectationsPublicationManifest | None,
    runtime_gap_manifest: RuntimeGapPublicationManifest | None,
    futu_optional_data_disposition_manifests: tuple[
        FutuOptionalDataDispositionPublicationManifest, ...
    ],
    forward_reoi_manifest: ForwardReOIValuationPublicationManifest | None,
    comparable_valuation_manifest: ComparableValuationPublicationManifest | None,
    composite_valuation_manifest: CompositeValuationPublicationManifest | None,
    score_v2_manifests: tuple[ScoreV2PublicationManifest, ...],
    owner_scorecard_manifest: OwnerScorecardPublicationManifest | None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "artifact_type": "research-report-data",
        "profile": profile,
        "issuer_id": research.result.bundle.issuer_id,
        "data_cutoff_date": research.result.bundle.data_cutoff_date,
        "research_bundle": research.result.bundle.to_dict(),
        "research_run_manifest": research.result.run_manifest.to_dict(),
        "research_source_index": research_source_manifest.to_dict(),
        "report_spec": report_spec.to_dict(),
        "report_content": content.to_dict(),
        "legacy_scores": [score.to_dict() for score in legacy_scores],
    }
    if profile == "full_valuation":
        assert valuation is not None
        assert composite_valuation_manifest is not None
        assert owner_scorecard_manifest is not None
        payload.update(
            {
                "valuation_manifest": to_json_value(valuation.archive.manifest),
                "valuation_result": to_json_value(valuation.archive.result_payload),
                "futu_session_publication_manifest": (
                    None if futu_session_manifest is None else futu_session_manifest.to_dict()
                ),
                "futu_partial_session_publication_manifest": (
                    None
                    if futu_partial_session_manifest is None
                    else futu_partial_session_manifest.to_dict()
                ),
                "futu_optional_data_disposition_publication_manifests": [
                    item.to_dict()
                    for item in futu_optional_data_disposition_manifests
                ],
                "forward_reoi_publication_manifest": (
                    None if forward_reoi_manifest is None else forward_reoi_manifest.to_dict()
                ),
                "comparable_valuation_publication_manifest": (
                    None
                    if comparable_valuation_manifest is None
                    else comparable_valuation_manifest.to_dict()
                ),
                "composite_valuation_publication_manifest": (
                    composite_valuation_manifest.to_dict()
                ),
                "score_v2_publication_manifests": [item.to_dict() for item in score_v2_manifests],
                "owner_scorecard_publication_manifest": (owner_scorecard_manifest.to_dict()),
                "market_expectations": (
                    None
                    if market_expectations_manifest is None
                    else market_expectations_manifest.to_dict()
                ),
                "runtime_gap_publication_manifest": (
                    None if runtime_gap_manifest is None else runtime_gap_manifest.to_dict()
                ),
            }
        )
    return payload


def _report_markdown(payload: Mapping[str, object]) -> str:
    content = payload["report_content"]
    assert isinstance(content, dict)
    lines = [
        "# 所有者视角综合研究报告",
        "",
        f"- 发行人：{_clean_text(payload['issuer_id'])}",
        f"- 数据截止日：{_clean_text(payload['data_cutoff_date'])}",
        f"- 报告配置：{_clean_text(payload['profile'])}",
        f"- 内容状态：{_clean_text(content['status'])}",
        f"- 内容指纹：{_clean_text(content['content_fingerprint'])}",
    ]
    for section in content["sections"]:
        lines.extend(
            (
                "",
                f"## {_clean_text(section['title_zh'])} / {_clean_text(section['title_en'])}",
                "",
            )
        )
        for paragraph in section["paragraphs"]:
            lines.append(_professionalize_numeric_tokens(paragraph["text_zh"]))
            lines.extend(
                ("", _professionalize_numeric_tokens(paragraph["text_en"]), "")
            )
            missing = paragraph["missing_evidence"]
            if missing:
                lines.append("证据缺口 / Evidence gaps: " + "；".join(missing))
    return "\n".join(lines) + "\n"


@_uses_report_decimal_context
def _content_tables_tex(content: ResearchReportContent) -> str:
    lines: list[str] = []
    compact_full_valuation = content["profile"] == "full_valuation"
    section_order = {
        str(section["section_id"]): index
        for index, section in enumerate(content["sections"])
    }
    ordered_tables = sorted(
        enumerate(content["tables"]),
        key=lambda item: (section_order[str(item[1]["section_id"])], item[0]),
    )
    for _, table in ordered_tables:
        column_count = len(table["columns"])
        font_command = (
            r"\scriptsize"
            if compact_full_valuation and column_count >= 4
            else r"\footnotesize"
            if compact_full_valuation and column_count == 3
            else r"\small"
        )
        lines.extend(
            (
                f"\\subsection*{{{_latex(table['title_zh'])} / {_latex(table['title_en'])}}}",
                rf"\begingroup{font_command}\sloppy",
            )
        )
        if column_count >= 3 and not compact_full_valuation:
            for row_index, row in enumerate(table["rows"], start=1):
                for start in range(0, column_count, 8):
                    stop = min(start + 8, column_count)
                    suffix = "" if column_count <= 8 else f" ({start + 1}-{stop})"
                    lines.extend(
                        (
                            r"\noindent\begin{minipage}{0.98\textwidth}",
                            (
                                r"\textcolor{OwnerNavy}{\textbf{记录 / Record "
                                + str(row_index)
                                + _latex(suffix)
                                + r"}}\par\smallskip"
                            ),
                            (
                                r"\begin{tabular}{@{}>{\raggedright\arraybackslash}"
                                r"p{0.26\textwidth}@{\hspace{0.65em}}"
                                r">{\raggedright\arraybackslash}p{0.66\textwidth}@{}}"
                            ),
                            r"\toprule",
                            r"字段 / Field & 值 / Value \\",
                            r"\midrule",
                        )
                    )
                    for column_index in range(start, stop):
                        lines.append(
                            _latex_table_cell(table["columns"][column_index])
                            + " & "
                            + _latex_table_cell(row[column_index])
                            + r" \\"
                        )
                    lines.extend(
                        (
                            r"\bottomrule",
                            r"\end{tabular}",
                            r"\end{minipage}\par\medskip",
                        )
                    )
            lines.extend((r"\endgroup", r"\medskip"))
            continue
        preferred_cap = 24 if column_count >= 3 else 30
        total_width = Decimal("0.88")
        preferred_widths = tuple(
            max(
                7,
                min(
                    preferred_cap,
                    max(
                        len(_clean_text(table["columns"][column_index])),
                        *(len(_clean_text(row[column_index])) for row in table["rows"]),
                    ),
                ),
            )
            for column_index in range(column_count)
        )
        preferred_total = sum(preferred_widths)
        widths = tuple(
            total_width * Decimal(preferred) / Decimal(preferred_total)
            for preferred in preferred_widths
        )
        columns = tuple(
            f">{{\\raggedright\\arraybackslash}}p{{{width.quantize(Decimal('0.001'))}\\textwidth}}"
            for width in widths
        )
        preamble = "@{}" + r"@{\hspace{0.65em}}".join(columns) + "@{}"
        cell_chunk_size = 4 if compact_full_valuation and column_count >= 3 else 8
        lines.extend(
            (
                f"\\begin{{longtable}}{{{preamble}}}",
                r"\toprule",
                " & ".join(
                    _latex_table_cell(item, chunk_size=cell_chunk_size)
                    for item in table["columns"]
                )
                + r" \\",
                r"\midrule",
                r"\endhead",
            )
        )
        for row in table["rows"]:
            lines.append(
                " & ".join(
                    _latex_table_cell(cell, chunk_size=cell_chunk_size) for cell in row
                )
                + r" \\"
            )
        lines.extend(
            (r"\bottomrule", r"\end{longtable}", r"\endgroup", r"\medskip")
        )
    return "\n".join(lines) + "\n"


@_uses_report_decimal_context
def _content_charts_tex(content: ResearchReportContent) -> str:
    lines: list[str] = []
    section_order = {
        str(section["section_id"]): index
        for index, section in enumerate(content["sections"])
    }
    ordered_charts = sorted(
        enumerate(content["charts"]),
        key=lambda item: (section_order[str(item[1]["section_id"])], item[0]),
    )
    for _, chart in ordered_charts:
        lines.append(f"\\subsection*{{{_latex(chart['title_zh'])} / {_latex(chart['title_en'])}}}")
        for series in chart["series"]:
            values: list[Decimal] = []
            for point in series["points"]:
                try:
                    parsed = Decimal(str(point["value"]))
                except (InvalidOperation, TypeError):
                    continue
                if parsed.is_finite():
                    values.append(abs(parsed))
            maximum = max(values, default=Decimal(0))
            lines.extend(
                (
                    f"\\paragraph{{{_latex(series['name'])}}}",
                    r"\noindent\footnotesize{红色向左为负值，蓝色向右为正值；"
                    r" Red-left is negative and blue-right is positive.}\par",
                    r"\begin{longtable}{"
                    r">{\raggedright\arraybackslash}p{0.31\textwidth}"
                    r">{\raggedleft\arraybackslash}p{0.21\textwidth}"
                    r"@{\hspace{0.35em}{\color{OwnerGray}\vrule width 0.35pt}\hspace{0.35em}}"
                    r">{\raggedright\arraybackslash}p{0.21\textwidth}"
                    r">{\raggedleft\arraybackslash}p{0.14\textwidth}}",
                )
            )
            for point in series["points"]:
                value = point["value"]
                try:
                    parsed = Decimal(str(value))
                except (InvalidOperation, TypeError):
                    parsed = None
                width = Decimal(0)
                if parsed is not None and parsed.is_finite() and maximum > 0:
                    width = min(Decimal("3.2"), abs(parsed) / maximum * Decimal("3.2"))
                label = (
                    "Unknown"
                    if parsed is None or not parsed.is_finite()
                    else _professional_decimal_text(parsed)
                )
                negative_bar = ""
                positive_bar = ""
                if parsed is not None and parsed.is_finite():
                    bar = (
                        r"\rule{"
                        + f"{width.quantize(Decimal('0.001'))}cm"
                        + r"}{2.6mm}"
                    )
                    if parsed < 0:
                        negative_bar = r"{\color{OwnerRed}" + bar + "}"
                    elif parsed > 0:
                        positive_bar = r"{\color{OwnerBlue}" + bar + "}"
                lines.append(
                    f"{_latex_table_cell(point['label'])} & {negative_bar} & "
                    f"{positive_bar} & {_latex_table_cell(label)} \\\\"
                )
            lines.extend((r"\end{longtable}", r"\medskip"))
    return "\n".join(lines) + "\n"


@_uses_report_decimal_context
def _content_charts_svg(content: ResearchReportContent) -> bytes:
    """Create a standalone deterministic chart atlas without a plotting runtime."""

    charts = list(content["charts"])
    rows: list[tuple[Mapping[str, object], Mapping[str, object]]] = []
    for chart in charts:
        for series in chart["series"]:
            rows.extend((chart, point) for point in series["points"])
    height = max(240, 90 + len(charts) * 62 + len(rows) * 34)
    zero_x = Decimal(720)
    maximum_bar_width = Decimal(250)
    cursor_y = 46
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        (
            f'<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="{height}" '
            f'viewBox="0 0 1200 {height}" role="img" '
            'aria-labelledby="chart-atlas-title chart-atlas-description">'
        ),
        '<title id="chart-atlas-title">Owner Equity Research chart atlas</title>',
        (
            '<desc id="chart-atlas-description">Deterministic evidence-bound charts; '
            'negative values extend left in red and positive values extend right in blue.</desc>'
        ),
        f'<metadata>content-fingerprint:{html.escape(content.fingerprint)}</metadata>',
        f'<rect x="0" y="0" width="1200" height="{height}" fill="#FFFFFF"/>',
        (
            '<text x="48" y="34" font-family="Noto Sans CJK SC, sans-serif" '
            'font-size="24" font-weight="700" fill="#17324D">模型图表 / Model Charts</text>'
        ),
    ]
    for chart in charts:
        title = f"{_clean_text(chart['title_zh'])} / {_clean_text(chart['title_en'])}"
        lines.append(
            f'<text x="48" y="{cursor_y + 32}" font-family="Noto Sans CJK SC, sans-serif" '
            f'font-size="18" font-weight="700" fill="#17324D">{html.escape(title)}</text>'
        )
        cursor_y += 54
        for series in chart["series"]:
            values = []
            for point in series["points"]:
                try:
                    parsed = Decimal(str(point["value"]))
                except (InvalidOperation, TypeError):
                    continue
                if parsed.is_finite():
                    values.append(abs(parsed))
            maximum = max(values, default=Decimal(0))
            series_name = _clean_text(series["name"])
            lines.append(
                f'<text x="66" y="{cursor_y + 16}" font-family="Noto Sans CJK SC, sans-serif" '
                f'font-size="13" fill="#5B6573">{html.escape(series_name)}</text>'
            )
            cursor_y += 28
            for point in series["points"]:
                label = _clean_text(point["label"])
                visible_label = label if len(label) <= 50 else label[:47] + "..."
                value_text = "Unknown" if point["value"] is None else _clean_text(point["value"])
                try:
                    parsed = Decimal(str(point["value"]))
                except (InvalidOperation, TypeError):
                    parsed = None
                width = Decimal(0)
                if parsed is not None and parsed.is_finite() and maximum > 0:
                    width = abs(parsed) / maximum * maximum_bar_width
                width_text = format(width.quantize(Decimal("0.1")), "f")
                if parsed is not None and parsed < 0:
                    x = zero_x - width
                    fill = "#B0443E"
                    sign = "negative"
                else:
                    x = zero_x
                    fill = "#2F6690" if parsed is not None and parsed > 0 else "#9AA3AD"
                    sign = "positive" if parsed is not None and parsed > 0 else "zero-or-unknown"
                x_text = format(x.quantize(Decimal("0.1")), "f")
                lines.extend(
                    (
                        f'<title>{html.escape(label)} = {html.escape(value_text)}</title>',
                        f'<text x="78" y="{cursor_y + 17}" '
                        'font-family="Noto Sans CJK SC, sans-serif" font-size="12" '
                        f'fill="#273746">{html.escape(visible_label)}</text>',
                        f'<line x1="{zero_x}" y1="{cursor_y}" x2="{zero_x}" '
                        f'y2="{cursor_y + 22}" stroke="#5B6573" stroke-width="1"/>',
                        f'<rect data-sign="{sign}" x="{x_text}" y="{cursor_y + 4}" '
                        f'width="{width_text}" height="14" fill="{fill}"/>',
                        f'<text x="1000" y="{cursor_y + 17}" text-anchor="end" '
                        'font-family="Noto Sans CJK SC, sans-serif" font-size="12" '
                        f'fill="#273746">{html.escape(value_text)}</text>',
                    )
                )
                cursor_y += 30
        cursor_y += 18
    lines.append("</svg>")
    return ("\n".join(lines) + "\n").encode("utf-8")


def _report_data_tex(content: ResearchReportContent) -> str:
    lines = [
        f"\\newcommand{{\\ReportIssuer}}{{{_latex(content['issuer_id'])}}}",
        r"\begin{titlepage}",
        r"\centering",
        r"\vspace*{35mm}",
        r"{\Huge\bfseries\color{OwnerNavy} 所有者视角综合研究报告\par}",
        r"\vspace{12mm}",
        rf"{{\Large {_latex(content['issuer_id'])}\par}}",
        r"\vspace{5mm}",
        rf"{{\large 数据截止日：{_latex(content['data_cutoff_date'])}\par}}",
        rf"{{\large 配置：{_latex(content['profile'])}\par}}",
        r"\vfill",
        r"{\small 证据有界、结果可重放、缺口不猜测\par}",
        r"\end{titlepage}",
        r"\setcounter{page}{2}",
        (
            r"\begingroup\small\tableofcontents\endgroup"
            if content["profile"] == "full_valuation"
            else r"\tableofcontents"
        ),
        r"\clearpage",
    ]
    for section in content["sections"]:
        lines.append(r"\par\bigskip\pagebreak[1]")
        title = f"{section['title_zh']} / {section['title_en']}"
        lines.append(f"\\section[{_latex(title)}]{{{_latex(title)}}}")
        for paragraph in section["paragraphs"]:
            lines.extend(
                (
                    _latex_prose(paragraph["text_zh"]) + r"\par",
                    r"{\color{OwnerGray}\small\noindent "
                    + _latex_prose(paragraph["text_en"])
                    + r"\par}\nopagebreak[4]",
                )
            )
            if paragraph["missing_evidence"]:
                lines.append(
                    r"\noindent\textbf{证据缺口 / Evidence gaps: }"
                    + _latex_prose("；".join(paragraph["missing_evidence"]))
                    + r"\par\nopagebreak[4]"
                )
            references = "；".join(_binding_label(item) for item in paragraph["bindings"])
            lines.append(
                r"{\footnotesize\color{OwnerGray}\noindent "
                r"证据绑定 / Evidence binding: "
                + _latex(references)
                + r"\par}"
            )
    lines.extend(
        (
            r"\par\bigskip\pagebreak[2]",
            r"\section{数据表 / Data Tables}",
            r"\input{report-table.tex}",
            r"\par\bigskip\pagebreak[2]",
            r"\section{模型图表 / Model Charts}",
            r"\input{report-chart.tex}",
            r"\par\bigskip\pagebreak[2]",
            r"\section{证据绑定附录 / Evidence Binding Appendix}",
            (
                r"\noindent 本附录保留报告中每项类型化证据的完整对象标识和 SHA-256。"
                r"正文仅显示人类可读标签与短摘要，以避免长标识越界；完整值仍可逐字节复核。\par"
            ),
            (
                r"\noindent This appendix preserves every typed evidence object's full identifier "
                r"and SHA-256. The body uses a human-readable label and short digest while this "
                r"table retains the complete auditable value.\par"
            ),
            r"\begingroup\footnotesize\sloppy",
            r"\setlength{\baselineskip}{8.5pt}",
            r"\setlength{\LTpre}{0.45em}",
            r"\setlength{\LTpost}{0.2em}",
            r"\renewcommand{\arraystretch}{0.94}",
        )
    )
    evidence_table_header = (
        (
            r"\begin{longtable}{@{}"
            r">{\raggedright\arraybackslash}p{0.18\textwidth}"
            r"@{\hspace{0.25em}}"
            r">{\raggedright\arraybackslash}p{0.43\textwidth}"
            r"@{\hspace{0.25em}}"
            r">{\raggedright\arraybackslash}p{0.33\textwidth}@{}}"
        ),
        r"\toprule",
        r"类型 / Type & 对象标识 / Object ID & SHA-256 \\",
        r"\midrule",
        r"\endfirsthead",
        r"\toprule",
        r"类型 / Type & 对象标识 / Object ID & SHA-256 \\",
        r"\midrule",
        r"\endhead",
        r"\endfoot",
        r"\bottomrule",
        r"\endlastfoot",
    )
    evidence_bindings = _report_evidence_bindings(content)
    # Keep the last six records together inside the same longtable.  This lets
    # TeX fill all earlier pages naturally while preventing a lone trailing
    # audit record; unlike a forced table split it cannot create a sparse page
    # immediately before the tail.
    keep_together_start = (
        len(evidence_bindings) - 6 if len(evidence_bindings) > 24 else len(evidence_bindings)
    )
    lines.extend(evidence_table_header)
    for index, binding in enumerate(evidence_bindings):
        keep_with_next = keep_together_start <= index < len(evidence_bindings) - 1
        lines.append(
            _latex_camel_breakable(binding["object_type"])
            + r" & "
            + _latex_breakable(binding["object_id"], chunk_size=4)
            + r" & "
            + _latex_breakable(binding["fingerprint"], chunk_size=4)
            + (r" \\*[0.28em]" if keep_with_next else r" \\[0.28em]")
        )
    lines.extend((r"\end{longtable}", r"\endgroup"))
    return "\n".join(lines) + "\n"


class LatexReportRenderer:
    """Pre-authorized offline Tectonic renderer with independent PDF QA."""

    def __init__(
        self,
        *,
        engine: str = "tectonic",
        timeout_seconds: int = 240,
        authority: ReportToolchainAuthority | None = None,
    ) -> None:
        if engine != "tectonic":
            raise ResearchReportError("the locked report renderer is Tectonic only")
        if type(timeout_seconds) is not int or timeout_seconds < 1 or timeout_seconds > 900:
            raise ResearchReportError("renderer timeout must be between 1 and 900 seconds")
        self.engine = engine
        self.timeout_seconds = timeout_seconds
        packaged_authority = load_report_toolchain_authority()
        self.authority = authority or packaged_authority
        if type(self.authority) is not ReportToolchainAuthority:
            raise ResearchReportError("renderer requires exact ReportToolchainAuthority")
        if self.authority.to_dict() != packaged_authority.to_dict():
            raise ResearchReportError(
                "renderer authority differs from the packaged pre-trusted authority"
            )
        self._tectonic_cache: str | None = None
        self._tectonic_cache_fingerprint: str | None = None

    def _runtime_authority(
        self,
    ) -> tuple[_TrustedExecutableSnapshot, _TrustedTectonicCacheSnapshot]:
        tectonic = _trusted_executable("tectonic")
        renderer_authority = to_json_value(self.authority["renderer"])
        expected_cache = to_json_value(self.authority["offline_bundle"])
        cache = _tectonic_cache_snapshot_for_authority(
            _trusted_tectonic_cache(),
            expected_cache,
        )
        if (
            not isinstance(renderer_authority, dict)
            or renderer_authority.get("engine") != "tectonic"
            or renderer_authority.get("basename") != Path(tectonic.source_path).name
            or renderer_authority.get("sha256") != tectonic.sha256
            or renderer_authority.get("size") != tectonic.size
            or {
                "tree_sha256": cache.tree_sha256,
                "member_count": cache.member_count,
                "total_bytes": cache.total_bytes,
            }
            != expected_cache
            or _distribution_tree_identity("pypdf")
            != to_json_value(self.authority["pdf_text_backend"])
            or _distribution_tree_identity("pypdfium2")
            != to_json_value(self.authority["pdf_render_backend"])
        ):
            raise ResearchReportError("runtime report toolchain differs from pre-trusted authority")
        return tectonic, cache

    def _command(
        self,
        *,
        executable_path: str,
        cache_path: str,
        cache_fingerprint: str,
    ) -> tuple[list[str], str, str]:
        self._tectonic_cache = cache_path
        self._tectonic_cache_fingerprint = cache_fingerprint
        return (
            [
                executable_path,
                "--only-cached",
                "--untrusted",
                "--keep-logs",
                "--reruns",
                "1",
                "--outdir",
                ".",
                "report.tex",
            ],
            "tectonic",
            (
                f"tectonic:sha256:{self.authority['renderer']['sha256']}:"
                f"cache-sha256:{cache_fingerprint}:"
                f"authority:{self.authority.fingerprint}"
            ),
        )

    def render(self, tex_sources: Mapping[str, bytes]) -> PdfRenderResult:
        required = {"report.tex", "report-data.tex", "report-table.tex", "report-chart.tex"}
        if set(tex_sources) != required:
            raise ResearchReportError("renderer requires exactly the registered TeX sources")
        for name, content in tex_sources.items():
            _validate_relative_path(name)
            if type(content) is not bytes or not content or len(content) > REPORT_TEXT_MAX_BYTES:
                raise ResearchReportError("renderer source is empty or exceeds its byte limit")
        executable_snapshot, cache_snapshot = self._runtime_authority()
        try:
            with tempfile.TemporaryDirectory(prefix="owner-report-pdf-") as temporary:
                workspace = Path(temporary).resolve(strict=True)
                workspace.chmod(0o700)
                staged_executable, staged_cache = _stage_report_toolchain(
                    workspace,
                    executable_snapshot,
                    cache_snapshot,
                )
                command, engine, renderer_id = self._command(
                    executable_path=staged_executable,
                    cache_path=staged_cache,
                    cache_fingerprint=cache_snapshot.tree_sha256,
                )
                environment = _closed_renderer_environment(
                    workspace,
                    command[0],
                    tectonic_cache=self._tectonic_cache if engine == "tectonic" else None,
                )
                version_result = _run_private_subprocess(
                    [command[0], "--version"],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    env=environment,
                )
                renderer_version = version_result.stdout.strip().splitlines()[0]
                if renderer_version != self.authority["renderer"]["version"]:
                    raise ResearchReportError(
                        "runtime renderer version differs from pre-trusted authority"
                    )
                for name, content in tex_sources.items():
                    (workspace / name).write_bytes(content)
                font_name, font_bytes = _trusted_font_asset()
                (workspace / font_name).write_bytes(font_bytes)
                completed = _run_private_subprocess(
                    command,
                    cwd=workspace,
                    env=environment,
                    check=False,
                    capture_output=True,
                    timeout=self.timeout_seconds,
                )
                if completed.returncode != 0:
                    diagnostic_sha256 = hashlib.sha256(
                        (completed.stdout + completed.stderr)[-32768:]
                    ).hexdigest()
                    raise ResearchReportError(
                        "LaTeX rendering failed "
                        f"(exit={completed.returncode}, diagnostic_sha256={diagnostic_sha256})"
                    )
                pdf_path = workspace / "report.pdf"
                if not pdf_path.is_file() or pdf_path.is_symlink():
                    raise ResearchReportError("LaTeX renderer did not create report.pdf")
                pdf_bytes = _read_bounded_regular_file(
                    pdf_path,
                    limit=REPORT_PDF_MAX_BYTES,
                    label="rendered PDF",
                )
                replayed_qa = replay_report_pdf_qa(
                    pdf_bytes,
                    authority=self.authority,
                )
                return PdfRenderResult(
                    pdf_bytes=pdf_bytes,
                    page_count=replayed_qa.page_count,
                    extracted_text=replayed_qa.extracted_text,
                    rendered_page_count=replayed_qa.page_count,
                    renderer_id=renderer_id,
                    renderer_version=renderer_version,
                    engine=engine,
                    toolchain_authority_id=self.authority.authority_id,
                    toolchain_authority_fingerprint=self.authority.fingerprint,
                    page_text_character_counts=replayed_qa.page_text_character_counts,
                    rendered_page_sha256=replayed_qa.rendered_page_sha256,
                    page_non_white_ratios=replayed_qa.page_non_white_ratios,
                )
        except (OSError, subprocess.SubprocessError, UnicodeError) as exc:
            raise ResearchReportError(f"PDF rendering or QA failed: {exc}") from exc


def _anti_padding_render_metrics(
    result: PdfRenderResult,
    content: ResearchReportContent,
) -> dict[str, object]:
    extracted_text = result.extracted_text
    normalized_render = re.sub(r"[^0-9A-Za-z\u4e00-\u9fff]+", "", extracted_text)
    paragraph_texts = [
        re.sub(r"[^0-9A-Za-z\u4e00-\u9fff]+", "", str(paragraph["text_zh"]))
        for section in content["sections"]
        for paragraph in section["paragraphs"]
    ]
    verified_tokens: list[str] = []
    for index, paragraph_text in enumerate(paragraph_texts):
        token = ""
        for length in range(24, min(len(paragraph_text), 160) + 1, 8):
            candidate = paragraph_text[:length]
            if sum(item.startswith(candidate) for item in paragraph_texts) == 1:
                token = candidate
                break
        if not token:
            token = paragraph_text
        if len(token) < 24 or normalized_render.count(token) != 1:
            raise ResearchReportError(
                f"rendered PDF omits or repeats substantive paragraph {index + 1}"
            )
        verified_tokens.append(token)
    if (
        len(verified_tokens) < 30
        or len(verified_tokens) != len(set(verified_tokens))
        or "本附录仅重复" in extracted_text
        or "audit padding" in extracted_text.lower()
    ):
        raise ResearchReportError("rendered PDF failed anti-padding narrative QA")
    counts = result.page_text_character_counts
    if len(counts) != result.page_count or any(
        type(value) is not int or value < 0 for value in counts
    ):
        raise ResearchReportError("rendered PDF lacks exact per-page text-density evidence")
    blank_pages = [index + 1 for index, value in enumerate(counts) if value == 0]
    low_density_pages = [
        index + 1
        for index, value in enumerate(counts)
        if index > 0 and value < REPORT_MIN_NON_COVER_CHARACTERS
    ]
    if blank_pages or low_density_pages:
        raise ResearchReportError(
            "rendered PDF contains blank or low-density non-cover pages "
            f"(blank={blank_pages}, low_density={low_density_pages})"
        )
    if (
        len(result.rendered_page_sha256) != result.page_count
        or any(re.fullmatch(r"[a-f0-9]{64}", item) is None for item in result.rendered_page_sha256)
        or len(result.page_non_white_ratios) != result.page_count
    ):
        raise ResearchReportError("rendered PDF lacks exact all-page visual evidence")
    ratios: list[Decimal] = []
    try:
        ratios = [Decimal(item) for item in result.page_non_white_ratios]
    except (InvalidOperation, TypeError) as exc:
        raise ResearchReportError("rendered PDF visual-density evidence is invalid") from exc
    if any(not value.is_finite() or value < 0 or value > 1 for value in ratios):
        raise ResearchReportError("rendered PDF visual-density evidence is invalid")
    visually_sparse_pages = [
        index + 1
        for index, value in enumerate(ratios)
        if index > 0 and value < Decimal("0.040000")
    ]
    if visually_sparse_pages:
        sparse_ratios = {
            page: format(ratios[page - 1], "f") for page in visually_sparse_pages
        }
        raise ResearchReportError(
            "rendered PDF contains visually sparse non-cover pages "
            f"(pages={visually_sparse_pages}, ratios={sparse_ratios})"
        )
    return {
        "status": "passed",
        "method": "unique-evidence-bound-narrative-v1",
        "verified_paragraph_count": len(verified_tokens),
        "unique_paragraph_count": len(set(verified_tokens)),
        "blank_page_count": 0,
        "low_density_non_cover_page_count": 0,
        "minimum_non_cover_characters": min(counts[1:], default=counts[0]),
        "page_character_counts_sha256": canonical_sha256(list(counts)),
    }


def _validate_render_result(
    result: PdfRenderResult,
    report_spec: ReportSpec,
    content: ResearchReportContent,
) -> dict[str, object]:
    if type(result) is not PdfRenderResult:
        raise ResearchReportError("renderer returned an untyped PDF result")
    if (
        not result.pdf_bytes.startswith(b"%PDF-")
        or not 1 <= len(result.pdf_bytes) <= REPORT_PDF_MAX_BYTES
        or not REPORT_MIN_PAGES <= result.page_count <= REPORT_MAX_PAGES
        or result.rendered_page_count != result.page_count
        or result.engine not in {"tectonic", "injected-test-renderer"}
    ):
        raise ResearchReportError(
            "rendered PDF failed the 30-60 page QA contract "
            f"(pages={result.page_count}, rendered={result.rendered_page_count}, "
            f"engine={result.engine})"
        )
    normalized = _clean_text(result.extracted_text)
    if not normalized or re.search(r"[\u4e00-\u9fff]", normalized) is None:
        raise ResearchReportError("rendered PDF lacks extractable simplified-Chinese text")
    section_search_text = _pdf_section_search_text(result.extracted_text)
    missing = [
        str(section["section_id"])
        for section in content["sections"]
        if _pdf_section_search_text(section["title_zh"]) not in section_search_text
    ]
    missing.extend(
        str(section["section_id"])
        for section in report_spec.sections
        if _pdf_section_search_text(section["title"]) not in section_search_text
    )
    if missing:
        raise ResearchReportError(f"rendered PDF is missing required sections: {missing}")
    return _anti_padding_render_metrics(result, content)


def _artifact_receipt(artifacts: tuple[ReportArtifact, ...]) -> list[dict[str, object]]:
    return [
        {
            "path": item.path,
            "media_type": item.media_type,
            "size": len(item.content),
            "sha256": item.sha256,
        }
        for item in sorted(artifacts, key=lambda artifact: artifact.path)
    ]


@_uses_report_decimal_context
@retained_authority_replay_scope
def build_research_report(
    *,
    profile: str,
    research: ReloadedResearchInput,
    report_spec: ReportSpec,
    research_source_index: ResearchSourceIndex,
    renderer: ReportRenderer,
    scores: tuple[Score, ...] = (),
    valuation: ReloadedValuationInput | None = None,
    futu_session_evidence: FutuSessionEvidence | None = None,
    futu_market_execution_evidence: FutuMarketExecutionEvidence | None = None,
    futu_peer_evidence_set: FutuPeerEvidenceSet | None = None,
    futu_optional_data_dispositions: tuple[FutuOptionalDataDisposition, ...] = (),
    futu_verifier: SignatureVerifier | None = None,
    forward_reoi: ForwardReOIValuationResult | None = None,
    comparable_valuation: ComparableValuationResult | None = None,
    composite_valuation: CompositeValuationResult | None = None,
    score_v2: tuple[ScoreV2, ...] = (),
    owner_scorecard: OwnerScorecard | None = None,
    market_expectations: MarketExpectationsComparison | None = None,
    runtime_gap: RuntimeGapReceipt | None = None,
) -> ReportBuildResult:
    """Build deterministic report inputs and accept only a PDF that passes all QA."""

    try:
        research_source_manifest = build_research_source_index_publication_manifest(
            research_source_index
        )
    except OwnerEquityTypeError as exc:
        raise ResearchReportError("research source index does not replay") from exc
    futu_session_manifest = None
    futu_partial_session_manifest = None
    futu_optional_data_disposition_manifests: tuple[
        FutuOptionalDataDispositionPublicationManifest, ...
    ] = ()
    market_expectations_manifest = None
    runtime_gap_manifest = None
    forward_reoi_manifest = None
    comparable_valuation_manifest = None
    composite_valuation_manifest = None
    score_v2_manifests: tuple[ScoreV2PublicationManifest, ...] = ()
    owner_scorecard_manifest = None
    if profile == "full_valuation":
        if type(valuation) is not ReloadedValuationInput:
            raise ResearchReportError("full_valuation requires a strictly reloaded archive")
        if type(composite_valuation) is not CompositeValuationResult:
            raise ResearchReportError("full_valuation requires an exact composite result")
        valuation_before_optional = composite_valuation.to_dict()
        scorecard_before_optional = None if owner_scorecard is None else owner_scorecard.to_dict()
        score_fingerprints_before_optional = tuple(item.fingerprint for item in score_v2)
        try:
            futu_optional_data_disposition_manifests = (
                build_futu_optional_data_disposition_publication_manifests(
                    futu_optional_data_dispositions
                )
            )
        except (KeyError, OSError, TypeError, ValueError, OwnerEquityTypeError) as exc:
            raise ResearchReportError("optional Futu dispositions do not replay") from exc
        if (
            composite_valuation.to_dict() != valuation_before_optional
            or (None if owner_scorecard is None else owner_scorecard.to_dict())
            != scorecard_before_optional
            or tuple(item.fingerprint for item in score_v2)
            != score_fingerprints_before_optional
        ):
            raise ResearchReportError("optional Futu data changed valuation or Score inputs")
        if composite_valuation.status == "complete":
            if type(futu_session_evidence) is not FutuSessionEvidence:
                raise ResearchReportError("complete full_valuation requires exact Futu session")
            if type(market_expectations) is not MarketExpectationsComparison:
                raise ResearchReportError(
                    "complete full_valuation requires exact post-conclusion expectations"
                )
            valuation_before_market = composite_valuation.to_dict()
            scorecard_before_market = None if owner_scorecard is None else owner_scorecard.to_dict()
            score_fingerprints_before_market = tuple(item.fingerprint for item in score_v2)
            try:
                futu_session_manifest = build_futu_session_publication_manifest(
                    futu_session_evidence,
                    verifier=futu_verifier,
                )
                market_expectations_manifest = build_market_expectations_publication_manifest(
                    market_expectations,
                    futu_session_manifest=futu_session_manifest,
                )
            except (FutuSessionEvidenceError, OwnerEquityTypeError) as exc:
                raise ResearchReportError("complete Futu context does not replay") from exc
            if (
                composite_valuation.to_dict() != valuation_before_market
                or (None if owner_scorecard is None else owner_scorecard.to_dict())
                != scorecard_before_market
                or tuple(item.fingerprint for item in score_v2) != score_fingerprints_before_market
            ):
                raise ResearchReportError("market expectations changed valuation or Score inputs")
        elif composite_valuation.status in {"blocked", "contested"}:
            if (
                type(futu_market_execution_evidence) is not FutuMarketExecutionEvidence
                or type(futu_peer_evidence_set) is not FutuPeerEvidenceSet
                or type(runtime_gap) is not RuntimeGapReceipt
                or futu_verifier is None
            ):
                raise ResearchReportError(
                    "ineligible full_valuation requires exact partial Futu and gap authorities"
                )
            if futu_session_evidence is not None or market_expectations is not None:
                raise ResearchReportError(
                    "ineligible full_valuation forbids post-conclusion Futu context"
                )
            try:
                futu_partial_session_manifest = build_futu_partial_session_publication_manifest(
                    market_execution_evidence=futu_market_execution_evidence,
                    peer_evidence_set=futu_peer_evidence_set,
                    attested_finalization=runtime_gap.attested_finalization,
                    verifier=futu_verifier,
                )
                runtime_gap_manifest = build_runtime_gap_publication_manifest(runtime_gap)
            except (FutuSessionEvidenceError, OwnerEquityTypeError) as exc:
                raise ResearchReportError("partial Futu context does not replay") from exc
        else:
            raise ResearchReportError("full_valuation composite status is not closed")
    _verify_inputs(
        profile,
        research,
        valuation,
        report_spec,
        research_source_index,
        research_source_manifest,
        scores,
        futu_session_evidence,
        futu_session_manifest,
        futu_market_execution_evidence,
        futu_peer_evidence_set,
        futu_partial_session_manifest,
        futu_optional_data_dispositions,
        futu_optional_data_disposition_manifests,
        futu_verifier,
        forward_reoi,
        comparable_valuation,
        composite_valuation,
        score_v2,
        owner_scorecard,
        market_expectations,
        market_expectations_manifest,
        runtime_gap,
        runtime_gap_manifest,
    )
    if profile == "full_valuation":
        assert valuation is not None
        assert composite_valuation is not None
        assert owner_scorecard is not None
        forward_reoi_manifest = (
            None
            if forward_reoi is None
            else ForwardReOIValuationPublicationManifest.from_source(forward_reoi)
        )
        comparable_valuation_manifest = (
            None
            if comparable_valuation is None
            else ComparableValuationPublicationManifest.from_source(comparable_valuation)
        )
        composite_valuation_manifest = CompositeValuationPublicationManifest.from_source(
            composite_valuation
        )
        score_v2_manifests = tuple(
            ScoreV2PublicationManifest.from_source(item)
            for item in sorted(score_v2, key=lambda item: item.lens)
        )
        owner_scorecard_manifest = OwnerScorecardPublicationManifest.from_source(owner_scorecard)
        _validate_downstream_publication_chain(
            research_bundle_fingerprint=research.result.bundle.bundle_fingerprint,
            contract_graph_fingerprint=research_source_manifest.to_dict()[
                "contract_graph_fingerprint"
            ],
            valuation_archive_fingerprint=valuation.archive.fingerprint,
            valuation_result_sha256=str(valuation.archive.manifest["valuation_result_sha256"]),
            futu_session_manifest=futu_session_manifest,
            futu_partial_session_manifest=futu_partial_session_manifest,
            forward_manifest=forward_reoi_manifest,
            comparable_manifest=comparable_valuation_manifest,
            composite_manifest=composite_valuation_manifest,
            score_manifests=score_v2_manifests,
            scorecard_manifest=owner_scorecard_manifest,
            market_manifest=market_expectations_manifest,
            runtime_gap_manifest=runtime_gap_manifest,
        )
    if renderer is None or not callable(getattr(renderer, "render", None)):
        raise ResearchReportError("an explicit report renderer is required")
    template, font_manifest = _asset_contents()
    content = _build_report_content(
        profile=profile,
        research=research,
        report_spec=report_spec,
        research_source_index=research_source_index,
        research_source_manifest=research_source_manifest,
        valuation=valuation,
        futu_session_manifest=futu_session_manifest,
        futu_partial_session_manifest=futu_partial_session_manifest,
        forward_reoi=forward_reoi,
        comparable_valuation=comparable_valuation,
        composite_valuation=composite_valuation,
        score_v2=score_v2,
        owner_scorecard=owner_scorecard,
        market_expectations_manifest=market_expectations_manifest,
        runtime_gap_manifest=runtime_gap_manifest,
        futu_optional_data_disposition_manifests=(
            futu_optional_data_disposition_manifests
        ),
    )
    payload = _report_payload(
        profile,
        research,
        valuation,
        report_spec,
        content,
        research_source_manifest,
        scores,
        futu_session_manifest,
        futu_partial_session_manifest,
        forward_reoi,
        comparable_valuation,
        composite_valuation,
        score_v2,
        owner_scorecard,
        market_expectations_manifest,
        runtime_gap_manifest,
        futu_optional_data_disposition_manifests,
        forward_reoi_manifest,
        comparable_valuation_manifest,
        composite_valuation_manifest,
        score_v2_manifests,
        owner_scorecard_manifest,
    )
    table_tex = _content_tables_tex(content)
    chart_tex = _content_charts_tex(content)
    chart_svg = _content_charts_svg(content)
    data_tex = _report_data_tex(content)
    tex_sources = {
        "report.tex": template.encode("utf-8"),
        "report-data.tex": data_tex.encode("utf-8"),
        "report-table.tex": table_tex.encode("utf-8"),
        "report-chart.tex": chart_tex.encode("utf-8"),
    }
    rendered = renderer.render(tex_sources)
    report_toolchain_authority: ReportToolchainAuthority | None = None
    if type(renderer) is LatexReportRenderer:
        if rendered.engine == "injected-test-renderer":
            raise ResearchReportError("production renderer returned test-only provenance")
        authority = renderer.authority
        report_toolchain_authority = authority
        if (
            rendered.toolchain_authority_id != authority.authority_id
            or rendered.toolchain_authority_fingerprint != authority.fingerprint
        ):
            raise ResearchReportError(
                "production renderer result is not bound to its pre-trusted authority"
            )
    elif rendered.engine != "injected-test-renderer":
        raise ResearchReportError(
            "a non-production renderer must identify itself as injected-test-renderer"
        )
    elif (
        rendered.toolchain_authority_id is not None
        or rendered.toolchain_authority_fingerprint is not None
    ):
        raise ResearchReportError("injected test renderer cannot claim production authority")
    anti_padding_qa = _validate_render_result(rendered, report_spec, content)
    artifacts = tuple(
        sorted(
            (
                ReportArtifact("report.pdf", "application/pdf", rendered.pdf_bytes),
                ReportArtifact("report.tex", "application/x-tex", tex_sources["report.tex"]),
                ReportArtifact(
                    "report-data.tex", "application/x-tex", tex_sources["report-data.tex"]
                ),
                ReportArtifact(
                    "report-table.tex", "application/x-tex", tex_sources["report-table.tex"]
                ),
                ReportArtifact(
                    "report-chart.tex", "application/x-tex", tex_sources["report-chart.tex"]
                ),
                ReportArtifact("report-charts.svg", "image/svg+xml", chart_svg),
                ReportArtifact("report-data.json", "application/json", _canonical_file(payload)),
                ReportArtifact(
                    "report-content.json",
                    "application/json",
                    _canonical_file(content.to_dict()),
                ),
                ReportArtifact(
                    "report.md", "text/markdown", _report_markdown(payload).encode("utf-8")
                ),
                ReportArtifact(
                    "report-extracted.txt",
                    "text/plain",
                    rendered.extracted_text.encode("utf-8"),
                ),
                ReportArtifact(
                    "font-manifest.json",
                    "application/json",
                    _canonical_file(font_manifest),
                ),
            ),
            key=lambda artifact: artifact.path,
        )
    )
    bundle = research.result.bundle
    valuation_archive_id = None
    valuation_fingerprint = None
    if valuation is not None:
        valuation_archive_id = str(valuation.archive.manifest["archive_id"])
        valuation_fingerprint = valuation.archive.fingerprint
    forward_reoi_fingerprint = None if forward_reoi is None else forward_reoi.fingerprint
    futu_session_evidence_fingerprint = (
        None if futu_session_evidence is None else futu_session_evidence.fingerprint
    )
    futu_session_manifest_fingerprint = (
        None if futu_session_manifest is None else futu_session_manifest.fingerprint
    )
    futu_market_execution_fingerprint = (
        None
        if futu_market_execution_evidence is None
        else futu_market_execution_evidence.fingerprint
    )
    futu_peer_evidence_set_fingerprint = (
        None if futu_peer_evidence_set is None else futu_peer_evidence_set.fingerprint
    )
    futu_partial_session_evidence_fingerprint = (
        None
        if futu_partial_session_manifest is None
        else futu_partial_session_manifest.partial_session_fingerprint
    )
    futu_partial_session_manifest_fingerprint = (
        None if futu_partial_session_manifest is None else futu_partial_session_manifest.fingerprint
    )
    futu_optional_data_disposition_fingerprints = [
        item.fingerprint for item in futu_optional_data_dispositions
    ]
    futu_optional_data_disposition_manifest_fingerprints = [
        item.fingerprint for item in futu_optional_data_disposition_manifests
    ]
    market_expectations_fingerprint = (
        None if market_expectations is None else market_expectations.fingerprint
    )
    market_expectations_manifest_fingerprint = (
        None if market_expectations_manifest is None else market_expectations_manifest.fingerprint
    )
    comparable_fingerprint = (
        None if comparable_valuation is None else comparable_valuation.fingerprint
    )
    composite_fingerprint = None if composite_valuation is None else composite_valuation.fingerprint
    score_v2_fingerprints = sorted(item.fingerprint for item in score_v2)
    owner_scorecard_fingerprint = None if owner_scorecard is None else owner_scorecard.fingerprint
    forward_reoi_manifest_fingerprint = (
        None if forward_reoi_manifest is None else forward_reoi_manifest.fingerprint
    )
    comparable_manifest_fingerprint = (
        None if comparable_valuation_manifest is None else comparable_valuation_manifest.fingerprint
    )
    composite_manifest_fingerprint = (
        None if composite_valuation_manifest is None else composite_valuation_manifest.fingerprint
    )
    score_manifest_fingerprints = sorted(item.fingerprint for item in score_v2_manifests)
    scorecard_manifest_fingerprint = (
        None if owner_scorecard_manifest is None else owner_scorecard_manifest.fingerprint
    )
    runtime_gap_fingerprint = None if runtime_gap is None else runtime_gap.fingerprint
    runtime_gap_manifest_fingerprint = (
        None if runtime_gap_manifest is None else runtime_gap_manifest.fingerprint
    )
    valuation_context_status = (
        "not_applicable"
        if profile == "research_only"
        else "complete"
        if futu_session_manifest is not None
        else "post_context_not_run"
    )
    identity = {
        "profile": profile,
        "valuation_context_status": valuation_context_status,
        "issuer_id": bundle.issuer_id,
        "data_cutoff_date": bundle.data_cutoff_date,
        "research_bundle_fingerprint": bundle.bundle_fingerprint,
        "research_source_index_fingerprint": research_source_index.fingerprint,
        "research_source_publication_manifest_fingerprint": (research_source_manifest.fingerprint),
        "valuation_archive_fingerprint": valuation_fingerprint,
        "futu_session_evidence_fingerprint": futu_session_evidence_fingerprint,
        "futu_session_publication_manifest_fingerprint": (futu_session_manifest_fingerprint),
        "futu_market_execution_evidence_fingerprint": futu_market_execution_fingerprint,
        "futu_peer_evidence_set_fingerprint": futu_peer_evidence_set_fingerprint,
        "futu_partial_session_evidence_fingerprint": (futu_partial_session_evidence_fingerprint),
        "futu_partial_session_publication_manifest_fingerprint": (
            futu_partial_session_manifest_fingerprint
        ),
        "futu_optional_data_disposition_fingerprints": (
            futu_optional_data_disposition_fingerprints
        ),
        "futu_optional_data_disposition_publication_manifest_fingerprints": (
            futu_optional_data_disposition_manifest_fingerprints
        ),
        "forward_reoi_fingerprint": forward_reoi_fingerprint,
        "comparable_valuation_fingerprint": comparable_fingerprint,
        "composite_valuation_fingerprint": composite_fingerprint,
        "report_spec_fingerprint": report_spec.fingerprint,
        "report_content_fingerprint": content.fingerprint,
        "score_fingerprints": sorted(score.fingerprint for score in scores),
        "score_v2_fingerprints": score_v2_fingerprints,
        "owner_scorecard_fingerprint": owner_scorecard_fingerprint,
        "forward_reoi_publication_manifest_fingerprint": (forward_reoi_manifest_fingerprint),
        "comparable_valuation_publication_manifest_fingerprint": (comparable_manifest_fingerprint),
        "composite_valuation_publication_manifest_fingerprint": (composite_manifest_fingerprint),
        "score_v2_publication_manifest_fingerprints": score_manifest_fingerprints,
        "owner_scorecard_publication_manifest_fingerprint": (scorecard_manifest_fingerprint),
        "market_expectations_fingerprint": market_expectations_fingerprint,
        "market_expectations_publication_manifest_fingerprint": (
            market_expectations_manifest_fingerprint
        ),
        "runtime_gap_fingerprint": runtime_gap_fingerprint,
        "runtime_gap_publication_manifest_fingerprint": runtime_gap_manifest_fingerprint,
        "renderer": {
            "renderer_id": _clean_text(rendered.renderer_id),
            "renderer_version": _clean_text(rendered.renderer_version),
            "engine": rendered.engine,
            "toolchain_authority_id": rendered.toolchain_authority_id,
            "toolchain_authority_fingerprint": (rendered.toolchain_authority_fingerprint),
        },
        "artifacts": _artifact_receipt(artifacts),
    }
    required_sections = sorted(str(item["section_id"]) for item in content["sections"])
    receipt: dict[str, object] = {
        "schema_version": "1.0.0",
        "artifact_type": "report-build-receipt",
        "report_build_id": f"report-build:{bundle.issuer_id}:{canonical_sha256(identity)[:24]}",
        "profile": profile,
        "valuation_context_status": valuation_context_status,
        "issuer_id": bundle.issuer_id,
        "data_cutoff_date": bundle.data_cutoff_date,
        "research_bundle_id": bundle.bundle_id,
        "research_bundle_fingerprint": bundle.bundle_fingerprint,
        "research_run_id": bundle.run_id,
        "research_source_index_fingerprint": research_source_index.fingerprint,
        "research_source_publication_manifest_fingerprint": (research_source_manifest.fingerprint),
        "valuation_archive_id": valuation_archive_id,
        "valuation_archive_fingerprint": valuation_fingerprint,
        "futu_session_evidence_fingerprint": futu_session_evidence_fingerprint,
        "futu_session_publication_manifest_fingerprint": (futu_session_manifest_fingerprint),
        "futu_market_execution_evidence_fingerprint": futu_market_execution_fingerprint,
        "futu_peer_evidence_set_fingerprint": futu_peer_evidence_set_fingerprint,
        "futu_partial_session_evidence_fingerprint": (futu_partial_session_evidence_fingerprint),
        "futu_partial_session_publication_manifest_fingerprint": (
            futu_partial_session_manifest_fingerprint
        ),
        "futu_optional_data_disposition_fingerprints": (
            futu_optional_data_disposition_fingerprints
        ),
        "futu_optional_data_disposition_publication_manifest_fingerprints": (
            futu_optional_data_disposition_manifest_fingerprints
        ),
        "forward_reoi_fingerprint": forward_reoi_fingerprint,
        "comparable_valuation_fingerprint": comparable_fingerprint,
        "composite_valuation_fingerprint": composite_fingerprint,
        "report_spec_id": report_spec.report_spec_id,
        "report_spec_fingerprint": report_spec.fingerprint,
        "report_content_fingerprint": content.fingerprint,
        "score_fingerprints": sorted(score.fingerprint for score in scores),
        "score_v2_fingerprints": score_v2_fingerprints,
        "owner_scorecard_fingerprint": owner_scorecard_fingerprint,
        "forward_reoi_publication_manifest_fingerprint": (forward_reoi_manifest_fingerprint),
        "comparable_valuation_publication_manifest_fingerprint": (comparable_manifest_fingerprint),
        "composite_valuation_publication_manifest_fingerprint": (composite_manifest_fingerprint),
        "score_v2_publication_manifest_fingerprints": score_manifest_fingerprints,
        "owner_scorecard_publication_manifest_fingerprint": (scorecard_manifest_fingerprint),
        "market_expectations_fingerprint": market_expectations_fingerprint,
        "market_expectations_publication_manifest_fingerprint": (
            market_expectations_manifest_fingerprint
        ),
        "runtime_gap_fingerprint": runtime_gap_fingerprint,
        "runtime_gap_publication_manifest_fingerprint": runtime_gap_manifest_fingerprint,
        "renderer": {
            "renderer_id": _clean_text(rendered.renderer_id),
            "renderer_version": _clean_text(rendered.renderer_version),
            "engine": rendered.engine,
            "toolchain_authority_id": rendered.toolchain_authority_id,
            "toolchain_authority_fingerprint": (rendered.toolchain_authority_fingerprint),
        },
        "artifacts": _artifact_receipt(artifacts),
        "qa": {
            "status": "passed",
            "page_count": rendered.page_count,
            "minimum_pages": REPORT_MIN_PAGES,
            "maximum_pages": REPORT_MAX_PAGES,
            "rendered_page_count": rendered.rendered_page_count,
            "extracted_text_sha256": _sha256(rendered.extracted_text.encode("utf-8")),
            "page_text_character_counts": list(rendered.page_text_character_counts),
            "rendered_page_sha256": list(rendered.rendered_page_sha256),
            "page_non_white_ratios": list(rendered.page_non_white_ratios),
            "pdf_text_backend": (
                None
                if report_toolchain_authority is None
                else to_json_value(report_toolchain_authority["pdf_text_backend"])
            ),
            "pdf_render_backend": (
                None
                if report_toolchain_authority is None
                else to_json_value(report_toolchain_authority["pdf_render_backend"])
            ),
            "language": "zh-CN",
            "simplified_chinese_detected": True,
            "required_section_ids": required_sections,
            "verified_section_ids": required_sections,
            "substantive_unit_count": content["substantive_unit_count"],
            "anti_padding": anti_padding_qa,
        },
    }
    receipt["receipt_fingerprint"] = canonical_sha256(receipt)
    _validate_parallel_schema("report-build-receipt", receipt)
    return ReportBuildResult(
        profile=profile,
        issuer_id=bundle.issuer_id,
        data_cutoff_date=bundle.data_cutoff_date,
        artifacts=artifacts,
        receipt=ReportBuildReceipt(receipt),
        content=content,
        research_source_index=research_source_index,
        research_source_manifest=research_source_manifest,
        legacy_scores=scores,
        futu_session_evidence=futu_session_evidence,
        futu_session_manifest=futu_session_manifest,
        futu_market_execution_evidence=futu_market_execution_evidence,
        futu_peer_evidence_set=futu_peer_evidence_set,
        futu_partial_session_manifest=futu_partial_session_manifest,
        futu_optional_data_dispositions=futu_optional_data_dispositions,
        futu_optional_data_disposition_manifests=(
            futu_optional_data_disposition_manifests
        ),
        forward_reoi=forward_reoi,
        comparable_valuation=comparable_valuation,
        composite_valuation=composite_valuation,
        score_v2=score_v2,
        owner_scorecard=owner_scorecard,
        forward_reoi_manifest=forward_reoi_manifest,
        comparable_valuation_manifest=comparable_valuation_manifest,
        composite_valuation_manifest=composite_valuation_manifest,
        score_v2_manifests=score_v2_manifests,
        owner_scorecard_manifest=owner_scorecard_manifest,
        market_expectations=market_expectations,
        market_expectations_manifest=market_expectations_manifest,
        runtime_gap=runtime_gap,
        runtime_gap_manifest=runtime_gap_manifest,
    )


__all__ = (
    "ComparableValuationPublicationManifest",
    "CompositeValuationPublicationManifest",
    "ForwardReOIValuationPublicationManifest",
    "LatexReportRenderer",
    "OwnerScorecardPublicationManifest",
    "PdfRenderResult",
    "ReloadedResearchInput",
    "ReloadedValuationInput",
    "ReportArtifact",
    "ReportBuildReceipt",
    "ReportBuildResult",
    "ReportToolchainAuthority",
    "ReportToolchainAuthorityRegistry",
    "ResearchReportContent",
    "REPORT_MAX_PAGES",
    "REPORT_MIN_PAGES",
    "REPORT_PROFILES",
    "ResearchReportError",
    "ScoreV2PublicationManifest",
    "bootstrap_report_toolchain_authority_entry",
    "bootstrap_report_toolchain_authority_entry_from_manifest",
    "build_report_toolchain_authority_registry",
    "build_research_report",
    "load_report_toolchain_authority",
    "load_report_toolchain_authority_registry",
    "reload_research_input",
    "reload_valuation_input",
)
