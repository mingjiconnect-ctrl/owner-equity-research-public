from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation

from lxml import etree, html

from .contracts import ExtractionCandidate, FilingArtifact, SourceDocument
from .fingerprints import canonical_sha256
from .units import UnitError, validate_unit_currency, xbrl_unit

EXTRACTOR_VERSION = "0.3.0-alpha.1"


class ExtractionError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ParsedNumber:
    value: float
    negative: bool


def parse_displayed_number(text: str) -> ParsedNumber:
    cleaned = " ".join(text.replace("\u00a0", " ").split()).strip()
    negative = cleaned.startswith("(") and cleaned.endswith(")")
    cleaned = re.sub(r"[$€£,%()]", "", cleaned).replace(",", "").strip()
    if cleaned in {"", "—", "–", "-"}:
        raise ExtractionError("displayed value is missing")
    try:
        value = float(Decimal(cleaned))
    except InvalidOperation as exc:
        raise ExtractionError(f"not a numeric display value: {text}") from exc
    return ParsedNumber(-value if negative else value, negative)


def _candidate_id(artifact: FilingArtifact, locator: str, concept: str) -> str:
    digest = canonical_sha256(
        {"artifact": artifact.artifact_id, "locator": locator, "concept": concept}
    )[:20]
    return f"candidate:{artifact.issuer_id}:{digest}"


def _excerpt_sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def extract_ixbrl_candidates(
    raw: bytes,
    *,
    artifact: FilingArtifact,
    source_document: SourceDocument,
) -> tuple[ExtractionCandidate, ...]:
    try:
        document = html.fromstring(raw)
    except (etree.ParserError, ValueError) as exc:
        raise ExtractionError("iXBRL document cannot be parsed") from exc

    def local_name(node: etree._Element) -> str:
        return str(node.tag).split("}")[-1].split(":")[-1].lower()

    def descendants(node: etree._Element, name: str) -> list[etree._Element]:
        return [item for item in node.iterdescendants() if local_name(item) == name]

    contexts: dict[str, dict[str, object]] = {}
    for node in document.iter():
        if local_name(node) != "context":
            continue
        identifier = node.get("id")
        if not identifier:
            continue
        starts = [item.text for item in descendants(node, "startdate") if item.text]
        ends = [item.text for item in descendants(node, "enddate") if item.text]
        instants = [item.text for item in descendants(node, "instant") if item.text]
        dimensions = {}
        for member in descendants(node, "explicitmember"):
            dimension = member.get("dimension")
            if dimension and member.text:
                dimensions[dimension] = member.text.strip()
        for member in descendants(node, "typedmember"):
            dimension = member.get("dimension")
            value = " ".join(member.text_content().split())
            if dimension and value:
                dimensions[dimension] = value
        contexts[identifier] = {
            "period": {
                "start": starts[0] if starts else None,
                "end": ends[0] if ends else (instants[0] if instants else None),
            },
            "dimensions": dimensions,
        }
    results: list[ExtractionCandidate] = []
    facts = [node for node in document.iter() if local_name(node) in {"nonfraction", "nonnumeric"}]
    for index, node in enumerate(facts):
        context_ref = node.get("contextref") or node.get("contextRef")
        concept = node.get("name")
        context = contexts.get(context_ref or "")
        if not context_ref or not concept or context is None:
            continue
        text = " ".join(node.text_content().split())
        is_numeric = local_name(node) == "nonfraction"
        value: float | str
        issues: list[str] = []
        if is_numeric:
            try:
                value = parse_displayed_number(text).value
            except ExtractionError:
                # Inline XBRL may use a transformation namespace.  Keep the
                # candidate blocked when the displayed value cannot be parsed;
                # never guess a numeric value from narrative text.
                continue
            scale_text = node.get("scale")
            if scale_text:
                value *= 10 ** int(scale_text)
            sign = node.get("sign")
            if sign == "-" and value > 0:
                value = -value
        else:
            value = text
        unit_ref = node.get("unitref") or node.get("unitRef")
        currency = "USD" if unit_ref and unit_ref.lower() in {"usd", "iso4217:usd"} else None
        unit = xbrl_unit(unit_ref, currency=currency) if is_numeric else None
        if is_numeric and not unit_ref:
            issues.append("unit_missing")
        elif is_numeric and unit is None:
            issues.append("unit_unregistered")
        locator = f"{context_ref}:{concept}:{index}"
        results.append(
            ExtractionCandidate(
                schema_version="1.0.0",
                candidate_id=_candidate_id(artifact, locator, concept),
                issuer_id=artifact.issuer_id,
                source_document_id=source_document.document_id,
                artifact_id=artifact.artifact_id,
                candidate_kind="numeric_fact" if is_numeric else "narrative_fact",
                concept=concept,
                value_type="number" if is_numeric else "text",
                value=value,
                unit=unit,
                currency=currency,
                period=context["period"],
                dimensions=context["dimensions"],
                locator={
                    "kind": "ixbrl_context",
                    "value": locator,
                    "excerpt_sha256": _excerpt_sha(text),
                },
                extraction_method="deterministic_ixbrl",
                extractor_id="owner-research-ixbrl",
                extractor_version=EXTRACTOR_VERSION,
                validation_status="validated" if not issues else "blocked",
                validation_issues=issues,
                high_impact=not is_numeric,
            )
        )
    return tuple(results)


def table_matrix(raw: bytes, *, table_id: str) -> tuple[tuple[str, ...], ...]:
    document = html.fromstring(raw)
    tables = document.xpath(f"//table[@id='{table_id}']")
    if len(tables) != 1:
        raise ExtractionError("expected exactly one table")
    rows = tables[0].xpath(".//tr")
    grid: list[list[str | None]] = []
    for row_index, row in enumerate(rows):
        while len(grid) <= row_index:
            grid.append([])
        column = 0
        for cell in row.xpath("./th|./td"):
            while column < len(grid[row_index]) and grid[row_index][column] is not None:
                column += 1
            text = " ".join(cell.text_content().split())
            rowspan = int(cell.get("rowspan", "1"))
            colspan = int(cell.get("colspan", "1"))
            for row_offset in range(rowspan):
                target_row = row_index + row_offset
                while len(grid) <= target_row:
                    grid.append([])
                while len(grid[target_row]) < column + colspan:
                    grid[target_row].append(None)
                for col_offset in range(colspan):
                    grid[target_row][column + col_offset] = text
            column += colspan
    width = max((len(row) for row in grid), default=0)
    return tuple(tuple((cell or "") for cell in row + [None] * (width - len(row))) for row in grid)


def extract_table_candidates(
    raw: bytes,
    *,
    artifact: FilingArtifact,
    source_document: SourceDocument,
    table_id: str,
    period: Mapping[str, str | None],
    unit: str,
    currency: str | None,
    concept: str = "disclosed_metric",
    value_columns: Sequence[int] = (1,),
    label_column: int = 0,
) -> tuple[ExtractionCandidate, ...]:
    """Extract numeric cells from a normalized table as governed candidates.

    The helper deliberately does not infer headers, segment identities, or missing
    cells.  Callers pass the period and columns selected from the filing and each
    cell retains a stable table-cell locator and excerpt hash.
    """
    try:
        validate_unit_currency(unit, currency)
    except UnitError as exc:
        raise ExtractionError(str(exc)) from exc
    if not isinstance(period, Mapping) or set(period) != {"start", "end"}:
        raise ExtractionError("table candidate period must contain start and end")
    matrix = table_matrix(raw, table_id=table_id)
    results: list[ExtractionCandidate] = []
    for row_index, row in enumerate(matrix):
        if row_index == 0 or label_column >= len(row):
            continue
        label = row[label_column].strip()
        if not label:
            continue
        for value_column in value_columns:
            if value_column >= len(row):
                continue
            displayed = row[value_column].strip()
            try:
                parsed = parse_displayed_number(displayed)
            except ExtractionError:
                # Headers, em-dashes, and undisclosed values stay absent rather
                # than being turned into zero or a fabricated Fact.
                continue
            locator = f"{table_id}:r{row_index}:c{value_column}"
            candidate_id = _candidate_id(artifact, locator, f"{concept}:{label}")
            results.append(
                ExtractionCandidate(
                    schema_version="1.0.0",
                    candidate_id=candidate_id,
                    issuer_id=artifact.issuer_id,
                    source_document_id=source_document.document_id,
                    artifact_id=artifact.artifact_id,
                    candidate_kind="numeric_fact",
                    concept=f"{concept}:{label}",
                    value_type="number",
                    value=parsed.value,
                    unit=unit,
                    currency=currency,
                    period=dict(period),
                    dimensions={"row_label": label, "table_id": table_id},
                    locator={
                        "kind": "table_cell",
                        "value": locator,
                        "excerpt_sha256": _excerpt_sha(displayed),
                    },
                    extraction_method="deterministic_table",
                    extractor_id="owner-research-table",
                    extractor_version=EXTRACTOR_VERSION,
                    validation_status="validated",
                    validation_issues=[],
                    high_impact=False,
                )
            )
    return tuple(results)


def duplicate_candidate_groups(
    candidates: Sequence[ExtractionCandidate],
) -> tuple[tuple[str, ...], ...]:
    """Return deterministic groups of candidates competing for the same Fact."""
    groups: dict[tuple[object, ...], list[str]] = {}
    for candidate in candidates:
        key = (
            candidate.issuer_id,
            candidate.concept,
            candidate.value_type,
            candidate.unit,
            candidate.currency,
            tuple(sorted(dict(candidate.period).items())),
            tuple(sorted(dict(candidate.dimensions).items())),
        )
        groups.setdefault(key, []).append(candidate.candidate_id)
    return tuple(
        tuple(sorted(group))
        for group in sorted(groups.values(), key=lambda item: tuple(sorted(item)))
        if len(group) > 1
    )
