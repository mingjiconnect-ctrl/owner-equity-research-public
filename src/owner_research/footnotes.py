from __future__ import annotations

import re
from collections.abc import Iterable

from lxml import html

from .contracts import FootnoteReview

REQUIRED_TOPICS = (
    "revenue_contract_balances",
    "sbc",
    "leases",
    "income_taxes",
    "pensions_postretirement",
    "goodwill_intangibles_impairment",
    "debt_liquidity_covenants",
    "contingencies_litigation",
    "acquisitions_divestitures",
    "restructuring_exit",
    "related_parties",
    "commitments_guarantees_off_balance_sheet",
    "supplier_finance",
    "vie",
    "fair_value_derivatives_hedging",
)

TOPIC_PATTERNS = {
    "revenue_contract_balances": (r"revenue recognition", r"contract balance"),
    "sbc": (r"stock[- ]based compensation", r"share[- ]based compensation"),
    "leases": (r"\bleases?\b",),
    "income_taxes": (r"income taxes",),
    "pensions_postretirement": (r"pension", r"postretirement"),
    "goodwill_intangibles_impairment": (r"goodwill", r"intangible", r"impairment"),
    "debt_liquidity_covenants": (r"debt", r"liquidity", r"covenant"),
    "contingencies_litigation": (r"contingenc", r"litigation", r"legal proceedings"),
    "acquisitions_divestitures": (r"acquisition", r"divestiture", r"business combination"),
    "restructuring_exit": (r"restructur", r"exit costs?"),
    "related_parties": (r"related part",),
    "commitments_guarantees_off_balance_sheet": (r"commitments", r"guarantees", r"off-balance"),
    "supplier_finance": (r"supplier finance", r"reverse factoring"),
    "vie": (r"variable interest entit", r"\bvie\b"),
    "fair_value_derivatives_hedging": (r"fair value", r"derivative", r"hedg"),
}


def discover_note_headings(raw: bytes) -> tuple[str, ...]:
    document = html.fromstring(raw)
    headings: list[str] = []
    selected = document.xpath("//h1|//h2|//h3|//h4|//*[@role='heading']")
    # SEC filing HTML commonly renders Note titles as styled div/span/a nodes
    # rather than semantic headings.  The fallback remains conservative: only
    # short elements whose text starts with a Note identifier are accepted.
    selected.extend(document.xpath("//div|//p|//span|//a|//td"))
    for node in selected:
        text = " ".join(node.text_content().split())
        if (
            text
            and len(text) <= 240
            and re.match(r"^note\s+[0-9a-z]+\b", text, re.IGNORECASE)
        ):
            headings.append(text)
    return tuple(dict.fromkeys(headings))


def discover_topic_codes(raw: bytes) -> tuple[str, ...]:
    text = " ".join(html.fromstring(raw).text_content().split()).lower()
    return tuple(
        topic
        for topic in REQUIRED_TOPICS
        if any(re.search(pattern, text) for pattern in TOPIC_PATTERNS[topic])
    )


def coverage_counts(reviews: Iterable[FootnoteReview]) -> dict[str, int]:
    items = tuple(reviews)
    counts = {
        status: sum(item.status == status for item in items)
        for status in ("reviewed", "not_disclosed", "not_applicable", "blocked")
    }
    return {
        "required_count": len(REQUIRED_TOPICS),
        "reviewed_count": counts["reviewed"],
        "not_disclosed_count": counts["not_disclosed"],
        "not_applicable_count": counts["not_applicable"],
        "blocked_count": counts["blocked"],
    }
