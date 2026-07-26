from __future__ import annotations

import json
from pathlib import Path

from owner_research.contracts import FiscalPeriod, contract_from_dict

ROOT = Path(__file__).parents[1]
GOLDEN = ROOT / "evals" / "golden" / "quarterly"


def load_case(name: str) -> dict:
    return json.loads((GOLDEN / name).read_text(encoding="utf-8"))


def load_contracts(case: dict) -> tuple[dict, dict, dict]:
    documents = {
        item["document_id"]: contract_from_dict("source-document", item)
        for item in case["documents"]
    }
    periods = {
        item["period_id"]: FiscalPeriod(**item)
        for item in case["periods"]
    }
    facts = {
        item["fact_id"]: contract_from_dict("fact", item)
        for item in case["facts"]
    }
    return documents, periods, facts
