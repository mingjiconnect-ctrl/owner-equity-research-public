"""Internal append-only compiler for the pinned rc.2 valuation request.

The compiler consumes a validated Phase 5D price-blind freeze and the market-reference
vertical slice.  It never fetches market data and never invokes valuation mathematics.
Only current-share lineage, the governed quote, and derived market equity are appended to
the frozen FactLedger; assumption entries remain byte-identical and are rebound solely to
the resulting FactLedger fingerprint.
"""

from __future__ import annotations

import hashlib
import json
import math
import subprocess
import unicodedata
from dataclasses import dataclass
from datetime import date
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from .component_lock import read_stable_file_bytes
from .contracts import CalculationResult, Fact, SourceDocument
from .fingerprints import FrozenMap, canonical_json, canonical_sha256, freeze, to_json_value
from .research_bundle_policies import dependency_closure_sha256
from .research_bundle_validation import (
    ResearchBundleValidationError,
    dependency_closure,
)
from .valuation_current_share_compiler import CurrentShareCompilationResult
from .valuation_fact_mapping import _source_is_registered
from .valuation_kernel_projection import (
    CurrentShareKernelProjection,
    KernelNumericProjectionWitness,
    _exact_decimal_multiply,
    project_current_share_lineage,
)
from .valuation_market_execution_policies import (
    FINAL_REQUEST_POLICY_ID,
    FINAL_REQUEST_POLICY_VERSION,
    PINNED_KERNEL_COMMIT,
    PINNED_KERNEL_SCHEMA_SHA256,
    PINNED_KERNEL_TAG,
)
from .valuation_market_snapshot import PreparedMarketReference
from .valuation_owner_preparation import OwnerValuationPreparationResult
from .valuation_price_blind_freeze import PriceBlindFreezeCompilationResult


class FinalRequestCompilationError(ValueError):
    """Raised when the complete request cannot be compiled without inference."""


_KERNEL_TAG_OBJECT = "4e19ce6a59bc4321ebcd368e807ed764f4e8abde"
_MODEL_SHARE_UNIT = "millions shares"
_MARKET_EQUITY_DERIVATION = "market_price_per_current_common_share * common_shares_outstanding"


def _canonical_market_validation_context_id(
    *,
    issuer_id: str,
    trading_date: str,
    raw_response_sha256: str,
) -> str:
    """Derive the sole accepted validation-context identity from market evidence."""

    return f"market-reference-context:{issuer_id}:{trading_date}:{raw_response_sha256[:16]}"


def _market_evidence_binding_sha256(
    *,
    context_id: str,
    context_fingerprint: str,
    access_fingerprint: str,
    provider_id: str,
    provider_registration_sha256: str,
    receipt_id: str,
    receipt_fingerprint: str,
    current_share_compilation_fingerprint: str,
    source_document_id: str,
    source_document_fingerprint: str,
    source_ref_fingerprint: str,
    raw_response_sha256: str,
    quote_fact_id: str,
    quote_fact_fingerprint: str,
    calculation_id: str,
    calculation_fingerprint: str,
) -> str:
    return canonical_sha256(
        {
            "context": [context_id, context_fingerprint],
            "access_fingerprint": access_fingerprint,
            "provider": [
                provider_id,
                provider_registration_sha256,
                receipt_id,
                receipt_fingerprint,
            ],
            "current_share_compilation_fingerprint": (current_share_compilation_fingerprint),
            "source_document": [source_document_id, source_document_fingerprint],
            "source_ref_fingerprint": source_ref_fingerprint,
            "raw_response_sha256": raw_response_sha256,
            "quote_fact": [quote_fact_id, quote_fact_fingerprint],
            "market_equity_calculation": [calculation_id, calculation_fingerprint],
        }
    )


def _company_identity_binding_sha256(
    *,
    issuer_id: str,
    legal_name: str,
    fact_id: str,
    fact_fingerprint: str,
    source_document_id: str,
    source_document_fingerprint: str,
) -> str:
    return canonical_sha256(
        {
            "issuer_id": issuer_id,
            "legal_name": legal_name,
            "fact": [fact_id, fact_fingerprint],
            "source_document": [source_document_id, source_document_fingerprint],
        }
    )


def _git(repository: Path, *args: str) -> str:
    try:
        return subprocess.check_output(
            ["git", "-C", str(repository), *args],
            text=True,
            stderr=subprocess.STDOUT,
        ).strip()
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        raise FinalRequestCompilationError("pinned kernel checkout cannot be verified") from exc


def _verify_kernel(repository: Path) -> tuple[Path, dict[str, dict[str, Any]]]:
    kernel = Path(repository).expanduser().resolve()
    if (
        _git(kernel, "rev-parse", "HEAD") != PINNED_KERNEL_COMMIT
        or _git(kernel, "rev-parse", f"{PINNED_KERNEL_TAG}^{{}}") != PINNED_KERNEL_COMMIT
        or _git(kernel, "rev-parse", f"refs/tags/{PINNED_KERNEL_TAG}") != _KERNEL_TAG_OBJECT
    ):
        raise FinalRequestCompilationError("kernel tag, commit, or tag object changed")
    schemas: dict[str, dict[str, Any]] = {}
    for relative, expected_sha in sorted(PINNED_KERNEL_SCHEMA_SHA256.items()):
        path = kernel / relative
        try:
            raw = read_stable_file_bytes(path)
        except (OSError, ValueError) as exc:
            raise FinalRequestCompilationError(
                f"pinned kernel Schema changed: {relative}"
            ) from exc
        if hashlib.sha256(raw).hexdigest() != expected_sha:
            raise FinalRequestCompilationError(f"pinned kernel Schema changed: {relative}")
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise FinalRequestCompilationError(
                f"pinned kernel Schema cannot be read: {relative}"
            ) from exc
        if not isinstance(payload, dict):
            raise FinalRequestCompilationError(
                f"pinned kernel Schema cannot be read: {relative}"
            )
        schemas[relative] = payload
    return kernel, schemas


def _validate_request_schema(request: dict[str, Any], schemas: dict[str, dict[str, Any]]) -> None:
    fact_schema = schemas["schemas/fact-ledger.schema.json"]
    assumption_schema = schemas["schemas/assumption-ledger.schema.json"]
    request_schema = schemas["schemas/valuation-request.schema.json"]
    registry = (
        Registry()
        .with_resource(fact_schema["$id"], Resource.from_contents(fact_schema))
        .with_resource(assumption_schema["$id"], Resource.from_contents(assumption_schema))
    )
    errors = sorted(
        Draft202012Validator(
            request_schema,
            registry=registry,
            format_checker=FormatChecker(),
        ).iter_errors(request),
        key=lambda item: tuple(str(part) for part in item.path),
    )
    if errors:
        first = errors[0]
        path = "$" + "".join(
            f"[{part}]" if isinstance(part, int) else f".{part}" for part in first.path
        )
        raise FinalRequestCompilationError(
            f"pinned request Schema rejected the compiled payload at {path}: {first.message}"
        )


@dataclass(frozen=True, slots=True)
class FinalFactLedgerCompilationResult:
    policy_id: str
    policy_version: str
    base_ledger_sha256: str
    base_ledger_payload: FrozenMap
    base_source_fingerprints: tuple[tuple[str, str], ...]
    base_fact_fingerprints: tuple[tuple[str, str], ...]
    current_share_projection: CurrentShareKernelProjection
    quote_projection_witness: KernelNumericProjectionWitness
    market_equity_projection_witness: KernelNumericProjectionWitness
    market_provider_id: str
    market_provider_registration_sha256: str
    market_provider_receipt_id: str
    market_provider_receipt_fingerprint: str
    market_validation_context_id: str
    market_validation_context_fingerprint: str
    market_access_result_fingerprint: str
    current_share_compilation_fingerprint: str
    market_source_document_id: str
    market_source_document_fingerprint: str
    market_source_ref_fingerprint: str
    market_raw_response_sha256: str
    market_quote_fact_id: str
    market_quote_fact_fingerprint: str
    market_equity_calculation_id: str
    market_equity_calculation_fingerprint: str
    market_evidence_binding_sha256: str
    added_source_ids: tuple[str, ...]
    added_fact_ids: tuple[str, ...]
    fact_ledger_payload: FrozenMap

    def __post_init__(self) -> None:
        if (self.policy_id, self.policy_version) != (
            FINAL_REQUEST_POLICY_ID,
            FINAL_REQUEST_POLICY_VERSION,
        ):
            raise ValueError("final FactLedger policy identity is invalid")
        if self.current_share_projection.status != "eligible":
            raise ValueError("final FactLedger lacks eligible current-share evidence")
        sources = tuple(sorted(self.base_source_fingerprints))
        facts = tuple(sorted(self.base_fact_fingerprints))
        added_sources = tuple(sorted(set(self.added_source_ids)))
        added_facts = tuple(sorted(set(self.added_fact_ids)))
        base_payload = freeze(self.base_ledger_payload)
        payload = freeze(self.fact_ledger_payload)
        if not added_sources or not added_facts:
            raise ValueError("final FactLedger did not append market lineage")
        if not all(
            (
                self.market_provider_id,
                self.market_provider_registration_sha256,
                self.market_provider_receipt_id,
                self.market_provider_receipt_fingerprint,
                self.market_validation_context_id,
                self.market_validation_context_fingerprint,
                self.market_access_result_fingerprint,
                self.current_share_compilation_fingerprint,
                self.market_source_document_id,
                self.market_source_document_fingerprint,
                self.market_source_ref_fingerprint,
                self.market_raw_response_sha256,
                self.market_quote_fact_id,
                self.market_quote_fact_fingerprint,
                self.market_equity_calculation_id,
                self.market_equity_calculation_fingerprint,
                self.market_evidence_binding_sha256,
            )
        ):
            raise ValueError("final FactLedger lacks governed market-provider identity")
        for value in (
            self.market_provider_receipt_fingerprint,
            self.market_provider_registration_sha256,
            self.market_validation_context_fingerprint,
            self.market_access_result_fingerprint,
            self.current_share_compilation_fingerprint,
            self.market_source_document_fingerprint,
            self.market_source_ref_fingerprint,
            self.market_raw_response_sha256,
            self.market_quote_fact_fingerprint,
            self.market_equity_calculation_fingerprint,
            self.market_evidence_binding_sha256,
        ):
            if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
                raise ValueError("final FactLedger contains an invalid evidence fingerprint")
        source_index = {item["source_id"]: item for item in payload["sources"]}
        fact_index = {item["fact_id"]: item for item in payload["facts"]}
        base_source_index = {item["source_id"]: item for item in base_payload["sources"]}
        base_fact_index = {item["fact_id"]: item for item in base_payload["facts"]}
        if (
            len(source_index) != len(payload["sources"])
            or len(fact_index) != len(payload["facts"])
            or len(base_source_index) != len(base_payload["sources"])
            or len(base_fact_index) != len(base_payload["facts"])
        ):
            raise ValueError("final FactLedger repeats evidence identity")
        base_source_ids = tuple(identifier for identifier, _fingerprint in sources)
        base_fact_ids = tuple(identifier for identifier, _fingerprint in facts)
        final_source_ids = tuple(item["source_id"] for item in payload["sources"])
        final_fact_ids = tuple(item["fact_id"] for item in payload["facts"])
        if (
            len(base_source_ids) != len(set(base_source_ids))
            or len(base_fact_ids) != len(set(base_fact_ids))
            or set(base_source_ids).intersection(added_sources)
            or set(base_fact_ids).intersection(added_facts)
            or set(final_source_ids) != set(base_source_ids).union(added_sources)
            or set(final_fact_ids) != set(base_fact_ids).union(added_facts)
            or final_source_ids != tuple(sorted(final_source_ids))
            or final_fact_ids != tuple(sorted(final_fact_ids))
            or set(base_source_index) != set(base_source_ids)
            or set(base_fact_index) != set(base_fact_ids)
            or any(
                identifier not in source_index
                or identifier not in base_source_index
                or source_index[identifier] != base_source_index[identifier]
                or canonical_sha256(base_source_index[identifier]) != fingerprint
                for identifier, fingerprint in sources
            )
            or any(
                identifier not in fact_index
                or identifier not in base_fact_index
                or fact_index[identifier] != base_fact_index[identifier]
                or canonical_sha256(base_fact_index[identifier]) != fingerprint
                for identifier, fingerprint in facts
            )
        ):
            raise ValueError("final FactLedger does not replay its append-only base receipts")
        if (
            tuple(base_payload.keys())
            != (
                "entity_id",
                "facts",
                "reporting_currency",
                "schema_version",
                "sources",
                "valuation_date",
            )
            or base_payload["schema_version"] != payload["schema_version"]
            or base_payload["entity_id"] != payload["entity_id"]
            or base_payload["valuation_date"] != payload["valuation_date"]
            or base_payload["reporting_currency"] != payload["reporting_currency"]
            or canonical_sha256(base_payload) != self.base_ledger_sha256
        ):
            raise ValueError("final FactLedger base fingerprint does not replay")
        if self.market_validation_context_id != _canonical_market_validation_context_id(
            issuer_id=str(payload["entity_id"]),
            trading_date=str(payload["valuation_date"]),
            raw_response_sha256=self.market_raw_response_sha256,
        ):
            raise ValueError("final FactLedger market validation context identity is not canonical")
        market_source = source_index.get(self.market_source_document_id)
        quote = fact_index.get(self.market_quote_fact_id)
        market = fact_index.get(f"derived:{self.market_equity_calculation_id}")
        current_share_id = self.current_share_projection.current_share_fact_id
        share_attestation = self.current_share_projection.research_evidence_attestation
        if (
            share_attestation is None
            or self.current_share_compilation_fingerprint
            != share_attestation["current_share_compilation_fingerprint"]
            or market_source is None
            or canonical_sha256(market_source) != self.market_source_ref_fingerprint
            or market_source.get("publisher") != self.market_provider_id
            or self.market_raw_response_sha256 not in market_source.get("locator", "")
            or self.market_source_document_id not in added_sources
            or quote is None
            or quote.get("concept") != "market_price_per_current_common_share"
            or quote.get("source_id") != self.market_source_document_id
            or quote.get("raw") is not True
            or quote.get("parent_fact_ids")
            or quote.get("value") != self.quote_projection_witness.kernel_value
            or self.quote_projection_witness.label != f"quote:{self.market_quote_fact_id}"
            or self.market_quote_fact_id not in added_facts
            or market is None
            or market.get("concept") != "market_equity_value"
            or market.get("source_id") != self.market_source_document_id
            or market.get("raw") is not False
            or tuple(market.get("parent_fact_ids", ()))
            != (self.market_quote_fact_id, current_share_id)
            or market.get("value") != self.market_equity_projection_witness.kernel_value
            or self.market_equity_projection_witness.label
            != f"market-equity:{self.market_equity_calculation_id}"
            or market["fact_id"] not in added_facts
            or self.market_evidence_binding_sha256
            != _market_evidence_binding_sha256(
                context_id=self.market_validation_context_id,
                context_fingerprint=self.market_validation_context_fingerprint,
                access_fingerprint=self.market_access_result_fingerprint,
                provider_id=self.market_provider_id,
                provider_registration_sha256=self.market_provider_registration_sha256,
                receipt_id=self.market_provider_receipt_id,
                receipt_fingerprint=self.market_provider_receipt_fingerprint,
                current_share_compilation_fingerprint=(self.current_share_compilation_fingerprint),
                source_document_id=self.market_source_document_id,
                source_document_fingerprint=self.market_source_document_fingerprint,
                source_ref_fingerprint=self.market_source_ref_fingerprint,
                raw_response_sha256=self.market_raw_response_sha256,
                quote_fact_id=self.market_quote_fact_id,
                quote_fact_fingerprint=self.market_quote_fact_fingerprint,
                calculation_id=self.market_equity_calculation_id,
                calculation_fingerprint=self.market_equity_calculation_fingerprint,
            )
        ):
            raise ValueError("final FactLedger does not bind governed market evidence")
        object.__setattr__(self, "base_source_fingerprints", sources)
        object.__setattr__(self, "base_fact_fingerprints", facts)
        object.__setattr__(self, "added_source_ids", added_sources)
        object.__setattr__(self, "added_fact_ids", added_facts)
        object.__setattr__(self, "base_ledger_payload", base_payload)
        object.__setattr__(self, "fact_ledger_payload", payload)

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(self.to_dict())


@dataclass(frozen=True, slots=True)
class FinalAssumptionLedgerCompilationResult:
    assumption_entries_sha256: str
    prior_fact_ledger_fingerprint: str
    final_fact_ledger_fingerprint: str
    assumption_ledger_payload: FrozenMap

    def __post_init__(self) -> None:
        payload = freeze(self.assumption_ledger_payload)
        if (
            payload["fact_ledger_fingerprint"] != self.final_fact_ledger_fingerprint
            or canonical_sha256(payload["assumptions"]) != self.assumption_entries_sha256
            or self.prior_fact_ledger_fingerprint == self.final_fact_ledger_fingerprint
        ):
            raise ValueError("final AssumptionLedger rebinding is invalid")
        object.__setattr__(self, "assumption_ledger_payload", payload)

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(self.to_dict())


@dataclass(frozen=True, slots=True)
class FinalValuationRequestCompilationResult:
    status: str
    issuer_id: str
    valuation_date: str
    price_blind_input_fingerprint: str
    prepared_market_reference_fingerprint: str | None
    company_legal_name_value: str | None
    company_name_fact_id: str | None
    company_name_fact_fingerprint: str | None
    company_name_source_document_id: str | None
    company_name_source_document_fingerprint: str | None
    company_identity_binding_sha256: str | None
    fact_ledger_result: FinalFactLedgerCompilationResult | None
    assumption_ledger_result: FinalAssumptionLedgerCompilationResult | None
    request_payload: FrozenMap | None
    canonical_request_json: str | None
    request_sha256: str | None
    issue_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.status not in {"compiled", "blocked", "specialist_required"}:
            raise ValueError("final request status is not registered")
        issues = tuple(sorted(set(self.issue_codes)))
        if self.status == "compiled":
            if (
                self.fact_ledger_result is None
                or self.assumption_ledger_result is None
                or self.request_payload is None
                or self.canonical_request_json is None
                or self.request_sha256 is None
                or self.prepared_market_reference_fingerprint is None
                or self.company_legal_name_value is None
                or self.company_name_fact_id is None
                or self.company_name_fact_fingerprint is None
                or self.company_name_source_document_id is None
                or self.company_name_source_document_fingerprint is None
                or self.company_identity_binding_sha256 is None
                or issues
                or canonical_json(self.request_payload) != self.canonical_request_json
                or canonical_sha256(self.request_payload) != self.request_sha256
            ):
                raise ValueError("compiled valuation request is incomplete")
            request = to_json_value(self.request_payload)
            fact_payload = to_json_value(self.fact_ledger_result.fact_ledger_payload)
            assumption_payload = to_json_value(
                self.assumption_ledger_result.assumption_ledger_payload
            )
            if (
                canonical_json(request.get("fact_ledger")) != canonical_json(fact_payload)
                or canonical_json(request.get("assumption_ledger"))
                != canonical_json(assumption_payload)
                or self.issuer_id != fact_payload.get("entity_id")
                or self.valuation_date != fact_payload.get("valuation_date")
                or self.assumption_ledger_result.prior_fact_ledger_fingerprint
                != self.fact_ledger_result.base_ledger_sha256
                or self.assumption_ledger_result.final_fact_ledger_fingerprint
                != canonical_sha256(fact_payload)
                or request.get("company", {}).get("name") != self.company_legal_name_value
                or self.company_identity_binding_sha256
                != _company_identity_binding_sha256(
                    issuer_id=self.issuer_id,
                    legal_name=self.company_legal_name_value,
                    fact_id=self.company_name_fact_id,
                    fact_fingerprint=self.company_name_fact_fingerprint,
                    source_document_id=self.company_name_source_document_id,
                    source_document_fingerprint=(self.company_name_source_document_fingerprint),
                )
            ):
                raise ValueError("compiled valuation request does not bind its ledger receipts")
            for value in (
                self.company_name_fact_fingerprint,
                self.company_name_source_document_fingerprint,
                self.company_identity_binding_sha256,
            ):
                if len(value) != 64 or any(
                    character not in "0123456789abcdef" for character in value
                ):
                    raise ValueError("compiled valuation request has invalid company provenance")
            fact_index = {item["fact_id"]: item for item in fact_payload.get("facts", ())}
            if len(fact_index) != len(fact_payload.get("facts", ())):
                raise ValueError("compiled valuation request repeats a Fact ID")
            current_share_id = (
                self.fact_ledger_result.current_share_projection.current_share_fact_id
            )
            market_facts = tuple(
                item
                for fact_id in self.fact_ledger_result.added_fact_ids
                if (item := fact_index.get(fact_id)) is not None
                and item.get("concept") == "market_equity_value"
            )
            if (
                current_share_id not in fact_index
                or len(market_facts) != 1
                or request.get("mckinsey", {})
                .get("equity_bridge", {})
                .get("share_denominator_fact_id")
                != current_share_id
                or request.get("penman", {}).get("market_equity_value_fact_id")
                != market_facts[0]["fact_id"]
                or tuple(market_facts[0].get("parent_fact_ids", ()))[-1:] != (current_share_id,)
            ):
                raise ValueError("compiled valuation request does not bind generated market Facts")
            referenced_fact_ids = set(request.get("company", {}).get("source_fact_ids", ()))
            referenced_fact_ids.update(
                fact_id
                for assessment in request.get("routing_assessments", {}).values()
                for fact_id in assessment.get("source_fact_ids", ())
            )
            for adjustments in request.get("method_views", {}).values():
                for adjustment in adjustments:
                    referenced_fact_ids.update(
                        (
                            adjustment.get("target_fact_id"),
                            adjustment.get("amount_fact_id"),
                        )
                    )
            referenced_fact_ids.discard(None)
            if not referenced_fact_ids.issubset(fact_index):
                raise ValueError(
                    "compiled valuation request contains dangling governed Fact bindings"
                )
        elif (
            any(
                item is not None
                for item in (
                    self.fact_ledger_result,
                    self.assumption_ledger_result,
                    self.request_payload,
                    self.canonical_request_json,
                    self.request_sha256,
                    self.prepared_market_reference_fingerprint,
                    self.company_legal_name_value,
                    self.company_name_fact_id,
                    self.company_name_fact_fingerprint,
                    self.company_name_source_document_id,
                    self.company_name_source_document_fingerprint,
                    self.company_identity_binding_sha256,
                )
            )
            or not issues
        ):
            raise ValueError("non-compiled valuation request promoted an artifact")
        object.__setattr__(
            self,
            "request_payload",
            freeze(self.request_payload) if self.request_payload is not None else None,
        )
        object.__setattr__(self, "issue_codes", issues)

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(self.to_dict())


def _noncompiled(
    *,
    preparation: OwnerValuationPreparationResult,
    status: str,
    issue: str,
) -> FinalValuationRequestCompilationResult:
    return FinalValuationRequestCompilationResult(
        status=status,
        issuer_id=preparation.issuer_id,
        valuation_date=preparation.data_cutoff_date,
        price_blind_input_fingerprint=preparation.price_blind_input_fingerprint,
        prepared_market_reference_fingerprint=None,
        company_legal_name_value=None,
        company_name_fact_id=None,
        company_name_fact_fingerprint=None,
        company_name_source_document_id=None,
        company_name_source_document_fingerprint=None,
        company_identity_binding_sha256=None,
        fact_ledger_result=None,
        assumption_ledger_result=None,
        request_payload=None,
        canonical_request_json=None,
        request_sha256=None,
        issue_codes=(issue,),
    )


def _append_by_id(
    base: list[dict[str, Any]],
    additions: tuple[dict[str, Any], ...],
    *,
    field: str,
) -> tuple[list[dict[str, Any]], tuple[str, ...]]:
    index = {str(item[field]): dict(item) for item in base}
    if len(index) != len(base):
        raise FinalRequestCompilationError(f"base ledger repeats {field}")
    added: list[str] = []
    for item in additions:
        identifier = str(item[field])
        if identifier in index:
            if canonical_json(index[identifier]) != canonical_json(item):
                raise FinalRequestCompilationError(f"appended object collides at {identifier}")
            continue
        index[identifier] = dict(item)
        added.append(identifier)
    return [index[key] for key in sorted(index)], tuple(sorted(added))


def _unique_exact_graph_object(
    values: tuple[Any, ...],
    *,
    expected: Any,
    identifier_field: str,
    expected_type: type[Any],
    label: str,
) -> Any:
    if type(expected) is not expected_type:
        raise FinalRequestCompilationError(f"prepared {label} has a substituted runtime type")
    identifier = getattr(expected, identifier_field)
    matches = tuple(item for item in values if getattr(item, identifier_field) == identifier)
    if (
        len(matches) != 1
        or type(matches[0]) is not expected_type
        or matches[0] != expected
        or matches[0].fingerprint != expected.fingerprint
    ):
        raise FinalRequestCompilationError(f"prepared {label} is not the unique graph object")
    return matches[0]


def _validated_prepared_market_context(prepared: PreparedMarketReference) -> Any:
    """Replay the exact accepted market objects before any numeric projection."""

    snapshot = prepared.snapshot
    snapshot_id = getattr(snapshot, "snapshot_id", None)
    snapshot_fingerprint = getattr(snapshot, "fingerprint", None)
    snapshot_matches = tuple(
        item
        for item in prepared.graph.market_reference_snapshots
        if getattr(item, "snapshot_id", None) == snapshot_id
    )
    if (
        not snapshot_id
        or not snapshot_fingerprint
        or len(snapshot_matches) != 1
        or snapshot_matches[0] != snapshot
        or getattr(snapshot_matches[0], "fingerprint", None) != snapshot_fingerprint
        or snapshot.status != "validated"
    ):
        raise FinalRequestCompilationError(
            "prepared Snapshot is not the unique accepted graph object"
        )
    source = _unique_exact_graph_object(
        prepared.graph.documents,
        expected=prepared.market_source,
        identifier_field="document_id",
        expected_type=SourceDocument,
        label="market SourceDocument",
    )
    quote = _unique_exact_graph_object(
        prepared.graph.facts,
        expected=prepared.quote_fact,
        identifier_field="fact_id",
        expected_type=Fact,
        label="quote Fact",
    )
    calculation = _unique_exact_graph_object(
        prepared.graph.calculations,
        expected=prepared.market_equity_calculation,
        identifier_field="calculation_id",
        expected_type=CalculationResult,
        label="market-equity CalculationResult",
    )
    current = prepared.current_shares
    if type(current) is not CurrentShareCompilationResult:
        raise FinalRequestCompilationError(
            "prepared current-share compilation has a substituted runtime type"
        )
    output = current.output_fact
    if output is None:
        raise FinalRequestCompilationError("prepared current-share compilation has no output")
    _unique_exact_graph_object(
        prepared.graph.facts,
        expected=output,
        identifier_field="fact_id",
        expected_type=Fact,
        label="current-share output Fact",
    )
    contexts = tuple(
        item
        for item in prepared.graph.market_reference_validation_contexts
        if item.market_access_result.fingerprint == snapshot.market_access_result_fingerprint
    )
    if len(contexts) != 1:
        raise FinalRequestCompilationError("market reference lacks one matched validation context")
    context = contexts[0]
    access = context.market_access_result
    context_current = context.current_share_compilation_result
    cutoff = date.fromisoformat(snapshot.data_cutoff_date)
    trading_date = date.fromisoformat(snapshot.trading_date)
    expected_context_id = _canonical_market_validation_context_id(
        issuer_id=snapshot.issuer_id,
        trading_date=snapshot.trading_date,
        raw_response_sha256=snapshot.raw_evidence["raw_response_sha256"],
    )
    if (
        getattr(context, "context_id", "") != expected_context_id
        or not getattr(context, "fingerprint", "")
        or type(context_current) is not CurrentShareCompilationResult
        or context_current != current
        or context_current.fingerprint != current.fingerprint
        or access.status != "eligible"
        or access.request is None
        or access.receipt is None
        or access.issuer_id != snapshot.issuer_id
        or access.data_cutoff_date != snapshot.data_cutoff_date
        or access.price_blind_input_fingerprint != snapshot.price_blind_input_fingerprint
        or access.protected_mckinsey_sha256 != snapshot.protected_mckinsey_sha256
        or access.protected_penman_assumptions_sha256
        != snapshot.protected_penman_assumptions_sha256
        or current.status != "eligible"
        or current.issuer_id != snapshot.issuer_id
        or current.data_cutoff_date != snapshot.data_cutoff_date
        or current.security_id != snapshot.security["security_id"]
        or current.quote_date != snapshot.trading_date
        or source.issuer_id != snapshot.issuer_id
        or quote.issuer_id != snapshot.issuer_id
        or calculation.issuer_id != snapshot.issuer_id
        or output.issuer_id != snapshot.issuer_id
        or source.period["end"] != snapshot.trading_date
        or quote.period["end"] != snapshot.trading_date
        or calculation.period["end"] != snapshot.trading_date
        or output.period["end"] != snapshot.trading_date
        or date.fromisoformat(source.published_date) > cutoff
        or trading_date > cutoff
    ):
        raise FinalRequestCompilationError(
            "prepared market evidence does not replay its accepted validation context"
        )
    return context


def _governed_market_authority(
    prepared: PreparedMarketReference,
    context: Any,
) -> dict[str, str]:
    snapshot = prepared.snapshot
    access = context.market_access_result
    request = access.request
    governed = access.receipt
    if request is None or governed is None:
        raise FinalRequestCompilationError("market validation context is incomplete")
    receipt = governed.receipt
    snapshot_request = snapshot.market_quote_request
    snapshot_receipt = snapshot.governed_market_quote_receipt
    if (
        request.request_id != snapshot_request["request_id"]
        or request.request_fingerprint != snapshot_request["request_fingerprint"]
        or receipt.receipt_id != snapshot_receipt["receipt_id"]
        or governed.fingerprint != snapshot_receipt["receipt_fingerprint"]
        or receipt.request_id != request.request_id
        or receipt.request_fingerprint != request.request_fingerprint
        or request.provider_id != receipt.provider_id
        or request.security_id != snapshot.security["security_id"]
        or receipt.security_id != snapshot.security["security_id"]
        or request.authorization_handoff_id != snapshot.authorization_handoff_id
        or receipt.authorization_handoff_id != snapshot.authorization_handoff_id
        or request.data_cutoff_date != snapshot.data_cutoff_date
        or receipt.data_cutoff_date != snapshot.data_cutoff_date
        or governed.provider_registration_sha256
        != snapshot.authority_lineage["provider_registration_sha256"]
        or governed.raw_response_sha256 != snapshot.raw_evidence["raw_response_sha256"]
    ):
        raise FinalRequestCompilationError(
            "market provider identity does not replay the validated Snapshot"
        )
    if not request.provider_id.strip() or not request.price_basis.strip():
        raise FinalRequestCompilationError("market provider identity is empty")
    return {
        "context_id": context.context_id,
        "context_fingerprint": context.fingerprint,
        "access_fingerprint": access.fingerprint,
        "provider_id": request.provider_id,
        "provider_registration_sha256": governed.provider_registration_sha256,
        "price_basis": request.price_basis,
        "receipt_id": receipt.receipt_id,
        "receipt_fingerprint": governed.fingerprint,
        "raw_response_sha256": governed.raw_response_sha256,
    }


def _market_source(
    prepared: PreparedMarketReference,
    authority: dict[str, str],
) -> dict[str, Any]:
    document = prepared.market_source
    if (
        document.document_id != prepared.snapshot.quote_source_document_id
        or document.authority_level != "market_reference"
        or document.content_sha256 != prepared.snapshot.raw_evidence["raw_response_sha256"]
    ):
        raise FinalRequestCompilationError("market SourceDocument does not replay Snapshot")
    security_id = prepared.snapshot.security["security_id"]
    return {
        "source_id": document.document_id,
        "title": (
            f"{authority['provider_id']} {authority['price_basis']} "
            f"for {security_id} on {prepared.snapshot.trading_date}"
        ),
        "publisher": authority["provider_id"],
        "published_date": document.published_date,
        "retrieved_at": document.retrieved_at,
        "locator": (f"document_id={document.document_id};content_sha256={document.content_sha256}"),
        "url": document.source_url,
        "local_path": None,
        "primary": False,
    }


def _market_facts(
    prepared: PreparedMarketReference,
    share_projection: CurrentShareKernelProjection,
    reporting_currency: str,
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    KernelNumericProjectionWitness,
    KernelNumericProjectionWitness,
]:
    snapshot = prepared.snapshot
    quote_decimal = Decimal(snapshot.quote_price_decimal)
    market_decimal = Decimal(snapshot.market_equity["value_decimal"])
    quote_witness = KernelNumericProjectionWitness.compile(
        label=f"quote:{snapshot.quote_fact_id}",
        authoritative_decimal=quote_decimal,
    )
    share_fact = next(
        item
        for item in share_projection.facts
        if item["fact_id"] == share_projection.current_share_fact_id
    )
    projected_market_value = quote_witness.kernel_value * float(share_fact["value"])
    market_witness = KernelNumericProjectionWitness.compile_from_projected_binary64(
        label=f"market-equity:{snapshot.market_equity['calculation_id']}",
        authoritative_decimal=market_decimal,
        projected_value=projected_market_value,
        scale_divisor=Decimal(1_000_000),
    )
    authoritative_market_equity = _exact_decimal_multiply(
        quote_decimal,
        Decimal(snapshot.share_basis["current_common_shares_outstanding_decimal"]),
        "authoritative market equity",
    )
    if market_decimal != authoritative_market_equity:
        raise FinalRequestCompilationError("authoritative market-equity Decimal changed")
    quote = prepared.quote_fact
    if (
        quote.fact_id != snapshot.quote_fact_id
        or quote.period["end"] != snapshot.trading_date
        or quote.source_document_id != prepared.market_source.document_id
        or Decimal(str(quote.value)) != quote_decimal
    ):
        raise FinalRequestCompilationError("research quote Fact does not replay Snapshot")
    quote_fact = {
        "fact_id": quote.fact_id,
        "concept": "market_price_per_current_common_share",
        "value": quote_witness.kernel_value,
        "unit": f"{reporting_currency} per share",
        "category": "market_price",
        "source_id": prepared.market_source.document_id,
        "source_location": quote.source_locator,
        "as_of_date": snapshot.trading_date,
        "currency": reporting_currency,
        "period_start": None,
        "period_end": None,
        "confidence": "high",
        "raw": True,
        "parent_fact_ids": [],
        "derivation": None,
        "equity_bridge_role": None,
    }
    calculation = prepared.market_equity_calculation
    if (
        calculation.calculation_id != snapshot.market_equity["calculation_id"]
        or tuple(calculation.input_fact_ids)
        != (quote.fact_id, share_projection.current_share_fact_id)
        or calculation.input_assumption_ids
        or Decimal(str(calculation.value)) != market_decimal
    ):
        raise FinalRequestCompilationError(
            "research market-equity CalculationResult does not replay Snapshot"
        )
    confidence = max(
        (str(share_fact["confidence"]), "high"),
        key=lambda item: {"high": 0, "medium": 1, "low": 2, "unknown": 3}[item],
    )
    market_fact = {
        "fact_id": f"derived:{calculation.calculation_id}",
        "concept": "market_equity_value",
        "value": market_witness.kernel_value,
        "unit": f"{reporting_currency} millions",
        "category": "market_price",
        "source_id": prepared.market_source.document_id,
        "source_location": f"derived:{calculation.calculation_id}",
        "as_of_date": snapshot.trading_date,
        "currency": reporting_currency,
        "period_start": None,
        "period_end": None,
        "confidence": confidence,
        "raw": False,
        "parent_fact_ids": [quote_fact["fact_id"], share_projection.current_share_fact_id],
        "derivation": _MARKET_EQUITY_DERIVATION,
        "equity_bridge_role": None,
    }
    return quote_fact, market_fact, quote_witness, market_witness


def _validate_price_blind_base_ledger(
    base_ledger: dict[str, Any],
    prepared: PreparedMarketReference,
) -> None:
    forbidden_concepts = {
        "market_price_per_current_common_share",
        "market_equity_value",
    }
    sources = tuple(base_ledger["sources"])
    source_ids = tuple(str(item["source_id"]) for item in sources)
    source_id_set = set(source_ids)
    if len(source_ids) != len(source_id_set):
        raise FinalRequestCompilationError("price-blind FactLedger repeats a SourceRef")
    market_source_id = prepared.market_source.document_id
    if market_source_id in source_id_set:
        raise FinalRequestCompilationError(
            "price-blind FactLedger already contains the governed market source"
        )
    facts = tuple(base_ledger["facts"])
    fact_ids = tuple(str(item["fact_id"]) for item in facts)
    if len(fact_ids) != len(set(fact_ids)):
        raise FinalRequestCompilationError("price-blind FactLedger repeats a Fact")
    for item in facts:
        if (
            item.get("concept") in forbidden_concepts
            or item.get("category") == "market_price"
            or item.get("source_id") == market_source_id
        ):
            raise FinalRequestCompilationError(
                "price-blind FactLedger contains market-price lineage"
            )
        if item.get("source_id") not in source_id_set:
            raise FinalRequestCompilationError(
                "price-blind FactLedger contains dangling source lineage"
            )


def _compile_fact_ledger(
    *,
    base_ledger: dict[str, Any],
    prepared: PreparedMarketReference,
) -> FinalFactLedgerCompilationResult:
    snapshot = prepared.snapshot
    if (
        base_ledger.get("entity_id") != snapshot.issuer_id
        or base_ledger.get("valuation_date") != snapshot.trading_date
        or base_ledger.get("reporting_currency") != snapshot.quote_currency
    ):
        raise FinalRequestCompilationError(
            "market reference and price-blind FactLedger identity/date/currency differ"
        )
    context = _validated_prepared_market_context(prepared)
    _validate_price_blind_base_ledger(base_ledger, prepared)
    projection = project_current_share_lineage(prepared)
    if projection.status == "specialist_required":
        raise FinalRequestCompilationError("current-share lineage requires specialist routing")
    if projection.status != "eligible":
        raise FinalRequestCompilationError("current-share lineage is not kernel eligible")
    reporting_currency = str(base_ledger["reporting_currency"])
    market_authority = _governed_market_authority(prepared, context)
    quote, market, quote_witness, market_witness = _market_facts(
        prepared,
        projection,
        reporting_currency,
    )
    base_sources = [dict(item) for item in base_ledger["sources"]]
    base_facts = [dict(item) for item in base_ledger["facts"]]
    base_source_fingerprints = tuple(
        sorted((str(item["source_id"]), canonical_sha256(item)) for item in base_sources)
    )
    base_fact_fingerprints = tuple(
        sorted((str(item["fact_id"]), canonical_sha256(item)) for item in base_facts)
    )
    projected_sources = tuple(to_json_value(item) for item in projection.sources)
    sources, share_source_ids = _append_by_id(
        base_sources,
        projected_sources,
        field="source_id",
    )
    market_source = _market_source(prepared, market_authority)
    sources, market_source_ids = _append_by_id(
        sources,
        (market_source,),
        field="source_id",
    )
    projected_facts = tuple(to_json_value(item) for item in projection.facts)
    facts, share_fact_ids = _append_by_id(base_facts, projected_facts, field="fact_id")
    facts, market_fact_ids = _append_by_id(facts, (quote, market), field="fact_id")
    payload = {
        "schema_version": "1.0.0",
        "entity_id": base_ledger["entity_id"],
        "valuation_date": base_ledger["valuation_date"],
        "reporting_currency": reporting_currency,
        "sources": sources,
        "facts": facts,
    }
    for identifier, fingerprint in base_source_fingerprints:
        item = next(value for value in payload["sources"] if value["source_id"] == identifier)
        if canonical_sha256(item) != fingerprint:
            raise FinalRequestCompilationError("price-blind SourceRef changed during append")
    for identifier, fingerprint in base_fact_fingerprints:
        item = next(value for value in payload["facts"] if value["fact_id"] == identifier)
        if canonical_sha256(item) != fingerprint:
            raise FinalRequestCompilationError("price-blind Fact changed during append")
    return FinalFactLedgerCompilationResult(
        policy_id=FINAL_REQUEST_POLICY_ID,
        policy_version=FINAL_REQUEST_POLICY_VERSION,
        base_ledger_sha256=canonical_sha256(base_ledger),
        base_ledger_payload=freeze(base_ledger),
        base_source_fingerprints=base_source_fingerprints,
        base_fact_fingerprints=base_fact_fingerprints,
        current_share_projection=projection,
        quote_projection_witness=quote_witness,
        market_equity_projection_witness=market_witness,
        market_provider_id=market_authority["provider_id"],
        market_provider_registration_sha256=market_authority["provider_registration_sha256"],
        market_provider_receipt_id=market_authority["receipt_id"],
        market_provider_receipt_fingerprint=market_authority["receipt_fingerprint"],
        market_validation_context_id=market_authority["context_id"],
        market_validation_context_fingerprint=market_authority["context_fingerprint"],
        market_access_result_fingerprint=market_authority["access_fingerprint"],
        current_share_compilation_fingerprint=prepared.current_shares.fingerprint,
        market_source_document_id=prepared.market_source.document_id,
        market_source_document_fingerprint=prepared.market_source.fingerprint,
        market_source_ref_fingerprint=canonical_sha256(market_source),
        market_raw_response_sha256=market_authority["raw_response_sha256"],
        market_quote_fact_id=prepared.quote_fact.fact_id,
        market_quote_fact_fingerprint=prepared.quote_fact.fingerprint,
        market_equity_calculation_id=prepared.market_equity_calculation.calculation_id,
        market_equity_calculation_fingerprint=(prepared.market_equity_calculation.fingerprint),
        market_evidence_binding_sha256=_market_evidence_binding_sha256(
            context_id=market_authority["context_id"],
            context_fingerprint=market_authority["context_fingerprint"],
            access_fingerprint=market_authority["access_fingerprint"],
            provider_id=market_authority["provider_id"],
            provider_registration_sha256=market_authority["provider_registration_sha256"],
            receipt_id=market_authority["receipt_id"],
            receipt_fingerprint=market_authority["receipt_fingerprint"],
            current_share_compilation_fingerprint=prepared.current_shares.fingerprint,
            source_document_id=prepared.market_source.document_id,
            source_document_fingerprint=prepared.market_source.fingerprint,
            source_ref_fingerprint=canonical_sha256(market_source),
            raw_response_sha256=market_authority["raw_response_sha256"],
            quote_fact_id=prepared.quote_fact.fact_id,
            quote_fact_fingerprint=prepared.quote_fact.fingerprint,
            calculation_id=prepared.market_equity_calculation.calculation_id,
            calculation_fingerprint=prepared.market_equity_calculation.fingerprint,
        ),
        added_source_ids=(*share_source_ids, *market_source_ids),
        added_fact_ids=(*share_fact_ids, *market_fact_ids),
        fact_ledger_payload=freeze(payload),
    )


def _compile_assumption_ledger(
    base: dict[str, Any],
    final_fact_ledger: dict[str, Any],
) -> FinalAssumptionLedgerCompilationResult:
    assumptions_before = to_json_value(base["assumptions"])
    assumption_ids = tuple(str(item.get("assumption_id", "")) for item in assumptions_before)
    if (
        any(not identifier for identifier in assumption_ids)
        or len(assumption_ids) != len(set(assumption_ids))
        or assumption_ids != tuple(sorted(assumption_ids))
    ):
        raise FinalRequestCompilationError(
            "AssumptionLedger entries are not uniquely sorted by assumption_id"
        )
    normalized_entries: list[dict[str, Any]] = []
    for item in assumptions_before:
        value = item.get("value")
        try:
            projected = float(value)
        except (OverflowError, TypeError, ValueError) as exc:
            raise FinalRequestCompilationError(
                "AssumptionLedger value is not a finite rc.2 number"
            ) from exc
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(projected)
        ):
            raise FinalRequestCompilationError("AssumptionLedger value is not a finite rc.2 number")
        normalized = dict(item)
        normalized["value"] = projected
        normalized_entries.append(normalized)
    if canonical_json(assumptions_before) != canonical_json(normalized_entries):
        raise FinalRequestCompilationError(
            "AssumptionLedger entries are not in canonical rc.2 representation"
        )
    entries_sha = canonical_sha256(assumptions_before)
    final_fingerprint = canonical_sha256(final_fact_ledger)
    payload = {
        "schema_version": base["schema_version"],
        "fact_ledger_fingerprint": final_fingerprint,
        "assumptions": assumptions_before,
    }
    if canonical_json(payload["assumptions"]) != canonical_json(base["assumptions"]):
        raise FinalRequestCompilationError("assumption entries changed during ledger rebinding")
    return FinalAssumptionLedgerCompilationResult(
        assumption_entries_sha256=entries_sha,
        prior_fact_ledger_fingerprint=str(base["fact_ledger_fingerprint"]),
        final_fact_ledger_fingerprint=final_fingerprint,
        assumption_ledger_payload=freeze(payload),
    )


def _bound_research_bundle_closure(
    prepared: PreparedMarketReference,
) -> dict[str, tuple[str, Any]]:
    snapshot = prepared.snapshot
    handoffs = tuple(
        item
        for item in prepared.graph.valuation_handoffs
        if item.handoff_id == snapshot.authorization_handoff_id
    )
    if len(handoffs) != 1:
        raise FinalRequestCompilationError("company identity lacks one authorization Handoff")
    handoff = handoffs[0]
    bundles = tuple(
        item
        for item in prepared.graph.research_bundles
        if item.bundle_id == handoff.research_bundle_id
    )
    if len(bundles) != 1:
        raise FinalRequestCompilationError("company identity lacks one bound ResearchBundle")
    bundle = bundles[0]
    if (
        handoff.state != "market_reference_allowed"
        or handoff.fingerprint != snapshot.authorization_handoff_fingerprint
        or handoff.issuer_id != snapshot.issuer_id
        or handoff.data_cutoff_date != snapshot.data_cutoff_date
        or bundle.issuer_id != snapshot.issuer_id
        or bundle.data_cutoff_date != snapshot.data_cutoff_date
        or handoff.research_bundle_fingerprint != bundle.bundle_fingerprint
        or handoff.research_bundle_dependency_sha256 != bundle.dependency_closure_sha256
        or handoff.component_lock_sha256 != snapshot.component_lock_sha256
    ):
        raise FinalRequestCompilationError(
            "company identity ResearchBundle binding does not replay"
        )
    roots = tuple(
        object_id for reference in bundle.module_references for object_id in reference["object_ids"]
    )
    try:
        closure = dependency_closure(prepared.graph, roots)
    except ResearchBundleValidationError as exc:
        raise FinalRequestCompilationError(
            "company identity ResearchBundle dependency closure is invalid"
        ) from exc
    closure_entries = [
        (kind, identifier, item.fingerprint) for identifier, (kind, item) in closure.items()
    ]
    if dependency_closure_sha256(closure_entries) != bundle.dependency_closure_sha256:
        raise FinalRequestCompilationError(
            "company identity ResearchBundle dependency hash does not replay"
        )
    return closure


def _governed_company_name(
    prepared: PreparedMarketReference,
) -> tuple[str, Fact, SourceDocument]:
    snapshot = prepared.snapshot
    closure = _bound_research_bundle_closure(prepared)
    documents = {item.document_id: item for item in prepared.graph.documents}
    candidates: list[tuple[Any, Any]] = []
    for fact in prepared.graph.facts:
        document = documents.get(fact.source_document_id)
        if (
            fact.issuer_id == snapshot.issuer_id
            and fact.concept == "issuer_legal_name"
            and fact.value_type == "text"
            and isinstance(fact.value, str)
            and fact.derivation is None
            and not fact.parent_fact_ids
            and fact.confidence in {"high", "medium"}
            and fact.period["end"] is not None
            and fact.period["end"] <= snapshot.data_cutoff_date
            and document is not None
            and document.issuer_id == snapshot.issuer_id
            and document.authority_level in {"primary_regulatory", "company_primary"}
            and document.published_date <= snapshot.data_cutoff_date
            and _source_is_registered(document)
            and closure.get(fact.fact_id) == ("Fact", fact)
            and closure.get(document.document_id) == ("SourceDocument", document)
        ):
            candidates.append((fact, document))
    if len(candidates) != 1:
        raise FinalRequestCompilationError("company legal name lacks one official cutoff-safe Fact")
    fact, document = candidates[0]
    canonical_name = unicodedata.normalize("NFC", fact.value)
    if (
        canonical_name != fact.value
        or canonical_name != " ".join(canonical_name.split())
        or not canonical_name
    ):
        raise FinalRequestCompilationError("company legal name is not canonical text")
    return canonical_name, fact, document


def _request_company(
    phase5c: dict[str, Any],
    prepared: PreparedMarketReference,
) -> tuple[dict[str, Any], str, Fact, SourceDocument]:
    classification = phase5c["reconciliation_result"]["phase5b_readiness_result"]["classification"]
    if (
        classification["specialist_route"] != "none"
        or classification["company_type"] != "nonfinancial_operating_company"
    ):
        raise FinalRequestCompilationError("company classification requires specialist routing")
    source_fact_ids = tuple(sorted(classification["mapped_fact_ids"]))
    if not source_fact_ids:
        raise FinalRequestCompilationError("company classification lacks mapped evidence")
    legal_name, legal_name_fact, legal_name_source = _governed_company_name(prepared)
    return (
        {
            "name": legal_name,
            "type": classification["company_type"],
            "classification_rationale": classification["rationale"],
            "source_fact_ids": list(source_fact_ids),
        },
        legal_name,
        legal_name_fact,
        legal_name_source,
    )


def _request_routing(phase5c: dict[str, Any], assumptions: dict[str, Any]) -> dict[str, Any]:
    if phase5c["specialist_route"] != "none" or any(
        phase5c["method_panels"][method]["status"] != "ready_for_phase5d"
        for method in ("mckinsey", "penman")
    ):
        raise FinalRequestCompilationError("Phase 5C is not ready for the core dual panel")
    assumption_fact_ids = sorted(
        {fact_id for item in assumptions["assumptions"] for fact_id in item["source_fact_ids"]}
    )
    if not assumption_fact_ids:
        raise FinalRequestCompilationError("near-term assumptions lack source Facts")
    output: dict[str, Any] = {}
    for key, assessment in phase5c["routing_assessments"].items():
        if key in {"required_data_complete", "credible_near_term_earnings"}:
            output[key] = {
                "value": True,
                "rationale": (
                    "The named-human-reviewed price-blind assumptions and complete request "
                    "inputs are present."
                    if key == "required_data_complete"
                    else "Named-human-reviewed near-term forecast assumptions are present."
                ),
                "source_fact_ids": assumption_fact_ids,
            }
            continue
        if assessment["status"] != "satisfied" or assessment["value"] is not True:
            raise FinalRequestCompilationError(f"routing assessment is not satisfied: {key}")
        fact_ids = sorted(assessment["evidence_fact_ids"])
        if not fact_ids:
            raise FinalRequestCompilationError(f"routing assessment lacks evidence: {key}")
        output[key] = {
            "value": True,
            "rationale": assessment["rationale"],
            "source_fact_ids": fact_ids,
        }
    return output


def _request_accounting(phase5c: dict[str, Any], final_ledger: dict[str, Any]) -> dict[str, Any]:
    checks = phase5c["reconciliation_result"]["checks"]
    balance = checks["balance_sheet"]
    clean = checks["clean_surplus"]
    if (
        balance["status"] != "reconciles_independently"
        or clean["status"] != "reconciles_independently"
    ):
        raise FinalRequestCompilationError("accounting checks are not independently reconciled")
    quality = phase5c["quality_result"]
    if any(quality["status_by_method"][method] != "pass" for method in ("mckinsey", "penman")):
        raise FinalRequestCompilationError("accounting quality blocks a dual-panel request")
    decisions = {item["finding_id"]: item for item in quality["issue_decisions"]}
    issues = []
    for item in quality["kernel_quality_issues"]:
        decision = decisions.get(item["issue_id"])
        if decision is None:
            raise FinalRequestCompilationError("accounting issue lacks its reviewed decision")
        issues.append(
            {
                **item,
                "rationale": (
                    f"Reviewed accounting-quality finding {item['issue_id']} was classified "
                    f"as {decision['disposition']}."
                ),
            }
        )
    ledger_facts = {item["fact_id"]: item for item in final_ledger["facts"]}
    liability_decisions = tuple(
        item
        for item in phase5c["reconciliation_result"]["fact_decisions"]
        if item["purpose"] == "adjusted_total_liabilities"
    )
    if len(liability_decisions) != 1 or liability_decisions[0]["disposition"] != "emitted":
        raise FinalRequestCompilationError(
            "adjusted-liabilities decision is unavailable or unresolved"
        )
    liability_terms = {
        item["input_role"]: tuple(item["fact_ids"])
        for item in liability_decisions[0]["term_bindings"]
    }
    if set(liability_terms) != {
        "total_liabilities",
        "equity_classified_non_common_claims",
    }:
        raise FinalRequestCompilationError(
            "adjusted-liabilities decision has an invalid term perimeter"
        )
    if liability_terms["equity_classified_non_common_claims"]:
        raise FinalRequestCompilationError(
            "equity-classified non-common claims require specialist accounting"
        )
    liability_roots = liability_terms["total_liabilities"]
    total_liabilities = tuple(
        ledger_facts[fact_id]
        for fact_id in liability_roots
        if fact_id in ledger_facts
        and ledger_facts[fact_id]["concept"] == "total_liabilities"
        and ledger_facts[fact_id]["raw"] is True
        and ledger_facts[fact_id]["period_start"] is None
        and ledger_facts[fact_id]["period_end"] is None
        and ledger_facts[fact_id]["currency"] == final_ledger["reporting_currency"]
        and ledger_facts[fact_id]["unit"] == f"{final_ledger['reporting_currency']} millions"
    )
    if len(total_liabilities) != 1:
        raise FinalRequestCompilationError(
            "balance-sheet reconciliation lacks one raw total-liabilities root"
        )
    balance_fact_ids = (
        balance["role_fact_ids"]["total_assets"],
        total_liabilities[0]["fact_id"],
        balance["role_fact_ids"]["common_equity"],
    )
    if any(fact_id not in ledger_facts for fact_id in balance_fact_ids):
        raise FinalRequestCompilationError("balance-sheet reconciliation Fact is absent")
    balance_facts = tuple(ledger_facts[fact_id] for fact_id in balance_fact_ids)
    if (
        len({item["as_of_date"] for item in balance_facts}) != 1
        or any(item["period_start"] is not None for item in balance_facts)
        or any(item["period_end"] is not None for item in balance_facts)
        or {item["currency"] for item in balance_facts} != {final_ledger["reporting_currency"]}
        or {item["unit"] for item in balance_facts}
        != {f"{final_ledger['reporting_currency']} millions"}
    ):
        raise FinalRequestCompilationError(
            "balance-sheet reconciliation perimeter is not comparable"
        )
    return {
        "balance_sheet": {
            "assets_fact_id": balance["role_fact_ids"]["total_assets"],
            "liabilities_fact_id": total_liabilities[0]["fact_id"],
            "equity_fact_id": balance["role_fact_ids"]["common_equity"],
        },
        "clean_surplus": {
            "beginning_equity_fact_id": clean["role_fact_ids"]["beginning_common_equity"],
            "comprehensive_income_fact_id": clean["role_fact_ids"][
                "comprehensive_income_attributable_to_common"
            ],
            "net_distributions_fact_id": clean["role_fact_ids"]["net_distributions_to_owners"],
            "ending_equity_fact_id": clean["role_fact_ids"]["ending_common_equity"],
        },
        "quality_issues": issues,
    }


def _request_method_views(phase5c: dict[str, Any]) -> dict[str, Any]:
    method = phase5c["method_view_result"]
    decisions = {
        item["adjustment_id"]: item
        for item in method["adjustment_decisions"]
        if item["disposition"] == "compiled"
    }
    output: dict[str, list[dict[str, Any]]] = {}
    for name in ("mckinsey", "penman"):
        entries = []
        for item in method["method_views"][name]:
            decision = decisions.get(item["adjustment_id"])
            if decision is None or decision["method"] != name:
                raise FinalRequestCompilationError("MethodView entry lacks compiled decision")
            entries.append(
                {
                    "adjustment_id": item["adjustment_id"],
                    "adjustment_group_id": decision["adjustment_group_id"],
                    "category": decision["category"],
                    "target_fact_id": item["target_fact_id"],
                    "amount_fact_id": item["amount_fact_id"],
                    "rationale": decision["rationale"],
                }
            )
        output[f"{name}_adjustments"] = entries
    return output


def _validate_forecast_axis(
    *,
    valuation_date: str,
    mckinsey_scenarios: list[dict[str, Any]],
    penman_payload: dict[str, Any],
) -> None:
    anchor = date.fromisoformat(valuation_date)

    def annual_axis(
        rows: list[dict[str, Any]],
        label: str,
        *,
        start: date,
    ) -> tuple[str, ...]:
        if not rows:
            raise FinalRequestCompilationError(f"{label} forecast is empty")
        previous = start
        values: list[str] = []
        for row in rows:
            current = date.fromisoformat(row["period_end"])
            if not 360 <= (current - previous).days <= 373:
                raise FinalRequestCompilationError(
                    f"{label} forecast is not based on the final valuation-date annual axis"
                )
            values.append(current.isoformat())
            previous = current
        return tuple(values)

    scenario_axes = {
        annual_axis(
            list(item["forecast"]),
            f"McKinsey {item['name']}",
            start=anchor,
        )
        for item in mckinsey_scenarios
    }
    if len(scenario_axes) != 1:
        raise FinalRequestCompilationError("McKinsey scenarios do not share one annual axis")
    penman_axis = annual_axis(
        list(penman_payload["forecast"]),
        "Penman",
        start=anchor,
    )
    mckinsey_axis = next(iter(scenario_axes))
    if penman_axis != mckinsey_axis[: len(penman_axis)]:
        raise FinalRequestCompilationError("McKinsey and Penman forecast axes differ")
    annual_axis(
        list(penman_payload["market_challenge_path"]),
        "Penman challenge",
        start=date.fromisoformat(penman_axis[-1]),
    )


def _compile_from_artifact(
    *,
    prepared: PreparedMarketReference,
    artifact: dict[str, Any],
    kernel_repository: Path,
) -> FinalValuationRequestCompilationResult:
    """Compile from a replayed artifact; kept internal for deterministic tests."""

    _kernel, schemas = _verify_kernel(kernel_repository)
    snapshot = prepared.snapshot
    if (
        artifact["issuer_id"] != snapshot.issuer_id
        or artifact["data_cutoff_date"] != snapshot.data_cutoff_date
        or artifact["price_blind_input_fingerprint"] != snapshot.price_blind_input_fingerprint
        or artifact["protected_mckinsey_sha256"] != snapshot.protected_mckinsey_sha256
        or artifact["protected_penman_assumptions_sha256"]
        != snapshot.protected_penman_assumptions_sha256
        or artifact["component_lock_sha256"] != snapshot.component_lock_sha256
    ):
        raise FinalRequestCompilationError("prepared market reference changed the frozen input")
    identity = artifact["kernel_identity"]
    if (
        identity["tag"] != PINNED_KERNEL_TAG
        or identity["commit"] != PINNED_KERNEL_COMMIT
        or identity["public_schema_sha256"] != PINNED_KERNEL_SCHEMA_SHA256
    ):
        raise FinalRequestCompilationError("price-blind artifact does not bind pinned rc.2")
    reviewed = artifact["reviewed_assumptions"]
    base_ledger = to_json_value(reviewed["augmented_fact_ledger_payload"])
    base_assumptions = to_json_value(reviewed["assumption_ledger_payload"])
    if (
        canonical_sha256(base_ledger) != base_assumptions["fact_ledger_fingerprint"]
        or canonical_sha256(base_assumptions["assumptions"])
        != reviewed["assumption_entries_sha256"]
    ):
        raise FinalRequestCompilationError("price-blind ledgers do not replay")
    fact_result = _compile_fact_ledger(base_ledger=base_ledger, prepared=prepared)
    final_ledger = to_json_value(fact_result.fact_ledger_payload)
    assumption_result = _compile_assumption_ledger(base_assumptions, final_ledger)
    final_assumptions = to_json_value(assumption_result.assumption_ledger_payload)
    phase5c = to_json_value(artifact["phase5c_readiness"])
    mckinsey = to_json_value(artifact["mckinsey_inputs"])
    penman = to_json_value(artifact["penman_inputs"])
    current_fact_id = fact_result.current_share_projection.current_share_fact_id
    market_fact_id = next(
        fact_id
        for fact_id in fact_result.added_fact_ids
        if fact_id.startswith("derived:")
        and next(item for item in final_ledger["facts"] if item["fact_id"] == fact_id)["concept"]
        == "market_equity_value"
    )
    bridge = phase5c["equity_bridge_result"]
    company, company_legal_name, company_name_fact, company_name_source = _request_company(
        phase5c,
        prepared,
    )
    _validate_forecast_axis(
        valuation_date=final_ledger["valuation_date"],
        mckinsey_scenarios=mckinsey["scenario_payload"]["scenarios"],
        penman_payload=penman["penman_payload"],
    )
    request = {
        "schema_version": "2.0.0",
        "model_unit": f"{final_ledger['reporting_currency']} millions",
        "share_unit": _MODEL_SHARE_UNIT,
        "fact_ledger": final_ledger,
        "assumption_ledger": final_assumptions,
        "company": company,
        "routing_assessments": _request_routing(phase5c, final_assumptions),
        "accounting_checks": _request_accounting(phase5c, final_ledger),
        "method_views": _request_method_views(phase5c),
        "mckinsey": {
            "base_invested_capital_fact_id": mckinsey["base_invested_capital_fact_id"],
            "scenarios": mckinsey["scenario_payload"]["scenarios"],
            "equity_bridge": {
                "share_denominator_fact_id": current_fact_id,
                "share_denominator_kind": "current_common_shares_outstanding",
                "share_denominator_evidence_kind": (
                    fact_result.current_share_projection.evidence_kind
                ),
                "items": bridge["bridge_items"],
                "role_assertions": bridge["role_assertions"],
            },
        },
        "penman": {
            "current_noa_fact_id": penman["current_noa_fact_id"],
            "market_equity_value_fact_id": market_fact_id,
            "net_financial_obligations_fact_id": penman["net_financial_obligations_fact_id"],
            **penman["penman_payload"],
        },
    }
    if request["mckinsey"]["equity_bridge"]["share_denominator_fact_id"] != next(
        item["parent_fact_ids"][1]
        for item in final_ledger["facts"]
        if item["fact_id"] == market_fact_id
    ):
        raise FinalRequestCompilationError("McKinsey and Penman use different share Facts")
    _validate_request_schema(request, schemas)
    return FinalValuationRequestCompilationResult(
        status="compiled",
        issuer_id=snapshot.issuer_id,
        valuation_date=snapshot.trading_date,
        price_blind_input_fingerprint=artifact["price_blind_input_fingerprint"],
        prepared_market_reference_fingerprint=prepared.fingerprint,
        company_legal_name_value=company_legal_name,
        company_name_fact_id=company_name_fact.fact_id,
        company_name_fact_fingerprint=company_name_fact.fingerprint,
        company_name_source_document_id=company_name_source.document_id,
        company_name_source_document_fingerprint=company_name_source.fingerprint,
        company_identity_binding_sha256=_company_identity_binding_sha256(
            issuer_id=snapshot.issuer_id,
            legal_name=company_legal_name,
            fact_id=company_name_fact.fact_id,
            fact_fingerprint=company_name_fact.fingerprint,
            source_document_id=company_name_source.document_id,
            source_document_fingerprint=company_name_source.fingerprint,
        ),
        fact_ledger_result=fact_result,
        assumption_ledger_result=assumption_result,
        request_payload=freeze(request),
        canonical_request_json=canonical_json(request),
        request_sha256=canonical_sha256(request),
        issue_codes=(),
    )


def compile_final_valuation_request(
    *,
    preparation: OwnerValuationPreparationResult,
    expected_freeze: PriceBlindFreezeCompilationResult,
    kernel_repository: Path,
) -> FinalValuationRequestCompilationResult:
    """Compile a complete rc.2 request from one replayed price-blind/market pair."""

    if preparation.status != "prepared" or preparation.prepared_market_reference is None:
        return _noncompiled(
            preparation=preparation,
            status=(
                "specialist_required" if preparation.status == "specialist_required" else "blocked"
            ),
            issue="preparation_not_ready",
        )
    artifact = expected_freeze.artifact.to_dict()
    prepared = preparation.prepared_market_reference
    if (
        preparation.issuer_id != artifact["issuer_id"]
        or preparation.data_cutoff_date != artifact["data_cutoff_date"]
        or preparation.price_blind_input_fingerprint != artifact["price_blind_input_fingerprint"]
        or prepared.snapshot.authorization_handoff_id != expected_freeze.handoffs[-1].handoff_id
        or prepared.snapshot.authorization_handoff_fingerprint
        != expected_freeze.handoffs[-1].fingerprint
    ):
        return _noncompiled(
            preparation=preparation,
            status="blocked",
            issue="freeze_or_authorization_binding_mismatch",
        )
    try:
        return _compile_from_artifact(
            prepared=prepared,
            artifact=artifact,
            kernel_repository=kernel_repository,
        )
    except (
        AttributeError,
        FinalRequestCompilationError,
        InvalidOperation,
        IndexError,
        KeyError,
        StopIteration,
        TypeError,
        ValueError,
    ) as exc:
        return _noncompiled(
            preparation=preparation,
            status="blocked",
            issue=f"final_request_blocked:{type(exc).__name__}",
        )


__all__ = ()
