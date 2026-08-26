"""Typed downstream publication records for the comprehensive owner workflow.

These records sit beside, rather than inside, the frozen PR1/PR2 contract graph.  A
source index can only be built from an exact, replayed ``ResearchBundle`` and
``ContractGraph``.  A market-expectations comparison can only be built after the
three-panel conclusion and four-lens scorecard exist, and it retains the exact Futu
session used to derive its public projection.
"""

from __future__ import annotations

import copy
import json
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass, field, fields
from datetime import date
from functools import cache
from pathlib import Path
from typing import Any, ClassVar
from urllib.parse import urlsplit, urlunsplit

from jsonschema import Draft202012Validator, FormatChecker

from .fingerprints import FrozenMap, canonical_sha256, freeze, to_json_value
from .futu_receipts import (
    FutuDataRequestReceipt,
    FutuDataResponseReceipt,
    FutuFrozenConclusionReceipt,
    FutuObservation,
    SignatureVerifier,
)
from .futu_session import (
    FutuSessionEvidence,
    FutuSessionPublicationManifest,
    validate_futu_session_evidence_replay,
    validate_futu_session_publication_manifest,
)
from .futu_sidecar import (
    FutuAttestedSessionFinalization,
    FutuRequestSpec,
    FutuSidecarExecution,
    load_protocol_registry,
)
from .research_bundle_builder import ResearchBundleBuildResult
from .validation import ContractGraph
from .valuation_market_runtime import contains_secret_material
from .valuation_synthesis_types import (
    CompositeValuationResult,
    NamedHumanReviewAuthority,
    OwnerScorecard,
    retained_authority_replay_scope,
)

_SCHEMA_NAMES = frozenset(
    {
        "market-expectations-comparison",
        "futu-optional-data-disposition",
        "owner-research-gap-publication-manifest",
        "owner-research-gap-receipt",
        "research-source-index",
    }
)
_SCHEMA_MAX_BYTES = 256 * 1024
_EXPECTATION_FAMILIES = (
    "analyst_consensus",
    "analyst_ratings",
    "valuation_context",
)
_OPTIONAL_PRE_PRICE_PROTOCOLS = (3235, 3244, 3245, 3246)
_OPTIONAL_DATA_STATUSES = frozenset(
    {
        "available",
        "not_comparable",
        "unavailable",
        "not_requested",
        "not_supported_for_us_sec_primary",
    }
)
_OPTIONAL_REVIEW_FIELDS = frozenset(
    {
        "company_executives",
        "executive_background_leader_name",
        "operational_efficiency",
        "us_buybacks_disposition",
    }
)
_OPTIONAL_REVIEW_ADMISSION_FIELDS = frozenset(
    {
        "futu_api_version",
        "market",
        "mappings",
        "registry_id",
        "registry_version",
    }
)
_OPTIONAL_REVIEW_ADMISSION_MAPPING_FIELDS = frozenset(
    {
        "accounting_standard_scope",
        "canonical_concept",
        "display_name",
        "field_id",
        "source_raw_plaintext_sha256",
        "statement_type",
    }
)


def _schema_directory() -> Path:
    packaged = Path(__file__).parent / "extension_schemas"
    repository = Path(__file__).parents[2] / "extension_schemas"
    for candidate in (packaged, repository):
        try:
            metadata = candidate.lstat()
        except OSError:
            continue
        if stat.S_ISDIR(metadata.st_mode) and not candidate.is_symlink():
            return candidate
    raise OwnerEquityTypeError("owner-equity schema directory is unavailable")


def _read_schema_file(path: Path, name: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise OwnerEquityTypeError(f"owner-equity schema is unavailable: {name}") from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size <= 0
            or metadata.st_size > _SCHEMA_MAX_BYTES
        ):
            raise OwnerEquityTypeError(f"owner-equity schema exceeds byte limit: {name}")
        chunks: list[bytes] = []
        remaining = _SCHEMA_MAX_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) != metadata.st_size or len(raw) > _SCHEMA_MAX_BYTES:
            raise OwnerEquityTypeError(f"owner-equity schema exceeds byte limit: {name}")
        return raw
    finally:
        os.close(descriptor)


def _reject_schema_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate schema member")
        value[key] = item
    return value


def _reject_schema_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")


class OwnerEquityTypeError(ValueError):
    """A downstream record does not replay its exact upstream typed objects."""


def _iso_date(value: object, label: str) -> str:
    if type(value) is not str:
        raise OwnerEquityTypeError(f"{label} must be an ISO-8601 date")
    try:
        return date.fromisoformat(value).isoformat()
    except ValueError as exc:
        raise OwnerEquityTypeError(f"{label} must be an ISO-8601 date") from exc


def _optional_data_reference(value: object, id_attribute: str) -> dict[str, str]:
    object_id = getattr(value, id_attribute, None)
    fingerprint = getattr(value, "fingerprint", None)
    if (
        type(object_id) is not str
        or not object_id
        or type(fingerprint) is not str
        or re.fullmatch(r"[0-9a-f]{64}", fingerprint) is None
    ):
        raise OwnerEquityTypeError("optional Futu evidence reference is invalid")
    return {"object_id": object_id, "fingerprint": fingerprint}


def _validate_optional_execution(execution: FutuSidecarExecution) -> None:
    if type(execution) is not FutuSidecarExecution:
        raise OwnerEquityTypeError("optional Futu data requires an exact sidecar execution")
    if (
        execution.bundle.stage != "valuation_pre_price_verification"
        or execution.bundle.status != "complete"
        or execution.bundle.issues
        or not execution.requests
        or any(type(item) is not FutuDataRequestReceipt for item in execution.requests)
        or any(type(item) is not FutuDataResponseReceipt for item in execution.responses)
        or any(type(item) is not FutuObservation for item in execution.observations)
    ):
        raise OwnerEquityTypeError("optional Futu data requires a complete pre-price execution")
    expected = (
        [
            _optional_data_reference(item, "request_id")
            for item in execution.requests
        ],
        [
            _optional_data_reference(item, "response_id")
            for item in execution.responses
        ],
        [
            _optional_data_reference(item, "observation_id")
            for item in execution.observations
        ],
    )
    if (
        to_json_value(execution.bundle.requests) != expected[0]
        or to_json_value(execution.bundle.responses) != expected[1]
        or to_json_value(execution.bundle.observations) != expected[2]
    ):
        raise OwnerEquityTypeError("optional Futu execution bundle references were rebound")


def _validated_optional_review_payload(
    review: NamedHumanReviewAuthority,
) -> dict[str, Any]:
    if type(review) is not NamedHumanReviewAuthority:
        raise OwnerEquityTypeError("optional Futu plan lacks exact named-human review")
    try:
        review.__post_init__()
    except (OSError, TypeError, ValueError) as exc:
        raise OwnerEquityTypeError("optional Futu review authority does not replay") from exc
    payload = to_json_value(review.reviewed_payload)
    allowed = _OPTIONAL_REVIEW_FIELDS | {"financial_field_admission"}
    if (
        not isinstance(payload, dict)
        or not _OPTIONAL_REVIEW_FIELDS.issubset(payload)
        or set(payload) not in {_OPTIONAL_REVIEW_FIELDS, allowed}
    ):
        raise OwnerEquityTypeError("optional Futu review payload fields are not closed")
    leader = payload["executive_background_leader_name"]
    if (
        review.scope != "futu_optional_data_plan"
        or type(payload["company_executives"]) is not bool
        or payload["operational_efficiency"] is not True
        or payload["us_buybacks_disposition"]
        != "not_supported_for_us_sec_primary"
        or (
            leader is not None
            and (
                type(leader) is not str
                or not leader.strip()
                or len(leader.encode("utf-8")) > 512
                or payload["company_executives"] is not True
            )
        )
    ):
        raise OwnerEquityTypeError("optional Futu reviewed plan is invalid")
    admission = payload.get("financial_field_admission")
    if admission is not None:
        if (
            not isinstance(admission, dict)
            or set(admission) != _OPTIONAL_REVIEW_ADMISSION_FIELDS
            or admission.get("registry_id") != "futu-reviewed-financial-field-admission"
            or admission.get("registry_version") != "1.0.0"
            or type(admission.get("futu_api_version")) is not str
            or type(admission.get("market")) is not str
            or not admission["market"]
            or not admission["market"].isascii()
            or not admission["market"].isupper()
            or not isinstance(admission.get("mappings"), list)
            or not admission["mappings"]
        ):
            raise OwnerEquityTypeError("optional Futu reviewed financial admission is invalid")
        for item in admission["mappings"]:
            if (
                not isinstance(item, dict)
                or set(item) != _OPTIONAL_REVIEW_ADMISSION_MAPPING_FIELDS
                or type(item.get("accounting_standard_scope")) is not str
                or not item["accounting_standard_scope"]
                or type(item.get("canonical_concept")) is not str
                or not item["canonical_concept"]
                or type(item.get("display_name")) is not str
                or not item["display_name"]
                or item["display_name"] != item["display_name"].strip()
                or type(item.get("field_id")) is not str
                or not item["field_id"].isascii()
                or not item["field_id"].isdecimal()
                or str(int(item["field_id"])) != item["field_id"]
                or type(item.get("source_raw_plaintext_sha256")) is not str
                or re.fullmatch(r"[0-9a-f]{64}", item["source_raw_plaintext_sha256"])
                is None
                or item.get("statement_type")
                not in {"income", "balance_sheet", "cash_flow"}
            ):
                raise OwnerEquityTypeError(
                    "optional Futu reviewed financial admission is invalid"
                )
    return payload


def load_reviewed_financial_field_admission(
    review: NamedHumanReviewAuthority,
) -> Mapping[str, Any] | None:
    payload = _validated_optional_review_payload(review)
    admission = payload.get("financial_field_admission")
    return admission if isinstance(admission, Mapping) else None


def _optional_data_review_payload(
    execution: FutuSidecarExecution,
    review: NamedHumanReviewAuthority,
) -> dict[str, Any]:
    payload = _validated_optional_review_payload(review)
    if (
        review.issuer_id != execution.bundle.issuer_id
        or review.data_cutoff_date != execution.requests[0].data_cutoff_date
    ):
        raise OwnerEquityTypeError("optional Futu review changed execution identity")
    return payload


def compile_futu_optional_data_request_specs(
    review_authority: NamedHumanReviewAuthority,
) -> tuple[FutuRequestSpec, ...]:
    """Compile the closed optional pre-price plan from exact reviewed official evidence."""

    reviewed = _validated_optional_review_payload(review_authority)
    specs: list[FutuRequestSpec] = []
    if reviewed["company_executives"]:
        specs.append(
            FutuRequestSpec(
                "valuation_pre_price_verification",
                3244,
                FrozenMap({}),
            )
        )
    leader = reviewed["executive_background_leader_name"]
    if leader is not None:
        specs.append(
            FutuRequestSpec(
                "valuation_pre_price_verification",
                3245,
                FrozenMap({"leader_name": leader}),
            )
        )
    specs.append(
        FutuRequestSpec(
            "valuation_pre_price_verification",
            3246,
            FrozenMap({"currency_code": "USD", "num": 50}),
        )
    )
    return tuple(specs)


def _optional_protocol_payloads(
    execution: FutuSidecarExecution,
    review: NamedHumanReviewAuthority,
) -> tuple[dict[str, Any], ...]:
    _validate_optional_execution(execution)
    reviewed = _optional_data_review_payload(execution, review)
    registry = load_protocol_registry()
    selected = {
        3244: reviewed["company_executives"],
        3245: reviewed["executive_background_leader_name"] is not None,
        3246: reviewed["operational_efficiency"],
    }
    requests_by_protocol = {
        protocol_id: tuple(
            item for item in execution.requests if item.protocol_id == protocol_id
        )
        for protocol_id in _OPTIONAL_PRE_PRICE_PROTOCOLS
    }
    if requests_by_protocol[3235] or any(
        bool(requests_by_protocol[protocol_id]) is not should_request
        for protocol_id, should_request in selected.items()
    ):
        raise OwnerEquityTypeError(
            "optional Futu execution differs from its frozen reviewed plan"
        )
    response_by_request = {
        request.request_id: tuple(
            response
            for response in execution.responses
            if response.request_id == request.request_id
            and response.request_fingerprint == request.fingerprint
        )
        for request in execution.requests
    }
    payloads: list[dict[str, Any]] = []
    for protocol_id in _OPTIONAL_PRE_PRICE_PROTOCOLS:
        protocol = registry[protocol_id]
        requests = requests_by_protocol[protocol_id]
        responses = tuple(
            response
            for request in requests
            for response in response_by_request[request.request_id]
        )
        if requests and (
            any(len(response_by_request[item.request_id]) != 1 for item in requests)
            or any(response.status != "completed" for response in responses)
            or not responses[-1].terminal
        ):
            raise OwnerEquityTypeError("optional Futu request lacks exact completed responses")
        response_fingerprints = {item.fingerprint for item in responses}
        observations = tuple(
            item
            for item in execution.observations
            if item.response_fingerprint in response_fingerprints
            and item.field_id != "availability"
        )
        if protocol_id == 3235:
            status = "not_supported_for_us_sec_primary"
            reason = "official_registry_excludes_us_sec_primary"
        elif not selected[protocol_id]:
            status = "not_requested"
            reason = "named_human_review_not_selected"
        elif not observations:
            status = "unavailable"
            reason = "vendor_returned_no_observations"
        elif protocol_id == 3246 and not any(
            item.comparison_eligible for item in observations
        ):
            status = "not_comparable"
            reason = "vendor_fields_not_comparable_to_official_facts"
        else:
            status = "available"
            reason = "vendor_observations_available"
        if protocol_id == 3245 and requests:
            leader = reviewed["executive_background_leader_name"]
            request_index = execution.requests.index(requests[0])
            prior_executive_requests = requests_by_protocol[3244]
            prior_response_fingerprints = {
                response.fingerprint
                for request in prior_executive_requests
                for response in response_by_request[request.request_id]
            }
            prior_observations = tuple(
                item
                for item in execution.observations
                if item.response_fingerprint in prior_response_fingerprints
            )
            if (
                requests[0].parameters.get("leader_name") != leader
                or not prior_executive_requests
                or execution.requests.index(prior_executive_requests[0]) >= request_index
                or not any(item.value == leader for item in prior_observations)
            ):
                raise OwnerEquityTypeError(
                    "executive background is not a same-run leader-name pass-back"
                )
        values: dict[str, Any] = {
            "schema_version": "1.0.0",
            "artifact_type": "futu-optional-data-disposition",
            "issuer_id": execution.bundle.issuer_id,
            "data_cutoff_date": execution.requests[0].data_cutoff_date,
            "protocol_id": protocol_id,
            "protocol_name": protocol["name"],
            "data_family": protocol["data_family"],
            "status": status,
            "reason_code": reason,
            "execution_bundle": _optional_data_reference(
                execution.bundle,
                "bundle_id",
            ),
            "review_authority": _optional_data_reference(review, "review_id"),
            "requests": [
                _optional_data_reference(item, "request_id") for item in requests
            ],
            "responses": [
                _optional_data_reference(item, "response_id") for item in responses
            ],
            "observations": [
                _optional_data_reference(item, "observation_id")
                for item in observations
            ],
        }
        disposition_id = (
            f"futu-optional-disposition:{protocol_id}:"
            f"{canonical_sha256(values)[:24]}"
        )
        values["disposition_id"] = disposition_id
        values["disposition_fingerprint"] = canonical_sha256(values)
        payloads.append(values)
    return tuple(payloads)


@dataclass(frozen=True, slots=True)
class FutuOptionalDataDisposition:
    """Live per-protocol availability proof derived from one exact pre-price run."""

    execution: FutuSidecarExecution = field(repr=False)
    review_authority: NamedHumanReviewAuthority = field(repr=False)
    _payload: FrozenMap
    SCHEMA_NAME: ClassVar[str] = "futu-optional-data-disposition"

    def __post_init__(self) -> None:
        raw = to_json_value(self._payload)
        if not isinstance(raw, dict):
            raise OwnerEquityTypeError("optional Futu disposition must be an object")
        _validate(self.SCHEMA_NAME, raw)
        expected = next(
            (
                item
                for item in _optional_protocol_payloads(
                    self.execution,
                    self.review_authority,
                )
                if item["protocol_id"] == raw["protocol_id"]
            ),
            None,
        )
        if expected != raw:
            raise OwnerEquityTypeError(
                "optional Futu disposition differs from exact execution authority"
            )
        object.__setattr__(self, "_payload", freeze(raw))

    def to_dict(self) -> dict[str, Any]:
        raw = to_json_value(self._payload)
        assert isinstance(raw, dict)
        return raw

    @property
    def fingerprint(self) -> str:
        return str(self._payload["disposition_fingerprint"])

    @property
    def protocol_id(self) -> int:
        return int(self._payload["protocol_id"])

    @property
    def status(self) -> str:
        return str(self._payload["status"])


@dataclass(frozen=True, slots=True)
class FutuOptionalDataDispositionPublicationManifest:
    """Disk-safe projection of one replayed optional Futu disposition."""

    _payload: FrozenMap
    SCHEMA_NAME: ClassVar[str] = "futu-optional-data-disposition"

    def __post_init__(self) -> None:
        raw = to_json_value(self._payload)
        if not isinstance(raw, dict):
            raise OwnerEquityTypeError("optional Futu publication must be an object")
        _validate(self.SCHEMA_NAME, raw)
        identity = dict(raw)
        fingerprint = identity.pop("disposition_fingerprint")
        if fingerprint != canonical_sha256(identity):
            raise OwnerEquityTypeError("optional Futu disposition fingerprint does not replay")
        disposition_id = identity.pop("disposition_id")
        expected_id = (
            f"futu-optional-disposition:{raw['protocol_id']}:"
            f"{canonical_sha256(identity)[:24]}"
        )
        if disposition_id != expected_id:
            raise OwnerEquityTypeError("optional Futu disposition ID does not replay")
        if raw["status"] not in _OPTIONAL_DATA_STATUSES:
            raise OwnerEquityTypeError("optional Futu disposition status is not closed")
        registry = load_protocol_registry()
        protocol = registry.get(raw["protocol_id"])
        status = raw["status"]
        expected_reason = {
            "available": "vendor_observations_available",
            "not_comparable": "vendor_fields_not_comparable_to_official_facts",
            "unavailable": "vendor_returned_no_observations",
            "not_requested": "named_human_review_not_selected",
            "not_supported_for_us_sec_primary": (
                "official_registry_excludes_us_sec_primary"
            ),
        }[status]
        if (
            protocol is None
            or raw["protocol_name"] != protocol["name"]
            or raw["data_family"] != protocol["data_family"]
            or raw["reason_code"] != expected_reason
            or (raw["protocol_id"] == 3235)
            != (status == "not_supported_for_us_sec_primary")
            or (status == "not_comparable" and raw["protocol_id"] != 3246)
            or (status in {"not_requested", "not_supported_for_us_sec_primary"})
            != (not raw["requests"] and not raw["responses"])
            or (status == "unavailable" and raw["observations"])
            or (status in {"available", "not_comparable"} and not raw["observations"])
        ):
            raise OwnerEquityTypeError(
                "optional Futu disposition semantics do not replay"
            )
        object.__setattr__(self, "_payload", freeze(raw))

    @classmethod
    def from_dict(
        cls,
        payload: Mapping[str, Any],
    ) -> FutuOptionalDataDispositionPublicationManifest:
        return cls(_payload=freeze(payload))

    def to_dict(self) -> dict[str, Any]:
        raw = to_json_value(self._payload)
        assert isinstance(raw, dict)
        return raw

    @property
    def fingerprint(self) -> str:
        return str(self._payload["disposition_fingerprint"])


def build_futu_optional_data_dispositions(
    *,
    execution: FutuSidecarExecution,
    review_authority: NamedHumanReviewAuthority,
) -> tuple[FutuOptionalDataDisposition, ...]:
    payloads = _optional_protocol_payloads(execution, review_authority)
    return tuple(
        FutuOptionalDataDisposition(
            execution=execution,
            review_authority=review_authority,
            _payload=freeze(payload),
        )
        for payload in payloads
    )


def build_futu_optional_data_disposition_publication_manifests(
    dispositions: tuple[FutuOptionalDataDisposition, ...],
) -> tuple[FutuOptionalDataDispositionPublicationManifest, ...]:
    if (
        type(dispositions) is not tuple
        or tuple(item.protocol_id for item in dispositions)
        != _OPTIONAL_PRE_PRICE_PROTOCOLS
        or any(type(item) is not FutuOptionalDataDisposition for item in dispositions)
    ):
        raise OwnerEquityTypeError("optional Futu disposition set is not exact")
    for item in dispositions:
        item.__post_init__()
    return tuple(
        FutuOptionalDataDispositionPublicationManifest.from_dict(item.to_dict())
        for item in dispositions
    )


@dataclass(frozen=True, slots=True)
class RuntimeGapReceipt:
    """Live typed proof that an unsafe or ineligible downstream read was suppressed."""

    schema_version: str
    receipt_id: str
    receipt_fingerprint: str
    phase: str
    issuer_id: str
    data_cutoff_date: str
    upstream_fingerprints: FrozenMap
    issue_codes: tuple[str, ...]
    composite_valuation: CompositeValuationResult = field(repr=False)
    owner_scorecard: OwnerScorecard = field(repr=False)
    frozen_conclusion: FutuFrozenConclusionReceipt = field(repr=False)
    attested_finalization: FutuAttestedSessionFinalization = field(repr=False)

    @retained_authority_replay_scope
    def __post_init__(self) -> None:
        if self.schema_version != "1.0.0":
            raise OwnerEquityTypeError("runtime gap schema version is invalid")
        if type(self.phase) is not str or not self.phase or len(self.phase) > 128:
            raise OwnerEquityTypeError("runtime gap phase is invalid")
        if type(self.issuer_id) is not str or not self.issuer_id or len(self.issuer_id) > 256:
            raise OwnerEquityTypeError("runtime gap issuer is invalid")
        object.__setattr__(
            self,
            "data_cutoff_date",
            _iso_date(self.data_cutoff_date, "runtime gap cutoff"),
        )
        upstream = freeze(self.upstream_fingerprints)
        if not upstream or any(
            type(key) is not str
            or not key
            or type(value) is not str
            or re.fullmatch(r"[0-9a-f]{64}", value) is None
            for key, value in upstream.items()
        ):
            raise OwnerEquityTypeError(
                "runtime gap requires named exact upstream fingerprints"
            )
        issues = tuple(sorted(set(self.issue_codes)))
        if not issues or any(
            type(item) is not str or not item or len(item) > 256 for item in issues
        ):
            raise OwnerEquityTypeError("runtime gap requires bounded issue codes")
        object.__setattr__(self, "upstream_fingerprints", upstream)
        object.__setattr__(self, "issue_codes", issues)
        if (
            type(self.composite_valuation) is not CompositeValuationResult
            or type(self.owner_scorecard) is not OwnerScorecard
            or type(self.frozen_conclusion) is not FutuFrozenConclusionReceipt
            or type(self.attested_finalization) is not FutuAttestedSessionFinalization
        ):
            raise OwnerEquityTypeError("runtime gap lacks exact retained live authorities")
        try:
            self.composite_valuation.__post_init__()
            self.owner_scorecard.__post_init__()
            self.frozen_conclusion.__post_init__()
            self.attested_finalization.__post_init__()
        except (OSError, TypeError, ValueError) as exc:
            raise OwnerEquityTypeError("runtime gap live authorities do not replay") from exc
        expected_upstream = freeze(
            {
                "composite_valuation": self.composite_valuation.fingerprint,
                "owner_scorecard": self.owner_scorecard.fingerprint,
                "frozen_conclusion": self.frozen_conclusion.fingerprint,
                "sidecar_finalization": self.attested_finalization.fingerprint,
            }
        )
        if (
            upstream != expected_upstream
            or self.phase != "futu_market_expectations"
            or self.issuer_id != self.composite_valuation.issuer_id
            or self.issuer_id != self.owner_scorecard.issuer_id
            or self.data_cutoff_date != self.owner_scorecard.as_of_date
            or self.owner_scorecard.composite_valuation_fingerprint
            != self.composite_valuation.fingerprint
            or self.frozen_conclusion.composite_valuation is not self.composite_valuation
            or self.frozen_conclusion.owner_scorecard is not self.owner_scorecard
            or self.frozen_conclusion.composite_valuation.status
            not in {"blocked", "contested"}
            or self.owner_scorecard.recommendation != "无法评级"
            or self.attested_finalization.skipped_conditional_conclusion
            is not self.frozen_conclusion
        ):
            raise OwnerEquityTypeError("runtime gap rebound its exact upstream authorities")
        values = self._identity_values()
        fingerprint = canonical_sha256(values)
        if (
            self.receipt_fingerprint != fingerprint
            or self.receipt_id
            != f"owner-research-gap:{self.phase}:{fingerprint[:24]}"
        ):
            raise OwnerEquityTypeError("runtime gap identity does not replay")
        _validate("owner-research-gap-receipt", self.to_dict())

    def _identity_values(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "phase": self.phase,
            "issuer_id": self.issuer_id,
            "data_cutoff_date": self.data_cutoff_date,
            "upstream_fingerprints": to_json_value(self.upstream_fingerprints),
            "issue_codes": list(self.issue_codes),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._identity_values(),
            "receipt_id": self.receipt_id,
            "receipt_fingerprint": self.receipt_fingerprint,
        }

    @property
    def fingerprint(self) -> str:
        return self.receipt_fingerprint

    @classmethod
    def create(
        cls,
        *,
        phase: str,
        composite_valuation: CompositeValuationResult,
        owner_scorecard: OwnerScorecard,
        frozen_conclusion: FutuFrozenConclusionReceipt,
        attested_finalization: FutuAttestedSessionFinalization,
        issue_codes: tuple[str, ...],
    ) -> RuntimeGapReceipt:
        if phase != "futu_market_expectations":
            raise OwnerEquityTypeError("runtime gap phase is not registered")
        if (
            type(composite_valuation) is not CompositeValuationResult
            or type(owner_scorecard) is not OwnerScorecard
            or type(frozen_conclusion) is not FutuFrozenConclusionReceipt
            or type(attested_finalization) is not FutuAttestedSessionFinalization
        ):
            raise OwnerEquityTypeError("runtime gap factory requires exact live authorities")
        values = {
            "schema_version": "1.0.0",
            "phase": phase,
            "issuer_id": composite_valuation.issuer_id,
            "data_cutoff_date": _iso_date(owner_scorecard.as_of_date, "runtime gap cutoff"),
            "upstream_fingerprints": {
                "composite_valuation": composite_valuation.fingerprint,
                "owner_scorecard": owner_scorecard.fingerprint,
                "frozen_conclusion": frozen_conclusion.fingerprint,
                "sidecar_finalization": attested_finalization.fingerprint,
            },
            "issue_codes": list(tuple(sorted(set(issue_codes)))),
        }
        fingerprint = canonical_sha256(values)
        return cls(
            receipt_id=f"owner-research-gap:{phase}:{fingerprint[:24]}",
            receipt_fingerprint=fingerprint,
            upstream_fingerprints=freeze(values["upstream_fingerprints"]),
            issue_codes=tuple(values["issue_codes"]),
            composite_valuation=composite_valuation,
            owner_scorecard=owner_scorecard,
            frozen_conclusion=frozen_conclusion,
            attested_finalization=attested_finalization,
            **{
                key: values[key]
                for key in (
                    "schema_version",
                    "phase",
                    "issuer_id",
                    "data_cutoff_date",
                )
            },
        )

@dataclass(frozen=True, slots=True)
class RuntimeGapPublicationManifest:
    """Disk-safe projection derived only from a replayed live gap receipt."""

    schema_version: str
    artifact_type: str
    manifest_id: str
    manifest_fingerprint: str
    source_receipt_id: str
    source_receipt_fingerprint: str
    phase: str
    issuer_id: str
    data_cutoff_date: str
    upstream_fingerprints: FrozenMap
    issue_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            self.schema_version != "1.0.0"
            or self.artifact_type != "owner-research-gap-publication-manifest"
        ):
            raise OwnerEquityTypeError("runtime gap publication identity is invalid")
        object.__setattr__(
            self,
            "data_cutoff_date",
            _iso_date(self.data_cutoff_date, "runtime gap publication cutoff"),
        )
        object.__setattr__(self, "upstream_fingerprints", freeze(self.upstream_fingerprints))
        object.__setattr__(self, "issue_codes", tuple(self.issue_codes))
        values = self._identity_values()
        fingerprint = canonical_sha256(values)
        if (
            self.manifest_fingerprint != fingerprint
            or self.manifest_id
            != f"owner-research-gap-publication:{self.issuer_id}:{fingerprint[:24]}"
        ):
            raise OwnerEquityTypeError("runtime gap publication fingerprint does not replay")
        _validate("owner-research-gap-publication-manifest", self.to_dict())

    def _identity_values(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "artifact_type": self.artifact_type,
            "source_receipt_id": self.source_receipt_id,
            "source_receipt_fingerprint": self.source_receipt_fingerprint,
            "phase": self.phase,
            "issuer_id": self.issuer_id,
            "data_cutoff_date": self.data_cutoff_date,
            "upstream_fingerprints": to_json_value(self.upstream_fingerprints),
            "issue_codes": list(self.issue_codes),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._identity_values(),
            "manifest_id": self.manifest_id,
            "manifest_fingerprint": self.manifest_fingerprint,
        }

    @property
    def fingerprint(self) -> str:
        return self.manifest_fingerprint

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> RuntimeGapPublicationManifest:
        if not isinstance(payload, Mapping):
            raise OwnerEquityTypeError("runtime gap publication must be an object")
        try:
            return cls(
                schema_version=payload["schema_version"],
                artifact_type=payload["artifact_type"],
                manifest_id=payload["manifest_id"],
                manifest_fingerprint=payload["manifest_fingerprint"],
                source_receipt_id=payload["source_receipt_id"],
                source_receipt_fingerprint=payload["source_receipt_fingerprint"],
                phase=payload["phase"],
                issuer_id=payload["issuer_id"],
                data_cutoff_date=payload["data_cutoff_date"],
                upstream_fingerprints=freeze(payload["upstream_fingerprints"]),
                issue_codes=tuple(payload["issue_codes"]),
            )
        except (KeyError, TypeError) as exc:
            raise OwnerEquityTypeError(
                "runtime gap publication fields are invalid"
            ) from exc


def build_runtime_gap_publication_manifest(
    receipt: RuntimeGapReceipt,
) -> RuntimeGapPublicationManifest:
    if type(receipt) is not RuntimeGapReceipt:
        raise OwnerEquityTypeError("runtime gap publication requires the exact live receipt")
    receipt.__post_init__()
    values = {
        "schema_version": "1.0.0",
        "artifact_type": "owner-research-gap-publication-manifest",
        "source_receipt_id": receipt.receipt_id,
        "source_receipt_fingerprint": receipt.fingerprint,
        "phase": receipt.phase,
        "issuer_id": receipt.issuer_id,
        "data_cutoff_date": receipt.data_cutoff_date,
        "upstream_fingerprints": to_json_value(receipt.upstream_fingerprints),
        "issue_codes": list(receipt.issue_codes),
    }
    fingerprint = canonical_sha256(values)
    return RuntimeGapPublicationManifest(
        manifest_id=(
            f"owner-research-gap-publication:{receipt.issuer_id}:{fingerprint[:24]}"
        ),
        manifest_fingerprint=fingerprint,
        upstream_fingerprints=receipt.upstream_fingerprints,
        issue_codes=receipt.issue_codes,
        **{
            key: values[key]
            for key in (
                "schema_version",
                "artifact_type",
                "source_receipt_id",
                "source_receipt_fingerprint",
                "phase",
                "issuer_id",
                "data_cutoff_date",
            )
        },
    )


_WINDOWS_ABSOLUTE_PATH = re.compile(r"^[A-Za-z]:[\\/]")
_LOCATOR_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*$")


def _credential_free_source_url(value: object) -> str:
    if type(value) is not str or not value or len(value) > 2048:
        raise OwnerEquityTypeError("source index URL must be one bounded string")
    if contains_secret_material(value) or any(character.isspace() for character in value):
        raise OwnerEquityTypeError("source index URL contains credential-like material")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise OwnerEquityTypeError("source index URL is malformed") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or port is not None
        or parsed.hostname != parsed.hostname.lower()
        or parsed.netloc != parsed.hostname
        or "\\" in parsed.path
        or urlunsplit(parsed) != value
    ):
        raise OwnerEquityTypeError(
            "source index URL must be normalized credential-free HTTPS"
        )
    return value


def _credential_free_locator(value: object) -> str:
    if type(value) is not str or not value or len(value) > 2048:
        raise OwnerEquityTypeError("source index locator must be one bounded string")
    if (
        contains_secret_material(value)
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
        or value.startswith(("/", "~", "\\", "file:"))
        or _WINDOWS_ABSOLUTE_PATH.match(value) is not None
    ):
        raise OwnerEquityTypeError("source index locator contains secret or local path material")
    if "://" in value:
        parsed = urlsplit(value)
        if (
            _LOCATOR_SCHEME.fullmatch(parsed.scheme) is None
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise OwnerEquityTypeError("source index locator URI is not audit-safe")
        if parsed.scheme == "https":
            _credential_free_source_url(value)
    return value


def _validate_public_source_projection(payload: Mapping[str, Any]) -> None:
    sources = payload.get("sources")
    if not isinstance(sources, list):
        raise OwnerEquityTypeError("source index sources must be an array")
    for source in sources:
        if not isinstance(source, dict):
            raise OwnerEquityTypeError("source index source must be an object")
        _credential_free_source_url(source.get("source_url"))
        locators = source.get("locators")
        if not isinstance(locators, list):
            raise OwnerEquityTypeError("source index locators must be an array")
        for locator in locators:
            _credential_free_locator(locator)


@cache
def _schema(name: str) -> dict[str, Any]:
    if name not in _SCHEMA_NAMES:
        raise KeyError(f"unknown owner-equity extension schema: {name}")
    path = _schema_directory() / f"{name}.schema.json"
    try:
        raw = _read_schema_file(path, name)
        payload = json.loads(
            raw,
            object_pairs_hook=_reject_schema_duplicates,
            parse_constant=_reject_schema_constant,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        if isinstance(exc, OwnerEquityTypeError):
            raise
        raise OwnerEquityTypeError(f"owner-equity schema is unavailable: {name}") from exc
    if not isinstance(payload, dict):
        raise OwnerEquityTypeError(f"owner-equity schema must be an object: {name}")
    Draft202012Validator.check_schema(payload)
    return payload


def load_owner_equity_schema(name: str) -> dict[str, Any]:
    """Return a detached copy of one parallel (non-PR1/PR2) schema."""

    return copy.deepcopy(_schema(name))


@cache
def _validator(name: str) -> Draft202012Validator:
    return Draft202012Validator(_schema(name), format_checker=FormatChecker())


def _validate(name: str, payload: Mapping[str, Any]) -> None:
    errors = sorted(
        _validator(name).iter_errors(to_json_value(payload)),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if errors:
        error = errors[0]
        location = "/".join(str(part) for part in error.absolute_path) or "<root>"
        raise OwnerEquityTypeError(f"{name} validation failed at {location}: {error.message}")


def _graph_fingerprint(graph: ContractGraph) -> str:
    if type(graph) is not ContractGraph:
        raise OwnerEquityTypeError("source index requires the exact ContractGraph")
    graph.validate()
    projection: dict[str, list[str]] = {}
    for graph_field in fields(graph):
        if graph_field.name == "component_lock_path":
            continue
        fingerprints: list[str] = []
        for value in getattr(graph, graph_field.name):
            fingerprint = getattr(value, "fingerprint", None)
            if type(fingerprint) is not str:
                raise OwnerEquityTypeError(
                    f"ContractGraph collection {graph_field.name} is not fingerprinted"
                )
            fingerprints.append(fingerprint)
        projection[graph_field.name] = fingerprints
    return canonical_sha256(projection)


def _source_locators(graph: ContractGraph, document_id: str) -> tuple[str, ...]:
    locators: set[str] = set()
    for graph_field in fields(graph):
        if graph_field.name == "component_lock_path":
            continue
        for value in getattr(graph, graph_field.name):
            if getattr(value, "source_document_id", None) != document_id:
                continue
            locator = getattr(value, "source_locator", None)
            if type(locator) is str and locator and len(locator) <= 2048:
                locators.add(locator)
    return tuple(sorted(locators))


def _source_index_payload(
    graph: ContractGraph,
    research: ResearchBundleBuildResult,
) -> dict[str, Any]:
    if type(research) is not ResearchBundleBuildResult:
        raise OwnerEquityTypeError("source index requires an exact ResearchBundle build result")
    graph_fingerprint = _graph_fingerprint(graph)
    bundle = research.bundle
    manifest = research.run_manifest
    if (
        bundle.run_id != manifest.run_id
        or bundle.issuer_id != manifest.issuer_id
        or bundle.data_cutoff_date != manifest.data_cutoff_date
        or bundle not in graph.research_bundles
        or manifest not in graph.manifests
    ):
        raise OwnerEquityTypeError("source index research authority does not replay in the graph")
    document_ids = tuple(bundle.source_document_ids)
    if not document_ids or len(document_ids) != len(set(document_ids)):
        raise OwnerEquityTypeError("source index requires a nonempty unique source set")
    indexed = {item.document_id: item for item in graph.documents}
    if len(indexed) != len(graph.documents) or any(item not in indexed for item in document_ids):
        raise OwnerEquityTypeError("source index document set does not replay in the graph")
    sources = []
    for document_id in sorted(document_ids):
        document = indexed[document_id]
        # A complete competitive-context review deliberately requires at least one
        # independent industry/peer source.  ``source_document_ids`` is the exact
        # dependency closure of the target issuer's reviewed Bundle, so a foreign
        # issuer here is not an unscoped extra document: it is retained target-context
        # evidence already bound by the graph and Bundle fingerprints.
        source_scope = (
            "target_issuer"
            if document.issuer_id == bundle.issuer_id
            else "external_context"
        )
        sources.append(
            {
                "document_id": document.document_id,
                "document_fingerprint": document.fingerprint,
                "document_type": document.document_type,
                "source_issuer_id": document.issuer_id,
                "source_scope": source_scope,
                "source_url": _credential_free_source_url(document.source_url),
                "content_sha256": document.content_sha256,
                "published_date": document.published_date,
                "retrieved_at": document.retrieved_at,
                "authority_level": document.authority_level,
                "locators": tuple(
                    _credential_free_locator(value)
                    for value in _source_locators(graph, document.document_id)
                ),
            }
        )
    payload: dict[str, Any] = {
        "schema_version": "1.0.0",
        "artifact_type": "research-source-index",
        "issuer_id": bundle.issuer_id,
        "data_cutoff_date": bundle.data_cutoff_date,
        "research_bundle_id": bundle.bundle_id,
        "research_bundle_fingerprint": bundle.bundle_fingerprint,
        "contract_graph_fingerprint": graph_fingerprint,
        "source_count": len(sources),
        "sources": sources,
    }
    payload["index_id"] = (
        f"research-source-index:{bundle.issuer_id}:{canonical_sha256(payload)[:24]}"
    )
    payload["index_fingerprint"] = canonical_sha256(payload)
    return payload


@dataclass(frozen=True, slots=True)
class ResearchSourceIndex:
    """Public source projection retaining its exact graph and Bundle authority."""

    graph: ContractGraph
    research: ResearchBundleBuildResult
    _payload: FrozenMap
    SCHEMA_NAME: ClassVar[str] = "research-source-index"

    def __post_init__(self) -> None:
        if (
            type(self.graph) is not ContractGraph
            or type(self.research) is not ResearchBundleBuildResult
        ):
            raise OwnerEquityTypeError("source index requires exact retained authorities")
        raw = to_json_value(self._payload)
        if not isinstance(raw, dict):
            raise OwnerEquityTypeError("source index payload must be an object")
        _validate(self.SCHEMA_NAME, raw)
        if raw != to_json_value(_source_index_payload(self.graph, self.research)):
            raise OwnerEquityTypeError("source index differs from its retained typed authorities")
        object.__setattr__(self, "_payload", freeze(raw))

    @classmethod
    def from_dict(
        cls,
        payload: Mapping[str, Any],
        *,
        graph: ContractGraph,
        research: ResearchBundleBuildResult,
    ) -> ResearchSourceIndex:
        return cls(graph=graph, research=research, _payload=freeze(payload))

    def to_dict(self) -> dict[str, Any]:
        raw = to_json_value(self._payload)
        assert isinstance(raw, dict)
        return raw

    @property
    def fingerprint(self) -> str:
        return str(self._payload["index_fingerprint"])


@dataclass(frozen=True, slots=True)
class ResearchSourceIndexPublicationManifest:
    """Disk-safe, closed projection of a live source index."""

    _payload: FrozenMap
    SCHEMA_NAME: ClassVar[str] = "research-source-index"

    def __post_init__(self) -> None:
        raw = to_json_value(self._payload)
        if not isinstance(raw, dict):
            raise OwnerEquityTypeError("source-index publication manifest must be an object")
        _validate(self.SCHEMA_NAME, raw)
        _validate_public_source_projection(raw)
        identity = dict(raw)
        supplied_fingerprint = identity.pop("index_fingerprint")
        if supplied_fingerprint != canonical_sha256(identity):
            raise OwnerEquityTypeError("source-index publication fingerprint does not replay")
        supplied_id = identity.pop("index_id")
        expected_id = f"research-source-index:{raw['issuer_id']}:{canonical_sha256(identity)[:24]}"
        if supplied_id != expected_id:
            raise OwnerEquityTypeError("source-index publication ID does not replay")
        object.__setattr__(self, "_payload", freeze(raw))

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> ResearchSourceIndexPublicationManifest:
        return cls(_payload=freeze(payload))

    def to_dict(self) -> dict[str, Any]:
        raw = to_json_value(self._payload)
        assert isinstance(raw, dict)
        return raw

    @property
    def fingerprint(self) -> str:
        return str(self._payload["index_fingerprint"])


def build_research_source_index(
    *,
    graph: ContractGraph,
    research: ResearchBundleBuildResult,
) -> ResearchSourceIndex:
    return ResearchSourceIndex(
        graph=graph,
        research=research,
        _payload=freeze(_source_index_payload(graph, research)),
    )


def build_research_source_index_publication_manifest(
    source_index: ResearchSourceIndex,
) -> ResearchSourceIndexPublicationManifest:
    if type(source_index) is not ResearchSourceIndex:
        raise OwnerEquityTypeError("source-index publication requires the exact live index")
    return ResearchSourceIndexPublicationManifest.from_dict(source_index.to_dict())


def _post_valuation_execution(session: FutuSessionEvidence):
    post = tuple(
        execution
        for execution in session.executions
        if execution.bundle.stage == "post_valuation_context"
    )
    if len(post) != 1:
        raise OwnerEquityTypeError("Futu session lacks one post-valuation execution")
    return post[0]


def _expectation_observations(session: FutuSessionEvidence) -> tuple[dict[str, Any], ...]:
    execution = _post_valuation_execution(session)
    response_fingerprints = {response.fingerprint for response in execution.responses}
    observations: list[dict[str, Any]] = []
    for observation in execution.observations:
        if type(observation) is not FutuObservation:
            raise OwnerEquityTypeError("market context retained a non-exact observation")
        if observation.data_family not in _EXPECTATION_FAMILIES:
            raise OwnerEquityTypeError("post-valuation comparison received an unregistered family")
        if observation.use_scope != "post_valuation_context":
            raise OwnerEquityTypeError("market context observation crossed a phase boundary")
        if observation.response_fingerprint not in response_fingerprints:
            raise OwnerEquityTypeError(
                "market context observation is outside the post-valuation execution"
            )
        if observation.field_id == "availability":
            continue
        observations.append(observation.to_dict())
    observations.sort(
        key=lambda item: (
            item["data_family"],
            item["field_id"],
            item["observation_fingerprint"],
        )
    )
    return tuple(observations)


def _expectation_coverage(
    observations: tuple[dict[str, Any], ...],
) -> tuple[str, tuple[str, ...]]:
    present = {str(item["data_family"]) for item in observations}
    missing = tuple(
        f"market_expectations_missing:{family}"
        for family in _EXPECTATION_FAMILIES
        if family not in present
    )
    return ("partial" if missing else "complete"), missing


def _market_expectations_payload(
    session: FutuSessionEvidence,
    composite: CompositeValuationResult,
    scorecard: OwnerScorecard,
) -> dict[str, Any]:
    if type(session) is not FutuSessionEvidence:
        raise OwnerEquityTypeError("market expectations require the exact live Futu session")
    if type(composite) is not CompositeValuationResult or type(scorecard) is not OwnerScorecard:
        raise OwnerEquityTypeError("market expectations require exact frozen conclusions")
    if (
        session.issuer_id != composite.issuer_id
        or scorecard.issuer_id != composite.issuer_id
        or scorecard.composite_valuation_fingerprint != composite.fingerprint
    ):
        raise OwnerEquityTypeError("market expectations conclusion identity differs")
    conclusion = session.frozen_conclusion
    if (
        conclusion.composite_valuation != composite
        or conclusion.owner_scorecard != scorecard
        or conclusion.issuer_id != composite.issuer_id
    ):
        raise OwnerEquityTypeError(
            "market expectations are not bound to the session's exact frozen conclusion"
        )
    post_execution = _post_valuation_execution(session)
    if any(
        request.frozen_conclusion_receipt_id != conclusion.receipt_id
        or request.frozen_conclusion_fingerprint != conclusion.fingerprint
        for request in post_execution.requests
    ):
        raise OwnerEquityTypeError(
            "market expectations post requests rebound the frozen conclusion"
        )
    observations = _expectation_observations(session)
    status, missing = _expectation_coverage(observations)
    payload: dict[str, Any] = {
        "schema_version": "1.0.0",
        "artifact_type": "market-expectations-comparison",
        "status": status,
        "issuer_id": composite.issuer_id,
        "as_of_date": composite.basis_receipt["valuation_date"],
        "futu_session_id": session.session_id,
        "futu_session_fingerprint": session.fingerprint,
        "composite_valuation_fingerprint": composite.fingerprint,
        "owner_scorecard_fingerprint": scorecard.fingerprint,
        "frozen_conclusion_receipt": {
            "object_id": conclusion.receipt_id,
            "fingerprint": conclusion.fingerprint,
        },
        "post_valuation_execution": {
            "object_id": post_execution.bundle.bundle_id,
            "fingerprint": post_execution.bundle.fingerprint,
        },
        "post_requests": [
            {"object_id": request.request_id, "fingerprint": request.fingerprint}
            for request in post_execution.requests
        ],
        "post_responses": [
            {"object_id": response.response_id, "fingerprint": response.fingerprint}
            for response in post_execution.responses
        ],
        "frozen_conclusion": {
            "composite_status": composite.status,
            "current_intrinsic_value": composite.current_intrinsic_value,
            "twelve_month_target": composite.twelve_month_target,
            "recommendation": scorecard.recommendation,
            "recommendation_eligible": composite.recommendation_eligible,
        },
        "observations": observations,
        "issue_codes": missing,
        "influence_attestation": "post_conclusion_context_only_no_model_or_score_input",
    }
    payload["comparison_id"] = (
        f"market-expectations-comparison:{composite.issuer_id}:{canonical_sha256(payload)[:24]}"
    )
    payload["comparison_fingerprint"] = canonical_sha256(payload)
    return payload


@dataclass(frozen=True, slots=True)
class MarketExpectationsComparison:
    """Post-conclusion Futu context that cannot feed valuation or scoring."""

    session: FutuSessionEvidence
    composite_valuation: CompositeValuationResult
    owner_scorecard: OwnerScorecard
    _payload: FrozenMap
    SCHEMA_NAME: ClassVar[str] = "market-expectations-comparison"

    def __post_init__(self) -> None:
        raw = to_json_value(self._payload)
        if not isinstance(raw, dict):
            raise OwnerEquityTypeError("market expectations payload must be an object")
        _validate(self.SCHEMA_NAME, raw)
        expected = to_json_value(
            _market_expectations_payload(
                self.session,
                self.composite_valuation,
                self.owner_scorecard,
            )
        )
        if raw != expected:
            raise OwnerEquityTypeError(
                "market expectations differ from their retained typed authorities"
            )
        object.__setattr__(self, "_payload", freeze(raw))

    @classmethod
    def from_dict(
        cls,
        payload: Mapping[str, Any],
        *,
        session: FutuSessionEvidence,
        composite_valuation: CompositeValuationResult,
        owner_scorecard: OwnerScorecard,
        verifier: SignatureVerifier,
    ) -> MarketExpectationsComparison:
        validate_futu_session_evidence_replay(session, verifier=verifier)
        return cls(
            session=session,
            composite_valuation=composite_valuation,
            owner_scorecard=owner_scorecard,
            _payload=freeze(payload),
        )

    def to_dict(self) -> dict[str, Any]:
        raw = to_json_value(self._payload)
        assert isinstance(raw, dict)
        return raw

    @property
    def fingerprint(self) -> str:
        return str(self._payload["comparison_fingerprint"])

    @property
    def status(self) -> str:
        return str(self._payload["status"])

    @property
    def issue_codes(self) -> tuple[str, ...]:
        return tuple(self._payload["issue_codes"])


@dataclass(frozen=True, slots=True)
class MarketExpectationsPublicationManifest:
    """Disk-safe market comparison with independently replayed observation identities."""

    _payload: FrozenMap
    SCHEMA_NAME: ClassVar[str] = "market-expectations-comparison"

    def __post_init__(self) -> None:
        raw = to_json_value(self._payload)
        if not isinstance(raw, dict):
            raise OwnerEquityTypeError("market-expectations publication must be an object")
        _validate(self.SCHEMA_NAME, raw)
        identity = dict(raw)
        supplied_fingerprint = identity.pop("comparison_fingerprint")
        if supplied_fingerprint != canonical_sha256(identity):
            raise OwnerEquityTypeError("market-expectations fingerprint does not replay")
        supplied_id = identity.pop("comparison_id")
        expected_id = (
            f"market-expectations-comparison:{raw['issuer_id']}:{canonical_sha256(identity)[:24]}"
        )
        if supplied_id != expected_id:
            raise OwnerEquityTypeError("market-expectations ID does not replay")
        try:
            observations = tuple(FutuObservation(**item) for item in raw["observations"])
        except (TypeError, ValueError) as exc:
            raise OwnerEquityTypeError(
                "market-expectations observations do not replay exact identities"
            ) from exc
        if len({item.observation_id for item in observations}) != len(observations):
            raise OwnerEquityTypeError("market-expectations repeats an observation")
        request_refs = tuple(
            (item["object_id"], item["fingerprint"]) for item in raw["post_requests"]
        )
        response_refs = tuple(
            (item["object_id"], item["fingerprint"]) for item in raw["post_responses"]
        )
        if (
            not request_refs
            or len(request_refs) != len(set(request_refs))
            or len(response_refs) != len(set(response_refs))
            or len(request_refs) != len(response_refs)
            or any(
                observation.response_fingerprint not in {item[1] for item in response_refs}
                for observation in observations
            )
        ):
            raise OwnerEquityTypeError(
                "market-expectations post-execution references do not replay"
            )
        object.__setattr__(self, "_payload", freeze(raw))

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> MarketExpectationsPublicationManifest:
        return cls(_payload=freeze(payload))

    def to_dict(self) -> dict[str, Any]:
        raw = to_json_value(self._payload)
        assert isinstance(raw, dict)
        return raw

    @property
    def fingerprint(self) -> str:
        return str(self._payload["comparison_fingerprint"])

    @property
    def status(self) -> str:
        return str(self._payload["status"])

    @property
    def issue_codes(self) -> tuple[str, ...]:
        return tuple(self._payload["issue_codes"])


def build_market_expectations_comparison(
    *,
    session: FutuSessionEvidence,
    composite_valuation: CompositeValuationResult,
    owner_scorecard: OwnerScorecard,
    verifier: SignatureVerifier,
) -> MarketExpectationsComparison:
    """Build only after replaying the full three-stage quote-only session."""

    if verifier is None or not callable(getattr(verifier, "verify", None)):
        raise OwnerEquityTypeError("market expectations require an exact signature verifier")
    validate_futu_session_evidence_replay(session, verifier=verifier)
    return MarketExpectationsComparison(
        session=session,
        composite_valuation=composite_valuation,
        owner_scorecard=owner_scorecard,
        _payload=freeze(
            _market_expectations_payload(session, composite_valuation, owner_scorecard)
        ),
    )


def build_market_expectations_publication_manifest(
    comparison: MarketExpectationsComparison,
    *,
    futu_session_manifest: FutuSessionPublicationManifest,
) -> MarketExpectationsPublicationManifest:
    if type(comparison) is not MarketExpectationsComparison:
        raise OwnerEquityTypeError("market-expectations publication requires the live comparison")
    if type(futu_session_manifest) is not FutuSessionPublicationManifest:
        raise OwnerEquityTypeError("market-expectations publication requires the Futu manifest")
    payload = comparison.to_dict()
    manifest = MarketExpectationsPublicationManifest.from_dict(payload)
    validate_market_expectations_publication_manifest(
        manifest,
        futu_session_manifest=futu_session_manifest,
    )
    return manifest


def validate_market_expectations_publication_manifest(
    manifest: MarketExpectationsPublicationManifest,
    *,
    futu_session_manifest: FutuSessionPublicationManifest,
) -> None:
    """Replay the disk-safe comparison against its exact Futu session projection."""

    if type(manifest) is not MarketExpectationsPublicationManifest:
        raise OwnerEquityTypeError("market-expectations validation requires the exact manifest")
    if type(futu_session_manifest) is not FutuSessionPublicationManifest:
        raise OwnerEquityTypeError("market-expectations validation requires the Futu manifest")
    validate_futu_session_publication_manifest(futu_session_manifest)
    payload = manifest.to_dict()
    if (
        payload["futu_session_id"] != futu_session_manifest.session_id
        or payload["futu_session_fingerprint"] != futu_session_manifest.session_fingerprint
        or payload["frozen_conclusion_receipt"]
        != to_json_value(futu_session_manifest.frozen_conclusion)
        or payload["post_valuation_execution"]
        != to_json_value(futu_session_manifest.execution_bundles[-1])
    ):
        raise OwnerEquityTypeError("market-expectations publication changed Futu session")
    request_refs = {
        (item["object_id"], item["fingerprint"]) for item in futu_session_manifest.requests
    }
    response_refs = {
        (item["object_id"], item["fingerprint"]) for item in futu_session_manifest.responses
    }
    comparison_request_refs = {
        (item["object_id"], item["fingerprint"]) for item in payload["post_requests"]
    }
    comparison_response_refs = {
        (item["object_id"], item["fingerprint"]) for item in payload["post_responses"]
    }
    if not comparison_request_refs.issubset(request_refs) or not comparison_response_refs.issubset(
        response_refs
    ):
        raise OwnerEquityTypeError(
            "market-expectations publication includes a request or response "
            "outside the Futu manifest"
        )
    manifest_refs = {
        (item["object_id"], item["fingerprint"]) for item in futu_session_manifest.observations
    }
    comparison_refs = {
        (item["observation_id"], item["observation_fingerprint"])
        for item in payload["observations"]
    }
    if not comparison_refs.issubset(manifest_refs):
        raise OwnerEquityTypeError(
            "market-expectations publication includes an observation outside the Futu manifest"
        )


__all__ = (
    "FutuOptionalDataDisposition",
    "FutuOptionalDataDispositionPublicationManifest",
    "MarketExpectationsComparison",
    "MarketExpectationsPublicationManifest",
    "OwnerEquityTypeError",
    "ResearchSourceIndex",
    "ResearchSourceIndexPublicationManifest",
    "RuntimeGapPublicationManifest",
    "RuntimeGapReceipt",
    "build_futu_optional_data_disposition_publication_manifests",
    "build_futu_optional_data_dispositions",
    "build_market_expectations_comparison",
    "build_market_expectations_publication_manifest",
    "build_research_source_index",
    "build_research_source_index_publication_manifest",
    "build_runtime_gap_publication_manifest",
    "compile_futu_optional_data_request_specs",
    "load_owner_equity_schema",
    "validate_market_expectations_publication_manifest",
)
