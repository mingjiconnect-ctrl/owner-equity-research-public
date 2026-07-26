"""Immutable internal Phase 5B mapping and readiness results."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .fingerprints import FrozenMap, canonical_sha256, freeze, to_json_value
from .valuation_fact_mapping_policies import (
    CLASSIFICATION_POLICY_ID,
    CLASSIFICATION_POLICY_VERSION,
    MAPPING_DISPOSITIONS,
    READINESS_POLICY_ID,
    READINESS_POLICY_VERSION,
    READINESS_STATUSES,
    REASON_CODES,
    ROUTING_ASSESSMENT_IDS,
    SPECIALIST_ROUTES,
    readiness_policy_sha256,
)


def _unique(values: tuple[str, ...], label: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} must be unique")


@dataclass(frozen=True, slots=True)
class FactMappingDecision:
    object_type: str
    object_id: str
    disposition: str
    reason_codes: tuple[str, ...]
    output_id: str | None = None

    def __post_init__(self) -> None:
        if self.object_type not in {"SourceDocument", "Fact", "CalculationResult"}:
            raise ValueError("mapping decision object type is not supported")
        if self.disposition not in MAPPING_DISPOSITIONS:
            raise ValueError("mapping decision disposition is not registered")
        if not self.object_id:
            raise ValueError("mapping decision object ID is required")
        _unique(self.reason_codes, "mapping decision reason codes")
        if not set(self.reason_codes).issubset(REASON_CODES):
            raise ValueError("mapping decision uses an unregistered reason code")
        if self.disposition == "mapped" and not self.output_id:
            raise ValueError("mapped decision requires an output ID")
        if self.disposition != "mapped" and self.output_id is not None:
            raise ValueError("non-mapped decision cannot emit an output ID")
        object.__setattr__(self, "reason_codes", tuple(sorted(self.reason_codes)))

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(to_json_value(self))


@dataclass(frozen=True, slots=True)
class FactLedgerMappingResult:
    issuer_id: str
    data_cutoff_date: str
    research_bundle_id: str
    research_bundle_fingerprint: str
    dependency_closure_sha256: str
    component_lock_sha256: str
    mapping_policy_id: str
    mapping_policy_version: str
    mapping_policy_sha256: str
    kernel_fact_ledger_schema_sha256: str
    ledger_payload: FrozenMap
    decisions: tuple[FactMappingDecision, ...]

    def __post_init__(self) -> None:
        if not self.issuer_id or not self.research_bundle_id:
            raise ValueError("mapping result identity is required")
        decision_keys = tuple(
            (item.object_type, item.object_id) for item in self.decisions
        )
        _unique(tuple(f"{kind}:{identifier}" for kind, identifier in decision_keys), "decisions")
        object.__setattr__(self, "ledger_payload", freeze(self.ledger_payload))
        object.__setattr__(
            self,
            "decisions",
            tuple(sorted(self.decisions, key=lambda item: (item.object_type, item.object_id))),
        )

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(to_json_value(self))


@dataclass(frozen=True, slots=True)
class CompanyClassificationResult:
    policy_id: str
    policy_version: str
    policy_sha256: str
    company_type: str
    specialist_route: str
    research_evidence_ids: tuple[str, ...]
    mapped_fact_ids: tuple[str, ...]
    routing_assessments: FrozenMap
    rationale: str

    def __post_init__(self) -> None:
        if (
            self.policy_id != CLASSIFICATION_POLICY_ID
            or self.policy_version != CLASSIFICATION_POLICY_VERSION
        ):
            raise ValueError("company classification policy is not registered")
        if self.policy_sha256 != readiness_policy_sha256():
            raise ValueError("company classification policy SHA is invalid")
        if self.company_type not in {
            "nonfinancial_operating_company",
            "bank",
            "insurer",
            "conglomerate",
            "asset_based",
            "distressed",
            "unresolved",
        }:
            raise ValueError("company type is not registered")
        if self.specialist_route not in SPECIALIST_ROUTES:
            raise ValueError("specialist route is not registered")
        if not self.rationale.strip():
            raise ValueError("company classification rationale is required")
        _unique(self.research_evidence_ids, "classification research evidence")
        _unique(self.mapped_fact_ids, "classification mapped facts")
        object.__setattr__(self, "research_evidence_ids", tuple(sorted(self.research_evidence_ids)))
        object.__setattr__(self, "mapped_fact_ids", tuple(sorted(self.mapped_fact_ids)))
        assessments = freeze(self.routing_assessments)
        if set(assessments) != set(ROUTING_ASSESSMENT_IDS):
            raise ValueError("company classification must cover six routing assessments")
        for assessment_id, raw in assessments.items():
            item = dict(raw)
            if set(item) != {
                "status",
                "value",
                "rationale",
                "research_evidence_ids",
                "mapped_fact_ids",
                "reason_codes",
            }:
                raise ValueError(f"routing assessment {assessment_id} has invalid fields")
            if item["status"] not in {"satisfied", "unsatisfied", "blocked"}:
                raise ValueError(f"routing assessment {assessment_id} has invalid status")
            if item["status"] == "blocked" and item["value"] is not None:
                raise ValueError("blocked routing assessment cannot assert a value")
            if item["status"] != "blocked" and not isinstance(item["value"], bool):
                raise ValueError("resolved routing assessment requires a boolean value")
            if not str(item["rationale"]).strip():
                raise ValueError("routing assessment requires a rationale")
            if not set(item["reason_codes"]).issubset(REASON_CODES):
                raise ValueError("routing assessment uses an unregistered reason code")
            for key in ("research_evidence_ids", "mapped_fact_ids", "reason_codes"):
                values = tuple(item[key])
                _unique(values, f"routing assessment {key}")
        object.__setattr__(self, "routing_assessments", assessments)

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(to_json_value(self))


@dataclass(frozen=True, slots=True)
class MethodReadiness:
    method: str
    status: str
    required_roles: tuple[str, ...]
    satisfied_roles: tuple[str, ...]
    missing_roles: tuple[str, ...]
    evidence_fact_ids: tuple[str, ...]
    research_evidence_ids: tuple[str, ...]
    reason_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.method not in {"mckinsey", "penman"}:
            raise ValueError("readiness method is not registered")
        if self.status not in READINESS_STATUSES:
            raise ValueError("readiness status is not registered")
        for values, label in (
            (self.required_roles, "required roles"),
            (self.satisfied_roles, "satisfied roles"),
            (self.missing_roles, "missing roles"),
            (self.evidence_fact_ids, "evidence Fact IDs"),
            (self.research_evidence_ids, "research evidence IDs"),
            (self.reason_codes, "readiness reason codes"),
        ):
            _unique(values, label)
        if set(self.satisfied_roles) | set(self.missing_roles) != set(self.required_roles):
            raise ValueError("readiness role coverage does not match required roles")
        if set(self.satisfied_roles) & set(self.missing_roles):
            raise ValueError("readiness roles cannot be both satisfied and missing")
        if not set(self.reason_codes).issubset(REASON_CODES):
            raise ValueError("readiness uses an unregistered reason code")
        if self.status == "ready" and (self.missing_roles or self.reason_codes):
            raise ValueError("ready method cannot retain missing roles or reasons")
        if self.status == "partial" and (
            not self.missing_roles or "required_role_missing" not in self.reason_codes
        ):
            raise ValueError("partial method requires missing roles")
        if self.status == "specialist_required" and (
            "specialist_route_required" not in self.reason_codes
        ):
            raise ValueError("specialist method requires its registered reason")
        if self.status == "blocked" and (
            "company_classification_unresolved" not in self.reason_codes
        ):
            raise ValueError("blocked method requires unresolved classification")
        for field_name in (
            "required_roles",
            "satisfied_roles",
            "missing_roles",
            "evidence_fact_ids",
            "research_evidence_ids",
            "reason_codes",
        ):
            object.__setattr__(self, field_name, tuple(sorted(getattr(self, field_name))))

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(to_json_value(self))


@dataclass(frozen=True, slots=True)
class ValuationReadinessResult:
    issuer_id: str
    data_cutoff_date: str
    mapping_result_fingerprint: str
    readiness_policy_id: str
    readiness_policy_version: str
    readiness_policy_sha256: str
    classification: CompanyClassificationResult
    mckinsey: MethodReadiness
    penman: MethodReadiness
    specialist_route: str

    def __post_init__(self) -> None:
        if (
            self.readiness_policy_id != READINESS_POLICY_ID
            or self.readiness_policy_version != READINESS_POLICY_VERSION
        ):
            raise ValueError("valuation readiness policy is not registered")
        if self.readiness_policy_sha256 != readiness_policy_sha256():
            raise ValueError("valuation readiness policy SHA is invalid")
        if self.specialist_route not in SPECIALIST_ROUTES:
            raise ValueError("valuation readiness specialist route is not registered")
        if self.classification.specialist_route != self.specialist_route:
            raise ValueError("classification and readiness specialist routes differ")
        if self.mckinsey.method != "mckinsey" or self.penman.method != "penman":
            raise ValueError("valuation readiness panels are not method-specific")
        if self.specialist_route == "none" and any(
            item.status == "specialist_required" for item in (self.mckinsey, self.penman)
        ):
            raise ValueError("core route cannot claim specialist readiness")
        if self.specialist_route == "unresolved" and any(
            item.status != "blocked" for item in (self.mckinsey, self.penman)
        ):
            raise ValueError("unresolved route requires blocked method panels")
        if self.specialist_route not in {"none", "unresolved"} and any(
            item.status != "specialist_required" for item in (self.mckinsey, self.penman)
        ):
            raise ValueError("specialist route requires specialist method panels")
        assessment = self.classification.routing_assessments["required_data_complete"]
        if assessment["status"] != "unsatisfied" or assessment["value"] is not False:
            raise ValueError("Phase 5B cannot assert complete valuation-request data")

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(to_json_value(self))

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)
