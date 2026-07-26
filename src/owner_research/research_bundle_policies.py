"""Closed Phase 4E-0 policy registry and deterministic hash primitives.

This policy module remains pure. Phase 4E-1 construction lives in
``research_bundle_builder`` and must submit its output to ContractGraph validation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .fingerprints import canonical_sha256

BUNDLE_POLICY_ID = "research-bundle"
BUNDLE_POLICY_VERSION = "1.0.0"


@dataclass(frozen=True, slots=True)
class ModulePolicy:
    module_type: str
    contract_type: str
    cardinality: str


MODULE_POLICIES = (
    ModulePolicy("quarterly_update", "QuarterlyUpdate", "exactly_one"),
    ModulePolicy("segment_snapshot", "SegmentSnapshot", "exactly_one"),
    ModulePolicy("footnote_review", "FootnoteReview", "one_or_more"),
    ModulePolicy("accounting_quality_review", "AccountingQualityReview", "exactly_one"),
    ModulePolicy("management_review", "ManagementReview", "exactly_one"),
    ModulePolicy("business_quality_review", "BusinessQualityReview", "one_per_material_scope"),
    ModulePolicy("capital_allocation_review", "CapitalAllocationReview", "exactly_one"),
)

MODULE_TYPES = tuple(item.module_type for item in MODULE_POLICIES)
MODULE_POLICY_BY_TYPE = {item.module_type: item for item in MODULE_POLICIES}


def module_artifact_sha256(entries: list[tuple[str, str, str]]) -> str:
    """Hash selected module objects without depending on input ordering."""

    return canonical_sha256(
        [
            {"contract_type": contract_type, "object_id": object_id, "fingerprint": fingerprint}
            for contract_type, object_id, fingerprint in sorted(entries)
        ]
    )


def dependency_closure_sha256(entries: list[tuple[str, str, str]]) -> str:
    """Hash the selected modules and every transitive contract dependency."""

    return module_artifact_sha256(entries)


def source_graph_sha256(entries: list[tuple[str, str]]) -> str:
    return canonical_sha256(
        [
            {"document_id": document_id, "content_sha256": content_sha256}
            for document_id, content_sha256 in sorted(entries)
        ]
    )


def bundle_identifier(issuer_id: str, cutoff: str, dependency_hash: str) -> str:
    return f"research-bundle:{issuer_id}:{cutoff}:{dependency_hash[:20]}"


def bundle_payload_sha256(payload: dict[str, Any]) -> str:
    """Hash the complete public payload, excluding its self-referential field."""

    semantic_payload = dict(payload)
    semantic_payload.pop("bundle_fingerprint", None)
    for key in (
        "source_document_ids",
        "fiscal_period_ids",
        "segment_definition_ids",
        "missing_evidence",
    ):
        semantic_payload[key] = sorted(semantic_payload[key])
    normalized_references = []
    for raw_reference in semantic_payload["module_references"]:
        reference = dict(raw_reference)
        reference["object_ids"] = sorted(reference["object_ids"])
        reference["missing_evidence"] = sorted(reference["missing_evidence"])
        scope = dict(reference["scope"])
        scope["segment_definition_ids"] = sorted(scope["segment_definition_ids"])
        reference["scope"] = scope
        freshness = dict(reference["freshness"])
        freshness["qualifying_source_document_ids"] = sorted(
            freshness["qualifying_source_document_ids"]
        )
        freshness["missing_evidence"] = sorted(freshness["missing_evidence"])
        reference["freshness"] = freshness
        normalized_references.append(reference)
    semantic_payload["module_references"] = sorted(
        normalized_references,
        key=lambda item: (item["module_type"], item["scope"]["scope_id"]),
    )
    return canonical_sha256(semantic_payload)
