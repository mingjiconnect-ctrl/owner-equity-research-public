"""Closed Phase 5E-0 policies for governed market access and kernel execution.

This module defines policy semantics only.  It intentionally contains no
network adapter, market-snapshot builder, request compiler, kernel invocation,
or artifact writer.
"""

from __future__ import annotations

from dataclasses import dataclass

from .fingerprints import canonical_sha256

PHASE5E_POLICY_ID = "phase5e-market-request-kernel-boundary"
PHASE5E_POLICY_VERSION = "1.0.0"

MARKET_QUOTE_POLICY_ID = "governed-market-quote"
MARKET_QUOTE_POLICY_VERSION = "1.0.0"
SECURITY_IDENTITY_POLICY_ID = "single-security-identity"
SECURITY_IDENTITY_POLICY_VERSION = "1.0.0"
SHARE_BASIS_POLICY_ID = "quote-date-current-common-shares"
SHARE_BASIS_POLICY_VERSION = "2.0.0"
FINAL_REQUEST_POLICY_ID = "price-blind-final-request"
FINAL_REQUEST_POLICY_VERSION = "1.0.0"
KERNEL_EXECUTION_POLICY_ID = "isolated-pinned-kernel"
KERNEL_EXECUTION_POLICY_VERSION = "1.0.0"

PINNED_KERNEL_REPOSITORY = "mingjiconnect-ctrl/owner-valuation-kernel"
PINNED_KERNEL_TAG = "v2.0.0-rc.2"
PINNED_KERNEL_COMMIT = "be9b0773d5a78f5f8a33ba982494512668df85fe"
PINNED_KERNEL_PACKAGE_VERSION = "2.0.0rc2"
PINNED_KERNEL_PLUGIN_VERSION = "2.0.0-rc.2"
PINNED_KERNEL_SCHEMA_SHA256 = {
    "schemas/assumption-ledger.schema.json": (
        "2232642332dc6444c784e21746cbd16bf8d4cd74fc483a0a345d95f98fc97a7a"
    ),
    "schemas/fact-ledger.schema.json": (
        "55be5aadad21629db1cdbe7fce386656eb930b52af8644d1314ba7404e384706"
    ),
    "schemas/sec-company-profile.schema.json": (
        "539b76ad7974162ba36b513c029d7d8377d352de4e150425c19c4dea620fbf06"
    ),
    "schemas/sec-company-review.schema.json": (
        "24dfa87fa94c0362569979e454cd1f536eef7c7845473567e4e88df872335205"
    ),
    "schemas/sec-evidence-pack.schema.json": (
        "3cf634214584d54d83b0d397da3139ca30815a44e99e7ecc24c3258b25a7b91a"
    ),
    "schemas/sec-scenario-policy.schema.json": (
        "74c0b0cce146891825fcf4599658f99a20fa66924cf07655895dcece00010065"
    ),
    "schemas/valuation-request.schema.json": (
        "67e991484943897585a79a8a1d3d0d52ebb36ec0ba4245cad9b17972877cca3d"
    ),
    "schemas/valuation-result.schema.json": (
        "bbfed2049ed258b767002b74ff45fb6847eb5723ffd6c1d31c53cf119625a683"
    ),
}

MARKET_PRICE_BASES = ("official_unadjusted_close",)
MARKET_SESSION_KINDS = ("regular",)
MARKET_SESSION_STATUSES = ("completed",)
MARKET_INSTRUMENT_STATUSES = ("active",)
MARKET_QUOTE_STATUSES = ("eligible", "blocked")

SECURITY_STRUCTURES = (
    "single_primary_common",
    "adr_or_depositary_receipt",
    "dual_or_multi_class_different_prices",
    "cross_listed_or_multi_venue",
    "multi_security_aggregation",
    "unresolved",
)
SECURITY_DISPOSITIONS = ("eligible", "specialist_required", "blocked")
SUPPORTED_SECURITY_STRUCTURE = "single_primary_common"
SUPPORTED_SHARE_CLASS = "common"

SHARE_BASIS_KINDS = (
    "current_common_shares_outstanding",
    "weighted_average_eps_diluted",
    "basic_point_in_time",
    "potential_shares",
    "authorized_or_reserved_shares",
    "unresolved",
)
SHARE_BASIS_EVIDENCE_KINDS = (
    "direct_point_in_time",
    "issued_less_treasury",
    "completed_event_rollforward",
)
SHARE_BASIS_DISPOSITIONS = ("eligible", "specialist_required", "blocked")
SUPPORTED_SHARE_BASIS = "current_common_shares_outstanding"
SUPPORTED_SPLIT_FACTOR = "1"

FINAL_REQUEST_ADDED_SOURCE_ROLES = ("market_reference",)
FINAL_REQUEST_ADDED_FACT_ROLES = ("market_quote", "market_equity_value")
FINAL_REQUEST_MUTABLE_BINDINGS = ("assumption_ledger.fact_ledger_fingerprint",)
FINAL_REQUEST_PROTECTED_CHANNELS = (
    "company",
    "routing_assessments",
    "accounting_checks",
    "method_views",
    "mckinsey",
    "assumption_entries",
    "price_blind_input",
    "protected_mckinsey_sha256",
    "protected_penman_assumptions_sha256",
)

KERNEL_EXECUTION_MODES = ("isolated_subprocess",)
KERNEL_REQUEST_TRANSPORTS = ("canonical_json_stdin",)
KERNEL_RESULT_TRANSPORTS = ("canonical_json_stdout",)
KERNEL_NETWORK_MODES = ("disabled",)

PHASE5E_REASON_CODES = frozenset(
    {
        "adjusted_close_forbidden",
        "assumption_entries_changed",
        "authorization_after_request_start",
        "corporate_action_evidence_missing",
        "cross_currency_security",
        "cross_listing_unsupported",
        "dual_class_security_unsupported",
        "future_quote",
        "handoff_transition_invalid",
        "kernel_component_drift",
        "kernel_network_not_disabled",
        "kernel_result_modified",
        "market_lineage_contamination",
        "market_value_not_derived",
        "multi_security_aggregation_unsupported",
        "non_regular_session",
        "price_blind_artifact_changed",
        "protected_hash_changed",
        "quote_after_retrieval",
        "quote_session_incomplete",
        "security_identity_unresolved",
        "split_factor_unsupported",
        "stale_or_halted_quote",
        "unregistered_provider",
        "weighted_average_shares_forbidden",
    }
)


@dataclass(frozen=True, slots=True)
class MarketQuotePolicy:
    policy_id: str
    policy_version: str
    permitted_price_bases: tuple[str, ...]
    permitted_session_kinds: tuple[str, ...]
    permitted_session_statuses: tuple[str, ...]
    latest_completed_session_on_or_before_cutoff: bool
    authorization_precedes_request: bool
    request_precedes_retrieval: bool
    provider_registration_required: bool
    raw_response_hash_required: bool
    trading_calendar_required: bool
    active_instrument_required: bool


@dataclass(frozen=True, slots=True)
class SecurityIdentityPolicy:
    policy_id: str
    policy_version: str
    supported_structure: str
    single_security_required: bool
    same_reporting_currency_required: bool
    unsupported_disposition: str


@dataclass(frozen=True, slots=True)
class ShareBasisPolicy:
    policy_id: str
    policy_version: str
    supported_basis: str
    weighted_average_forbidden: bool
    quote_date_alignment_required: bool
    corporate_action_evidence_required: bool
    supported_split_factor: str
    unsupported_split_disposition: str


@dataclass(frozen=True, slots=True)
class FinalRequestPolicy:
    policy_id: str
    policy_version: str
    added_source_roles: tuple[str, ...]
    added_fact_roles: tuple[str, ...]
    mutable_bindings: tuple[str, ...]
    protected_channels: tuple[str, ...]
    assumption_entry_byte_equality_required: bool
    existing_fact_byte_equality_required: bool


@dataclass(frozen=True, slots=True)
class KernelExecutionPolicy:
    policy_id: str
    policy_version: str
    execution_mode: str
    request_transport: str
    result_transport: str
    network_mode: str
    pinned_wheel_required: bool
    dependency_wheel_hashes_required: bool
    schema_hash_verification_required: bool
    result_byte_preservation_required: bool


MARKET_QUOTE_POLICY = MarketQuotePolicy(
    MARKET_QUOTE_POLICY_ID,
    MARKET_QUOTE_POLICY_VERSION,
    MARKET_PRICE_BASES,
    MARKET_SESSION_KINDS,
    MARKET_SESSION_STATUSES,
    True,
    True,
    True,
    True,
    True,
    True,
    True,
)
SECURITY_IDENTITY_POLICY = SecurityIdentityPolicy(
    SECURITY_IDENTITY_POLICY_ID,
    SECURITY_IDENTITY_POLICY_VERSION,
    SUPPORTED_SECURITY_STRUCTURE,
    True,
    True,
    "specialist_required",
)
SHARE_BASIS_POLICY = ShareBasisPolicy(
    SHARE_BASIS_POLICY_ID,
    SHARE_BASIS_POLICY_VERSION,
    SUPPORTED_SHARE_BASIS,
    True,
    True,
    True,
    SUPPORTED_SPLIT_FACTOR,
    "specialist_required",
)
FINAL_REQUEST_POLICY = FinalRequestPolicy(
    FINAL_REQUEST_POLICY_ID,
    FINAL_REQUEST_POLICY_VERSION,
    FINAL_REQUEST_ADDED_SOURCE_ROLES,
    FINAL_REQUEST_ADDED_FACT_ROLES,
    FINAL_REQUEST_MUTABLE_BINDINGS,
    FINAL_REQUEST_PROTECTED_CHANNELS,
    True,
    True,
)
KERNEL_EXECUTION_POLICY = KernelExecutionPolicy(
    KERNEL_EXECUTION_POLICY_ID,
    KERNEL_EXECUTION_POLICY_VERSION,
    "isolated_subprocess",
    "canonical_json_stdin",
    "canonical_json_stdout",
    "disabled",
    True,
    True,
    True,
    True,
)

PHASE5E_POLICIES = {
    "market_quote": MARKET_QUOTE_POLICY,
    "security_identity": SECURITY_IDENTITY_POLICY,
    "share_basis": SHARE_BASIS_POLICY,
    "final_request": FINAL_REQUEST_POLICY,
    "kernel_execution": KERNEL_EXECUTION_POLICY,
}


def phase5e_policy_sha256() -> str:
    """Return the canonical hash of every closed Phase 5E-0 registry."""

    return canonical_sha256(
        {
            "policy_id": PHASE5E_POLICY_ID,
            "policy_version": PHASE5E_POLICY_VERSION,
            "policies": PHASE5E_POLICIES,
            "security_structures": SECURITY_STRUCTURES,
            "security_dispositions": SECURITY_DISPOSITIONS,
            "share_basis_kinds": SHARE_BASIS_KINDS,
            "share_basis_dispositions": SHARE_BASIS_DISPOSITIONS,
            "market_quote_statuses": MARKET_QUOTE_STATUSES,
            "market_instrument_statuses": MARKET_INSTRUMENT_STATUSES,
            "kernel_identity": {
                "repository": PINNED_KERNEL_REPOSITORY,
                "tag": PINNED_KERNEL_TAG,
                "commit": PINNED_KERNEL_COMMIT,
                "package_version": PINNED_KERNEL_PACKAGE_VERSION,
                "plugin_version": PINNED_KERNEL_PLUGIN_VERSION,
                "schema_sha256": PINNED_KERNEL_SCHEMA_SHA256,
            },
            "reason_codes": tuple(sorted(PHASE5E_REASON_CODES)),
        }
    )
