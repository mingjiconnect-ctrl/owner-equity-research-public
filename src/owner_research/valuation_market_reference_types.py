"""Internal validation witnesses for MarketReferenceSnapshot 3.0.0.

This module deliberately provides no builder or compiler. ContractGraph derives claim-control
authority from the frozen Phase 5C bridge while current-share numeric lineage remains separate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .fingerprints import canonical_sha256, to_json_value
from .valuation_market_access import MarketAccessResult
from .valuation_price_blind_freeze import (
    PriceBlindFreezeCompilationResult,
    PriceBlindInputArtifact,
)
from .valuation_security_identity import SecurityIdentityCompilationResult


def _ordered(values: Any, label: str, *, required: bool = False) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)) or any(not isinstance(value, str) for value in values):
        raise ValueError(f"{label} must be a sequence of IDs")
    ordered = tuple(sorted(values))
    if len(ordered) != len(set(ordered)) or any(not value.strip() for value in ordered):
        raise ValueError(f"{label} must contain unique nonempty IDs")
    if required and not ordered:
        raise ValueError(f"{label} is required")
    return ordered


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def _records_for_root(
    records: tuple[dict[str, Any], ...],
    root_id: str,
) -> tuple[dict[str, Any], ...]:
    return tuple(item for item in records if item.get("root_fact_id") == root_id)


@dataclass(frozen=True, slots=True)
class Phase5CDilutionClaimAuthority:
    """Code-derived claim-control witness over the frozen Phase 5C bridge surface."""

    phase5c_readiness_sha256: str
    equity_bridge_fingerprint: str
    economic_claim_bindings_sha256: str
    consumption_records_sha256: str
    included_option_root_fact_ids: tuple[str, ...]
    excluded_option_root_fact_ids: tuple[str, ...]
    blocked_option_root_fact_ids: tuple[str, ...]
    option_bridge_status: str
    option_bridge_root_fact_ids: tuple[str, ...]
    standard_path_disposition: str

    @classmethod
    def from_price_blind_artifact(
        cls,
        artifact: PriceBlindInputArtifact,
    ) -> Phase5CDilutionClaimAuthority:
        payload = artifact.to_dict()
        readiness = _mapping(payload.get("phase5c_readiness"), "frozen Phase 5C readiness")
        if (
            readiness.get("issuer_id") != payload["issuer_id"]
            or readiness.get("data_cutoff_date") != payload["data_cutoff_date"]
        ):
            raise ValueError("frozen Phase 5C readiness identity does not replay")
        bridge = _mapping(
            readiness.get("equity_bridge_result"),
            "frozen Phase 5C equity bridge",
        )
        bridge_fingerprint = readiness.get("equity_bridge_fingerprint")
        if (
            not isinstance(bridge_fingerprint, str)
            or bridge_fingerprint != canonical_sha256(bridge)
            or bridge.get("issuer_id") != payload["issuer_id"]
            or bridge.get("data_cutoff_date") != payload["data_cutoff_date"]
        ):
            raise ValueError("frozen Phase 5C equity-bridge fingerprint does not replay")
        method_view = _mapping(bridge.get("method_view_result"), "Phase 5C MethodView")
        reconciliation = _mapping(
            method_view.get("reconciliation_result"),
            "Phase 5C accounting reconciliation",
        )
        bindings_value = reconciliation.get("economic_claim_bindings")
        records_value = bridge.get("consumption_records")
        decisions_value = bridge.get("role_decisions")
        if not isinstance(bindings_value, (list, tuple)) or not isinstance(
            records_value, (list, tuple)
        ) or not isinstance(decisions_value, (list, tuple)):
            raise ValueError("Phase 5C dilution authority collections are unavailable")
        bindings = tuple(_mapping(item, "economic-claim binding") for item in bindings_value)
        records = tuple(_mapping(item, "consumption record") for item in records_value)
        decisions = tuple(_mapping(item, "equity-bridge role decision") for item in decisions_value)
        option_bindings = tuple(
            item for item in bindings if item.get("economic_identity") == "option_or_dilution_claim"
        )
        option_decisions = tuple(
            item for item in decisions if item.get("role") == "option_or_dilution_claim"
        )
        if not option_bindings or len(option_decisions) != 1:
            raise ValueError("Phase 5C option/dilution authority is incomplete")
        option_decision = option_decisions[0]
        option_status = option_decision.get("status")
        if option_status not in {"modeled", "explicitly_absent", "not_applicable", "unresolved"}:
            raise ValueError("Phase 5C option bridge status is invalid")

        treatment_roots: dict[str, set[str]] = {
            "included": set(),
            "excluded": set(),
            "blocked": set(),
        }
        phase5c_diluted_id = bridge.get("diluted_shares_fact_id")
        if not isinstance(phase5c_diluted_id, str) or not phase5c_diluted_id:
            raise ValueError("Phase 5C diluted-share Fact is unavailable")
        for binding in option_bindings:
            roots = set(_ordered(binding.get("root_fact_ids"), "option roots", required=True))
            treatment = binding.get("diluted_share_treatment")
            if treatment in treatment_roots:
                if treatment_roots[treatment].intersection(roots):
                    raise ValueError("Phase 5C option roots are duplicated within one treatment")
                treatment_roots[treatment].update(roots)
            if treatment in {"included", "excluded"} and _ordered(
                binding.get("diluted_share_fact_ids"),
                "option diluted-share evidence",
                required=True,
            ) != (phase5c_diluted_id,):
                raise ValueError("Phase 5C option treatment does not bind its diluted-share Fact")
        included = treatment_roots["included"]
        excluded = treatment_roots["excluded"]
        blocked = treatment_roots["blocked"]
        if (
            included.intersection(excluded)
            or included.intersection(blocked)
            or excluded.intersection(blocked)
        ):
            raise ValueError("Phase 5C option treatments overlap")

        option_decision_roots = set(
            _ordered(option_decision.get("root_fact_ids"), "option bridge roots")
        )
        if included.intersection(option_decision_roots) and option_status == "modeled":
            raise ValueError("included option roots cannot be modeled in the equity bridge")
        if excluded and (option_status != "modeled" or option_decision_roots != excluded):
            raise ValueError("excluded option roots must exactly equal the modeled bridge roots")
        if not excluded and option_status == "modeled":
            raise ValueError("modeled option bridge lacks an excluded dilution treatment")
        if blocked and option_status != "unresolved":
            raise ValueError("blocked option roots require an unresolved bridge role")

        for root_id in included:
            root_records = _records_for_root(records, root_id)
            denominator_methods = {
                item.get("method")
                for item in root_records
                if item.get("channel") in {"mckinsey_diluted_shares", "penman_diluted_shares"}
                and item.get("consumption_kind") == "economic_deduction"
            }
            if denominator_methods != {"mckinsey", "penman"} or any(
                item.get("channel") == "mckinsey_equity_bridge" for item in root_records
            ):
                raise ValueError("included option root is not consumed only through denominators")
        for root_id in excluded:
            root_records = _records_for_root(records, root_id)
            if any(
                item.get("channel") in {"mckinsey_diluted_shares", "penman_diluted_shares"}
                for item in root_records
            ) or not any(
                item.get("channel") == "mckinsey_equity_bridge"
                and item.get("method") == "mckinsey"
                and item.get("consumption_kind") == "economic_deduction"
                for item in root_records
            ):
                raise ValueError("excluded option root is not isolated to the modeled bridge")

        _ordered(
            bridge.get("diluted_share_root_fact_ids"),
            "legacy Phase 5C denominator roots",
            required=True,
        )
        disposition = (
            "blocked" if blocked else "specialist_required" if included else "eligible"
        )
        return cls(
            phase5c_readiness_sha256=canonical_sha256(readiness),
            equity_bridge_fingerprint=bridge_fingerprint,
            economic_claim_bindings_sha256=canonical_sha256(bindings),
            consumption_records_sha256=canonical_sha256(records),
            included_option_root_fact_ids=tuple(sorted(included)),
            excluded_option_root_fact_ids=tuple(sorted(excluded)),
            blocked_option_root_fact_ids=tuple(sorted(blocked)),
            option_bridge_status=option_status,
            option_bridge_root_fact_ids=tuple(sorted(option_decision_roots)),
            standard_path_disposition=disposition,
        )

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(self.to_dict())


@dataclass(frozen=True, slots=True)
class MarketReferenceValidationContext:
    context_id: str
    price_blind_artifact: PriceBlindInputArtifact
    security_compilation_result: SecurityIdentityCompilationResult
    market_access_result: MarketAccessResult
    current_share_compilation_result: Any
    raw_evidence_locator: str
    raw_evidence_path: Path | None = field(default=None, repr=False, compare=False)
    provider_evidence_sha256: str | None = None
    price_blind_artifact_directory: Path | None = field(
        default=None,
        repr=False,
        compare=False,
    )
    price_blind_freeze_result: PriceBlindFreezeCompilationResult | None = field(
        default=None,
        repr=False,
        compare=False,
    )
    market_reference_request: Any = field(default=None, repr=False, compare=False)
    reviewed_quote: Any = field(default=None, repr=False, compare=False)
    authorization_reservation: Any = field(default=None, repr=False, compare=False)
    authorization_consumption: Any = field(default=None, repr=False, compare=False)
    review_file_path: Path | None = field(default=None, repr=False, compare=False)
    claim_control_authority: Phase5CDilutionClaimAuthority = field(init=False)

    def __post_init__(self) -> None:
        if not self.context_id.strip() or not self.raw_evidence_locator.strip():
            raise ValueError("market-reference validation context identity is required")
        if self.provider_evidence_sha256 is not None and (
            len(self.provider_evidence_sha256) != 64
            or any(
                character not in "0123456789abcdef"
                for character in self.provider_evidence_sha256
            )
        ):
            raise ValueError("provider evidence must be a lowercase SHA-256")
        if type(self.price_blind_artifact) is not PriceBlindInputArtifact:
            raise TypeError("validation context requires the exact price-blind artifact type")
        if type(self.security_compilation_result) is not SecurityIdentityCompilationResult:
            raise TypeError("validation context requires the exact security compilation type")
        if type(self.market_access_result) is not MarketAccessResult:
            raise TypeError("validation context requires the exact market-access result type")
        from .valuation_current_share_compiler import CurrentShareCompilationResult

        if type(self.current_share_compilation_result) is not CurrentShareCompilationResult:
            raise TypeError("validation context requires the exact current-share compilation type")
        security = self.security_compilation_result
        access = self.market_access_result
        compilation = self.current_share_compilation_result
        share_basis = compilation.share_basis_decision
        if (
            security.status != "eligible"
            or security.decision is None
            or security.evidence_closure is None
        ):
            raise ValueError("validation context security identity is not eligible")
        if access.status != "eligible" or access.request is None or access.receipt is None:
            raise ValueError("validation context market access is not eligible")
        artifact = self.price_blind_artifact.to_dict()
        if (
            access.issuer_id != artifact["issuer_id"]
            or access.data_cutoff_date != artifact["data_cutoff_date"]
            or access.price_blind_input_fingerprint != artifact["price_blind_input_fingerprint"]
            or access.protected_mckinsey_sha256 != artifact["protected_mckinsey_sha256"]
            or access.protected_penman_assumptions_sha256
            != artifact["protected_penman_assumptions_sha256"]
        ):
            raise ValueError("validation context changed its price-blind identity")
        receipt = access.receipt
        if (
            receipt.security_compilation_fingerprint != security.fingerprint
            or receipt.security_evidence_closure_sha256 != security.evidence_closure.closure_sha256
            or access.request.security_id != security.decision.security_id
        ):
            raise ValueError("validation context security and market access do not replay")
        if (
            compilation.status != "eligible"
            or compilation.output_fact is None
            or compilation.evidence_closure is None
            or share_basis is None
            or share_basis.disposition != "eligible"
            or share_basis.issuer_id != access.issuer_id
            or share_basis.security_id != access.request.security_id
            or share_basis.quote_date != access.receipt.receipt.trading_date
        ):
            raise ValueError("validation context share basis is not eligible")
        if receipt.evidence_mode == "human_reviewed_file":
            from .valuation_market_provider import (
                MarketAuthorizationConsumption,
                MarketAuthorizationReservation,
                MarketReferenceRequest,
                RawMarketQuote,
            )

            if (
                self.price_blind_artifact_directory is None
                or self.price_blind_freeze_result is None
                or self.raw_evidence_path is None
                or self.review_file_path is None
                or type(self.market_reference_request) is not MarketReferenceRequest
                or type(self.reviewed_quote) is not RawMarketQuote
                or type(self.authorization_reservation)
                is not MarketAuthorizationReservation
                or type(self.authorization_consumption)
                is not MarketAuthorizationConsumption
                or self.price_blind_freeze_result.artifact.fingerprint
                != self.price_blind_artifact.fingerprint
                or self.market_reference_request.authorization_handoff_id
                != access.authorization_handoff_id
                or self.reviewed_quote.review_receipt_sha256
                != self.provider_evidence_sha256
                or self.authorization_consumption.authorization_handoff_id
                != access.authorization_handoff_id
                or self.authorization_reservation.authorization_handoff_id
                != access.authorization_handoff_id
                or self.authorization_reservation.request_fingerprint
                != self.market_reference_request.request_fingerprint
                or self.authorization_consumption.reservation_fingerprint
                != self.authorization_reservation.fingerprint
                or self.authorization_consumption.request_fingerprint
                != self.market_reference_request.request_fingerprint
                or self.authorization_consumption.market_access_result_fingerprint
                != access.fingerprint
                or self.authorization_consumption.quote_fingerprint
                != self.reviewed_quote.fingerprint
            ):
                raise ValueError(
                    "human-reviewed validation context lacks replayable provider evidence"
                )
        elif any(
            value is not None
            for value in (
                self.provider_evidence_sha256,
                self.price_blind_artifact_directory,
                self.price_blind_freeze_result,
                self.raw_evidence_path,
                self.review_file_path,
                self.market_reference_request,
                self.reviewed_quote,
                self.authorization_reservation,
                self.authorization_consumption,
            )
        ):
            raise ValueError(
                "non-reviewed market context cannot carry reviewed-file replay authority"
            )
        authority = Phase5CDilutionClaimAuthority.from_price_blind_artifact(
            self.price_blind_artifact
        )
        if authority.standard_path_disposition == "specialist_required":
            raise ValueError("included Phase 5C claims require specialist routing")
        if authority.standard_path_disposition == "blocked":
            raise ValueError("blocked Phase 5C claims prohibit Snapshot validation")
        object.__setattr__(self, "claim_control_authority", authority)

    @property
    def share_basis_decision(self) -> Any:
        """Return only the compiler-owned decision; callers cannot inject it."""

        return self.current_share_compilation_result.share_basis_decision

    @property
    def issuer_id(self) -> str:
        return self.market_access_result.issuer_id

    @property
    def data_cutoff_date(self) -> str:
        return self.market_access_result.data_cutoff_date

    def to_dict(self) -> dict[str, Any]:
        return {
            "context_id": self.context_id,
            "price_blind_artifact": self.price_blind_artifact.to_dict(),
            "security_compilation_result": self.security_compilation_result.to_dict(),
            "market_access_result": self.market_access_result.to_dict(),
            "current_share_compilation_result": (
                self.current_share_compilation_result.to_dict()
            ),
            "raw_evidence_locator": self.raw_evidence_locator,
            "provider_evidence_sha256": self.provider_evidence_sha256,
            "market_reference_request": (
                to_json_value(self.market_reference_request)
                if self.market_reference_request is not None
                else None
            ),
            "reviewed_quote": (
                self.reviewed_quote.to_dict()
                if self.reviewed_quote is not None
                else None
            ),
            "authorization_consumption": (
                self.authorization_consumption.to_dict()
                if self.authorization_consumption is not None
                else None
            ),
            "authorization_reservation": (
                self.authorization_reservation.to_dict()
                if self.authorization_reservation is not None
                else None
            ),
            "claim_control_authority": self.claim_control_authority.to_dict(),
        }

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(to_json_value(self.to_dict()))


__all__ = ()
