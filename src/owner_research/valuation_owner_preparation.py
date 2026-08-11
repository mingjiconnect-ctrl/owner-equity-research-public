"""Internal Phase 5 v1 preparation orchestration through a validated market Snapshot."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .fingerprints import canonical_sha256, to_json_value
from .validation import ContractGraph
from .valuation_current_share_compiler import compile_quote_date_current_common_shares
from .valuation_market_provider import (
    ReviewedFileMarketProvider,
    RunClock,
    acquire_reviewed_market_reference,
)
from .valuation_market_snapshot import (
    PreparedMarketReference,
    build_reviewed_market_reference_snapshot,
)
from .valuation_price_blind_freeze import (
    PriceBlindFreezeCompilationResult,
    load_price_blind_input_artifact,
)
from .valuation_security_identity import SecurityIdentityCompilationResult


@dataclass(frozen=True, slots=True)
class OwnerValuationPreparationResult:
    status: str
    issuer_id: str
    data_cutoff_date: str
    price_blind_input_fingerprint: str
    prepared_market_reference: PreparedMarketReference | None
    issue_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.status not in {"prepared", "blocked", "specialist_required"}:
            raise ValueError("owner-valuation preparation status is not registered")
        issues = tuple(sorted(self.issue_codes))
        if self.status == "prepared":
            if self.prepared_market_reference is None or issues:
                raise ValueError("prepared valuation lacks its market reference")
        elif self.prepared_market_reference is not None or not issues:
            raise ValueError("non-prepared valuation must retain a blocking reason")
        object.__setattr__(self, "issue_codes", issues)

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(self.to_dict())


def prepare_owner_valuation(
    *,
    graph: ContractGraph,
    price_blind_artifact_directory: Path,
    expected_freeze: PriceBlindFreezeCompilationResult,
    expected_security: SecurityIdentityCompilationResult,
    market_provider: ReviewedFileMarketProvider,
    clock: RunClock,
) -> OwnerValuationPreparationResult:
    """Replay the completed 5B-5D freeze, then compile current shares and Snapshot v4."""

    loaded = load_price_blind_input_artifact(
        price_blind_artifact_directory,
        graph=graph,
        expected_result=expected_freeze,
    )
    artifact = loaded.artifact.to_dict()
    if expected_security.status != "eligible":
        return OwnerValuationPreparationResult(
            status=(
                "specialist_required"
                if expected_security.status == "specialist_required"
                else "blocked"
            ),
            issuer_id=artifact["issuer_id"],
            data_cutoff_date=artifact["data_cutoff_date"],
            price_blind_input_fingerprint=artifact["price_blind_input_fingerprint"],
            prepared_market_reference=None,
            issue_codes=expected_security.issue_codes or ("security_identity_blocked",),
        )
    acquisition = acquire_reviewed_market_reference(
        price_blind_artifact_directory=price_blind_artifact_directory,
        graph=graph,
        expected_freeze=loaded,
        expected_security=expected_security,
        provider=market_provider,
        clock=clock,
    )
    shares = compile_quote_date_current_common_shares(
        price_blind_artifact_directory=price_blind_artifact_directory,
        graph=graph,
        expected_freeze=loaded,
        expected_security=expected_security,
        expected_market_access=acquisition.access_result,
    )
    if shares.status != "eligible":
        return OwnerValuationPreparationResult(
            status=(
                "specialist_required"
                if shares.status == "specialist_required"
                else "blocked"
            ),
            issuer_id=artifact["issuer_id"],
            data_cutoff_date=artifact["data_cutoff_date"],
            price_blind_input_fingerprint=artifact["price_blind_input_fingerprint"],
            prepared_market_reference=None,
            issue_codes=shares.issue_codes,
        )
    prepared = build_reviewed_market_reference_snapshot(
        price_blind_artifact_directory=price_blind_artifact_directory,
        graph=graph,
        expected_freeze=loaded,
        expected_security=expected_security,
        acquisition=acquisition,
        current_shares=shares,
    )
    return OwnerValuationPreparationResult(
        status="prepared",
        issuer_id=artifact["issuer_id"],
        data_cutoff_date=artifact["data_cutoff_date"],
        price_blind_input_fingerprint=artifact["price_blind_input_fingerprint"],
        prepared_market_reference=prepared,
        issue_codes=(),
    )


__all__ = ()
