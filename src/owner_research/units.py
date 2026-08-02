from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, localcontext


class UnitError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class UnitSpec:
    family: str
    scale: Decimal
    currency_required: bool


UNIT_REGISTRY_VERSION = "1.0.0"

_MONETARY = {
    "currency_units": Decimal("1"),
    "currency_thousands": Decimal("1000"),
    "currency_millions": Decimal("1000000"),
    "currency_billions": Decimal("1000000000"),
}
_COUNT_UNITS = {
    "count",
    "units",
    "customers",
    "users",
    "subscribers",
    "members",
    "stores",
    "locations",
    "employees",
    "shares",
    "transactions",
    "orders",
    "shipments",
    "incidents",
    "nps_points",
}
_RATE_UNITS = {"ratio", "percent", "percentage_points", "basis_points"}
_TIME_UNITS = {"days", "hours", "minutes"}
_PER_UNIT_MONETARY = {
    "currency_per_share",
    "currency_per_customer",
    "currency_per_user",
    "currency_per_subscriber",
    "currency_per_member",
    "currency_per_store",
    "currency_per_location",
    "currency_per_employee",
    "currency_per_transaction",
    "currency_per_order",
    "currency_per_shipment",
}

UNIT_REGISTRY: dict[str, UnitSpec] = {
    **{
        unit: UnitSpec(family="monetary", scale=scale, currency_required=True)
        for unit, scale in _MONETARY.items()
    },
    **{
        unit: UnitSpec(family=f"count:{unit}", scale=Decimal("1"), currency_required=False)
        for unit in _COUNT_UNITS
    },
    **{
        unit: UnitSpec(family=f"rate:{unit}", scale=Decimal("1"), currency_required=False)
        for unit in _RATE_UNITS
    },
    **{
        unit: UnitSpec(family=f"time:{unit}", scale=Decimal("1"), currency_required=False)
        for unit in _TIME_UNITS
    },
    **{
        unit: UnitSpec(family=f"per_unit:{unit}", scale=Decimal("1"), currency_required=True)
        for unit in _PER_UNIT_MONETARY
    },
}


def unit_spec(unit: str) -> UnitSpec:
    try:
        return UNIT_REGISTRY[unit]
    except KeyError as exc:
        raise UnitError(f"unregistered unit: {unit}") from exc


def validate_unit_currency(unit: str | None, currency: str | None) -> None:
    if unit is None:
        raise UnitError("numeric values require a registered unit")
    spec = unit_spec(unit)
    if spec.currency_required and currency is None:
        raise UnitError("monetary units require an ISO currency")
    if not spec.currency_required and currency is not None:
        raise UnitError("nonmonetary units require currency=null")


def compatible_units(left: str, right: str) -> bool:
    return unit_spec(left).family == unit_spec(right).family


def normalize_value(value: int | float, unit: str) -> Decimal:
    spec = unit_spec(unit)
    parsed = Decimal(str(value))
    # Decimal multiplication obeys the ambient context even when both operands are exact.
    # Size the local context from both coefficients so large integral share counts and monetary
    # magnitudes cannot be silently rounded during a unit-only scale conversion.
    precision = len(parsed.as_tuple().digits) + len(spec.scale.as_tuple().digits) + 2
    with localcontext() as context:
        context.prec = max(context.prec, precision)
        return parsed * spec.scale


def xbrl_unit(unit_ref: str | None, *, currency: str | None) -> str | None:
    if unit_ref is None:
        return None
    normalized = unit_ref.lower()
    if currency is not None:
        return "currency_units"
    if "share" in normalized:
        return "shares"
    if normalized in {"pure", "xbrli:pure"}:
        return "ratio"
    return None


LEGACY_FACT_UNITS = {
    "units": "currency_units",
    "thousands": "currency_thousands",
    "millions": "currency_millions",
    "billions": "currency_billions",
}


def migrate_fact_v1_to_v2(payload: dict[str, object]) -> dict[str, object]:
    if payload.get("schema_version") != "1.0.0":
        raise UnitError("Fact migration accepts schema_version 1.0.0 only")
    migrated = dict(payload)
    if migrated.get("value_type") == "number":
        unit = migrated.get("unit")
        currency = migrated.get("currency")
        if not isinstance(unit, str) or unit not in LEGACY_FACT_UNITS:
            raise UnitError("legacy numeric Fact unit requires an explicit known mapping")
        if not isinstance(currency, str):
            raise UnitError("legacy numeric Fact migration requires a currency")
        migrated["unit"] = LEGACY_FACT_UNITS[unit]
    migrated["schema_version"] = "2.0.0"
    return migrated
