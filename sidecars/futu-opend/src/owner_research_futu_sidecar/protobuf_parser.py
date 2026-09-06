from __future__ import annotations

import base64
import importlib
import math
import re
import struct
import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime
from datetime import date as calendar_date
from decimal import Decimal
from fractions import Fraction
from typing import Any
from zoneinfo import ZoneInfo

from google.protobuf.descriptor import FieldDescriptor
from google.protobuf.message import DecodeError, Message

from .canonical import SidecarContractError, canonical_sha256
from .frame_guard import FrameExchange

_PB2_MODULES = {
    1002: "GetGlobalState_pb2",
    3103: "Qot_RequestHistoryKL_pb2",
    3104: "Qot_RequestHistoryKLQuota_pb2",
    3202: "Qot_GetStaticInfo_pb2",
    3227: "Qot_GetFinancialsStatements_pb2",
    3228: "Qot_GetFinancialsRevenueBreakdown_pb2",
    3229: "Qot_GetResearchAnalystConsensus_pb2",
    3230: "Qot_GetResearchRatingSummary_pb2",
    3232: "Qot_GetValuationDetail_pb2",
    3234: "Qot_GetCorporateActionsDividends_pb2",
    3235: "Qot_GetCorporateActionsBuybacks_pb2",
    3236: "Qot_GetCorporateActionsStockSplits_pb2",
    3243: "Qot_GetCompanyProfile_pb2",
    3244: "Qot_GetCompanyExecutives_pb2",
    3245: "Qot_GetCompanyExecutiveBackground_pb2",
    3246: "Qot_GetCompanyOperationalEfficiency_pb2",
}
MAXIMUM_OBSERVATIONS = 10_000
_OPTIONAL_EMPTY_PROTOCOL_IDS = frozenset(
    {3229, 3230, 3232, 3244, 3245, 3246}
)
_REVENUE_BREAKDOWN_DIMENSION_TYPES = frozenset({1, 2, 4, 8})
_REVENUE_RATIO_ABSOLUTE_TOLERANCE = 0.1
_US_STOCK_SPLIT_FORBIDDEN_FIELDS = (
    "exDate",
    "exDateStr",
    "smDeciDate",
    "smDeciDateStr",
    "tempTradeBeginDate",
    "tempTradeBeginDateStr",
    "simulTradeBeginDate",
    "simulTradeBeginDateStr",
    "simulTradeEndDate",
    "simulTradeEndDateStr",
    "eventStatus",
    "newParValue",
    "tempShareCode",
    "tempShareAbbrName",
    "newTradeUnit",
    "sharesAfterEffect",
)
_US_VENDOR_CODE = re.compile(r"[A-Z0-9][A-Z0-9.-]{0,31}\Z")
_US_EXCHANGE_MICS = {4: "XNYS", 5: "XNAS"}
_QUOTA_MARKET_TIMEZONES = {
    1: "Asia/Hong_Kong",
    2: "Asia/Hong_Kong",
    11: "America/New_York",
    21: "Asia/Shanghai",
    22: "Asia/Shanghai",
    31: "Asia/Singapore",
    41: "Asia/Tokyo",
    51: "Australia/Sydney",
    61: "Asia/Kuala_Lumpur",
    71: "America/Toronto",
}


class ProtobufParserError(SidecarContractError):
    """Raised when exact OpenD protobuf evidence cannot be normalized."""


@dataclass(frozen=True, slots=True)
class GlobalStateResult:
    ret_type: int
    err_code: int
    qot_logined: bool
    trd_logined: bool
    server_version: int
    server_build_no: int
    exchange: FrameExchange


@dataclass(frozen=True, slots=True)
class ParsedDataResult:
    ret_type: int
    err_code: int
    next_key: str | None
    terminal: bool
    observations: tuple[dict[str, Any], ...]
    exchange: FrameExchange


def _response(exchange: FrameExchange) -> Message:
    module_name = _PB2_MODULES.get(exchange.protocol_id)
    if module_name is None:
        raise ProtobufParserError("protocol has no pinned protobuf response parser")
    try:
        module = importlib.import_module(f"futu.common.pb.{module_name}")
        value = module.Response()
        value.ParseFromString(exchange.response.body)
    except (ImportError, DecodeError) as exc:
        raise ProtobufParserError("OpenD response does not parse under the pinned SDK") from exc
    return value


def parse_global_state(exchange: FrameExchange) -> GlobalStateResult:
    if exchange.protocol_id != 1002:
        raise ProtobufParserError("GlobalState parser received another protocol")
    request = _parse_request(exchange)
    if (
        _list_field_names(request.c2s) != ("userID",)
        or not request.c2s.HasField("userID")
        or int(request.c2s.userID) <= 0
    ):
        raise ProtobufParserError("GlobalState request lacks one bound login user identity")
    response = _response(exchange)
    if response.retType != 0 or response.errCode != 0 or not response.HasField("s2c"):
        raise ProtobufParserError("OpenD GlobalState did not return a successful payload")
    server_version = int(response.s2c.serverVer)
    server_build_no = int(response.s2c.serverBuildNo)
    if server_version <= 0 or server_build_no <= 0:
        raise ProtobufParserError("OpenD GlobalState lacks an exact server version and build")
    return GlobalStateResult(
        ret_type=int(response.retType),
        err_code=int(response.errCode),
        qot_logined=bool(response.s2c.qotLogined),
        trd_logined=bool(response.s2c.trdLogined),
        server_version=server_version,
        server_build_no=server_build_no,
        exchange=exchange,
    )


def parse_data_response(exchange: FrameExchange) -> ParsedDataResult:
    if exchange.protocol_id in {1002, 3235}:
        raise ProtobufParserError("protocol is not an eligible US data response")
    response = _response(exchange)
    request = _bound_request(exchange)
    ret_type = int(response.retType)
    err_code = int(response.errCode)
    if ret_type != 0 or err_code != 0 or not response.HasField("s2c"):
        return ParsedDataResult(
            ret_type=ret_type,
            err_code=err_code,
            next_key=None,
            terminal=True,
            observations=(),
            exchange=exchange,
        )
    if exchange.protocol_id == 3103:
        observations = _history_observations(response.s2c, request.c2s)
    elif exchange.protocol_id == 3104:
        observations = _history_quota_observations(response.s2c)
    elif exchange.protocol_id == 3202:
        observations = _static_info_observations(response.s2c, request.c2s)
    elif exchange.protocol_id == 3227:
        observations = _financial_statement_observations(response.s2c, request.c2s)
    elif exchange.protocol_id == 3228:
        observations = _revenue_breakdown_observations(response.s2c)
    elif exchange.protocol_id == 3234:
        observations = _dividend_observations(response.s2c)
    elif exchange.protocol_id == 3236:
        observations = _stock_split_observations(response.s2c, request.c2s)
    elif exchange.protocol_id == 3229:
        observations = _consensus_observations(response.s2c)
    elif exchange.protocol_id == 3232:
        observations = _valuation_observations(response.s2c)
    elif exchange.protocol_id == 3243:
        observations = _profile_observations(response.s2c)
    else:
        observations = tuple(_flatten_message(response.s2c))
    if not observations and exchange.protocol_id in _OPTIONAL_EMPTY_PROTOCOL_IDS:
        observations = (
            _observation(
                field_id="availability",
                value_type="null",
                value=None,
                qualifiers={
                    "availability_status": "unavailable",
                    "reason_code": "official_no_data",
                },
            ),
        )
    if exchange.protocol_id == 3243 and not observations:
        raise ProtobufParserError("required company-profile response is empty")
    if len(observations) > MAXIMUM_OBSERVATIONS:
        raise ProtobufParserError("OpenD response exceeds the observation count limit")
    next_key = _next_key(exchange.protocol_id, response.s2c)
    return ParsedDataResult(
        ret_type=ret_type,
        err_code=err_code,
        next_key=next_key,
        terminal=next_key in {None, "-1"},
        observations=observations,
        exchange=exchange,
    )


def _bound_request(exchange: FrameExchange) -> Message:
    request = _parse_request(exchange)
    if exchange.protocol_id == 3104:
        c2s = request.c2s
        if (
            _list_field_names(c2s) != ("bGetDetail", "header")
            or not c2s.HasField("bGetDetail")
            or bool(c2s.bGetDetail) is not True
            or _list_field_names(c2s.header) != ("securityFirm",)
            or int(c2s.header.securityFirm) != 0
        ):
            raise ProtobufParserError("history quota request is not exact get-detail shape")
    elif exchange.protocol_id == 3103:
        c2s = request.c2s
        begin_time = str(c2s.beginTime)
        end_time = str(c2s.endTime)
        request_date = begin_time[:10]
        if (
            _list_field_names(c2s)
            != (
                "rehabType",
                "klType",
                "security",
                "beginTime",
                "endTime",
                "maxAckKLNum",
                "needKLFieldsFlag",
                "session",
                "header",
            )
            or _list_field_names(c2s.security) != ("market", "code")
            or _list_field_names(c2s.header) != ("securityFirm",)
            or int(c2s.header.securityFirm) != 0
            or int(c2s.rehabType) != 0
            or int(c2s.klType) != 2
            or int(c2s.security.market) != 11
            or _US_VENDOR_CODE.fullmatch(str(c2s.security.code)) is None
            or begin_time != f"{request_date} 00:00:00"
            or end_time != f"{request_date} 23:59:59"
            or not _is_canonical_date(request_date)
            or int(c2s.maxAckKLNum) != 1
            or int(c2s.needKLFieldsFlag) != 40
            or c2s.HasField("nextReqKey")
            or c2s.HasField("extendedTime")
            or int(c2s.session) != 1
        ):
            raise ProtobufParserError("daily-close request bytes differ from the RTH shape")
    elif exchange.protocol_id == 3202:
        c2s = request.c2s
        if (
            _list_field_names(c2s) != ("market", "secType", "securityList", "header")
            or len(c2s.securityList) != 1
            or _list_field_names(c2s.securityList[0]) != ("market", "code")
            or _list_field_names(c2s.header) != ("securityFirm",)
            or int(c2s.header.securityFirm) != 0
            or int(c2s.market) != 0
            or int(c2s.secType) != 0
            or int(c2s.securityList[0].market) != 11
            or _US_VENDOR_CODE.fullmatch(str(c2s.securityList[0].code)) is None
        ):
            raise ProtobufParserError("static-info request bytes differ from one US code")
    else:
        _validate_security_request(exchange.protocol_id, request.c2s)
    return request


def _parse_request(exchange: FrameExchange) -> Message:
    module_name = _PB2_MODULES[exchange.protocol_id]
    try:
        module = importlib.import_module(f"futu.common.pb.{module_name}")
        request = module.Request()
        request.ParseFromString(exchange.request.body)
    except (ImportError, DecodeError) as exc:
        raise ProtobufParserError("OpenD request does not parse under the pinned SDK") from exc
    if not request.IsInitialized() or not request.HasField("c2s"):
        raise ProtobufParserError("OpenD request lacks its required C2S payload")
    canonical_request = request.__class__()
    canonical_request.CopyFrom(request)
    canonical_request.DiscardUnknownFields()
    if canonical_request.SerializeToString(deterministic=True) != exchange.request.body:
        raise ProtobufParserError("OpenD request is not one canonical known protobuf message")
    return request


def _list_field_names(message: Message) -> tuple[str, ...]:
    return tuple(field.name for field, _ in message.ListFields())


def _validate_security_request(protocol_id: int, c2s: Message) -> None:
    security = c2s.security
    if int(security.market) != 11 or _US_VENDOR_CODE.fullmatch(str(security.code)) is None:
        raise ProtobufParserError("Futu request is not bound to one US security")
    if protocol_id == 3227:
        valid = (
            int(c2s.statementType) in {1, 2, 3, 4}
            and c2s.HasField("financialType")
            and int(c2s.financialType) == 7
            and str(c2s.currencyCode) == "USD"
            and c2s.HasField("num")
            and 1 <= int(c2s.num) <= 50
            and _valid_optional_page_key(c2s, "nextKey")
        )
    elif protocol_id == 3228:
        valid = (
            c2s.HasField("date")
            and int(c2s.date) == 0
            and int(c2s.financialType) == 7
            and str(c2s.currencyCode) == "USD"
        )
    elif protocol_id == 3229:
        valid = True
    elif protocol_id == 3230:
        valid = (
            int(c2s.ratingDimensionType) == 1
            and not c2s.HasField("uid")
            and int(c2s.num) == 20
            and _valid_optional_page_key(c2s, "nextKey")
        )
    elif protocol_id == 3232:
        valid = not c2s.HasField("valuationType") and not c2s.HasField("intervalType")
    elif protocol_id == 3234:
        valid = True
    elif protocol_id == 3236:
        valid = not c2s.HasField("num") and _valid_optional_page_key(c2s, "nextKey")
    elif protocol_id in {3243, 3244}:
        valid = True
    elif protocol_id == 3245:
        valid = (
            bool(str(c2s.leaderName).strip()) and len(str(c2s.leaderName).encode("utf-8")) <= 512
        )
    elif protocol_id == 3246:
        valid = (
            int(c2s.num) == 50
            and str(c2s.currencyCode) == "USD"
            and not c2s.HasField("financialType")
            and _valid_optional_page_key(c2s, "nextKey")
        )
    else:
        valid = False
    if not valid:
        raise ProtobufParserError("Futu request bytes differ from the closed protocol shape")


def _valid_optional_page_key(message: Message, name: str) -> bool:
    if not message.HasField(name):
        return True
    value = str(getattr(message, name))
    return bool(value) and value != "-1" and len(value.encode("utf-8")) <= 4096


def _history_observations(s2c: Message, request: Message) -> tuple[dict[str, Any], ...]:
    if len(s2c.klList) != 1:
        raise ProtobufParserError("daily K-line response must contain exactly one row")
    row = s2c.klList[0]
    trading_date = str(row.time)[:10]
    if (
        int(s2c.security.market) != int(request.security.market)
        or str(s2c.security.code) != str(request.security.code)
        or s2c.HasField("nextReqKey")
        or trading_date != str(request.beginTime)[:10]
        or not row.HasField("isBlank")
        or bool(row.isBlank)
        or not row.HasField("closePrice")
        or float(row.closePrice) <= 0
        or not row.HasField("volume")
        or int(row.volume) <= 0
    ):
        raise ProtobufParserError("daily K-line response does not replay the exact request")
    return (
        _number_observation(
            field_id="close",
            value=float(row.closePrice),
            period_end=trading_date,
            unit="currency_per_share",
            currency="USD",
            qualifiers={
                "autype": "NONE",
                "ktype": "K_DAY",
                "price_basis": "vendor_unadjusted_daily_close_rth_requested",
                "rth_semantics_attested": False,
                "session": "RTH",
            },
        ),
        _integer_observation(
            field_id="volume",
            value=int(row.volume),
            period_end=trading_date,
            unit="shares",
            qualifiers={
                "autype": "NONE",
                "ktype": "K_DAY",
                "price_basis": "vendor_unadjusted_daily_close_rth_requested",
                "rth_semantics_attested": False,
                "session": "RTH",
            },
        ),
    )


def _history_quota_observations(s2c: Message) -> tuple[dict[str, Any], ...]:
    used_quota = int(s2c.usedQuota)
    remaining_quota = int(s2c.remainQuota)
    if used_quota < 0 or remaining_quota < 0 or len(s2c.detailList) != used_quota:
        raise ProtobufParserError("history quota response contains impossible counts")
    aggregate_qualifiers = {
        "get_detail": True,
        "quota_kind": "historical_candlestick_distinct_security_7d",
        "quota_window_days": 7,
    }
    observations: list[dict[str, Any]] = [
        _integer_observation(
            field_id="history_quota_used",
            value=used_quota,
            unit="distinct_securities",
            qualifiers=aggregate_qualifiers,
        ),
        _integer_observation(
            field_id="history_quota_remaining",
            value=remaining_quota,
            unit="distinct_securities",
            qualifiers=aggregate_qualifiers,
        ),
    ]
    seen: set[tuple[int, str]] = set()
    for detail in s2c.detailList:
        raw_market = int(detail.security.market)
        raw_code = str(detail.security.code)
        if raw_market not in _QUOTA_MARKET_TIMEZONES or _US_VENDOR_CODE.fullmatch(raw_code) is None:
            raise ProtobufParserError("history quota detail has an invalid security identity")
        identity = (raw_market, raw_code)
        if identity in seen:
            raise ProtobufParserError("history quota detail repeats a security identity")
        seen.add(identity)
        vendor_code = (
            f"US.{raw_code}"
            if raw_market == 11 and _US_VENDOR_CODE.fullmatch(raw_code) is not None
            else None
        )
        source_time = str(detail.requestTime)
        source_timestamp = (
            int(detail.requestTimeStamp) if detail.HasField("requestTimeStamp") else None
        )
        last_request_at = _history_quota_time(
            raw_market=raw_market,
            source_time=source_time,
            source_timestamp=source_timestamp,
        )
        observations.append(
            _text_observation(
                field_id="history_quota_detail",
                value=vendor_code or f"{raw_market}:{raw_code}",
                qualifiers={
                    "last_request_at": last_request_at,
                    "raw_market_code": raw_market,
                    "raw_security_code": raw_code,
                    "source_request_time": source_time,
                    "source_request_timestamp": source_timestamp,
                    "vendor_security_code": vendor_code,
                },
            )
        )
    return tuple(observations)


def _history_quota_time(
    *, raw_market: int, source_time: str, source_timestamp: int | None
) -> str:
    try:
        parsed = datetime.strptime(source_time, "%Y-%m-%d %H:%M:%S")
    except ValueError as exc:
        raise ProtobufParserError("history quota request time is not canonical") from exc
    if parsed.strftime("%Y-%m-%d %H:%M:%S") != source_time:
        raise ProtobufParserError("history quota request time is not canonical")
    timezone_name = _QUOTA_MARKET_TIMEZONES.get(raw_market)
    if timezone_name is None:
        raise ProtobufParserError("history quota detail market has no pinned timezone")
    market_timezone = ZoneInfo(timezone_name)
    if source_timestamp is not None:
        if source_timestamp <= 0:
            raise ProtobufParserError("history quota request timestamp is invalid")
        try:
            observed = datetime.fromtimestamp(source_timestamp, tz=UTC)
        except (OSError, OverflowError, ValueError) as exc:
            raise ProtobufParserError("history quota request timestamp is invalid") from exc
        if observed.astimezone(market_timezone).strftime("%Y-%m-%d %H:%M:%S") != source_time:
            raise ProtobufParserError("history quota request time and timestamp disagree")
    else:
        candidates = {
            parsed.replace(tzinfo=market_timezone, fold=fold).astimezone(UTC)
            for fold in (0, 1)
            if parsed.replace(tzinfo=market_timezone, fold=fold)
            .astimezone(UTC)
            .astimezone(market_timezone)
            .replace(tzinfo=None)
            == parsed
        }
        if len(candidates) != 1:
            raise ProtobufParserError("history quota request time is ambiguous or nonexistent")
        (observed,) = candidates
    return observed.isoformat(timespec="seconds").replace("+00:00", "Z")


def _static_info_observations(s2c: Message, request: Message) -> tuple[dict[str, Any], ...]:
    if len(s2c.staticInfoList) != 1 or not s2c.staticInfoList[0].HasField("basic"):
        raise ProtobufParserError("static info must contain exactly one basic row")
    item = s2c.staticInfoList[0]
    basic = item.basic
    requested = request.securityList[0]
    listing_date = str(basic.listTime)
    if (
        item.HasField("warrantExData")
        or item.HasField("optionExData")
        or item.HasField("futureExData")
        or int(basic.security.market) != int(requested.market)
        or str(basic.security.code) != str(requested.code)
        or int(basic.secType) != 3
        or not basic.HasField("delisting")
        or bool(basic.delisting)
        or not basic.HasField("exchType")
        or int(basic.exchType) not in _US_EXCHANGE_MICS
        or not _is_canonical_date(listing_date)
        or int(basic.id) <= 0
        or int(basic.lotSize) <= 0
        or not str(basic.name).strip()
    ):
        raise ProtobufParserError("static info is not one active XNYS/XNAS common stock")
    raw_market = int(basic.security.market)
    raw_code = str(basic.security.code)
    raw_exchange = int(basic.exchType)
    qualifiers = {
        "raw_exchange_type": raw_exchange,
        "raw_market_code": raw_market,
        "raw_security_type": int(basic.secType),
    }
    return (
        _text_observation(
            field_id="vendor_security_market",
            value="US",
            qualifiers=qualifiers,
        ),
        _text_observation(
            field_id="vendor_security_code",
            value=f"US.{raw_code}",
            qualifiers=qualifiers,
        ),
        _text_observation(
            field_id="security_type",
            value="COMMON_EQUITY",
            qualifiers=qualifiers,
        ),
        _text_observation(
            field_id="listing_mic",
            value=_US_EXCHANGE_MICS[raw_exchange],
            qualifiers=qualifiers,
        ),
        _text_observation(
            field_id="listing_date",
            value=listing_date,
            qualifiers=qualifiers,
        ),
        _observation(
            field_id="delisting",
            value_type="boolean",
            value=False,
            qualifiers=qualifiers,
        ),
        _integer_observation(
            field_id="vendor_security_id",
            value=int(basic.id),
            qualifiers=qualifiers,
        ),
        _integer_observation(
            field_id="lot_size",
            value=int(basic.lotSize),
            unit="shares",
            qualifiers=qualifiers,
        ),
        _text_observation(
            field_id="security_name",
            value=str(basic.name),
            qualifiers=qualifiers,
        ),
    )


def _is_canonical_date(value: str) -> bool:
    try:
        return calendar_date.fromisoformat(value).isoformat() == value
    except ValueError:
        return False


def _financial_statement_observations(s2c: Message, request: Message) -> tuple[dict[str, Any], ...]:
    statement_type, period_kind = {
        1: ("income", "flow"),
        2: ("balance_sheet", "stock"),
        3: ("cash_flow", "flow"),
        4: ("main_index", "mixed"),
    }[int(request.statementType)]
    requested_financial_type = int(request.financialType)
    descriptors: dict[int, str] = {}
    values: list[dict[str, Any]] = []
    for item in s2c.structureList:
        field_id = int(item.fieldId)
        display_name = str(item.displayName).strip()
        normalized_name = " ".join(
            unicodedata.normalize("NFKC", display_name).casefold().split()
        )
        if (
            not item.HasField("fieldId")
            or field_id <= 0
            or field_id in descriptors
            or not item.HasField("displayName")
            or not display_name
            or len(display_name.encode("utf-8")) > 512
            or not normalized_name
        ):
            raise ProtobufParserError("financial structureList entry is invalid")
        descriptors[field_id] = normalized_name
        values.append(
            _text_observation(
                field_id=f"financial_structure:{field_id}",
                value=display_name,
                qualifiers={
                    "financial_field_id": str(field_id),
                    "futu_api_version": "10.10.7008",
                    "normalized_display_name": normalized_name,
                    "statement_type": statement_type,
                },
            )
        )
    if not descriptors or not s2c.reportList:
        raise ProtobufParserError("financial response lacks structureList or reports")
    reports: list[tuple[Message, str, int, list[Message]]] = []
    period_ends: set[str] = set()
    fiscal_years: set[int] = set()
    used_field_ids: set[int] = set()
    for report in s2c.reportList:
        period_end = str(report.dateTimeStr)
        fiscal_year = int(report.fiscalYear)
        vendor_period = str(report.periodText)
        accounting_standard = str(report.accountingStandards)
        auditor_report = str(report.auditorReport)
        if (
            not report.HasField("dateTimeStr")
            or not _is_canonical_date(period_end)
            or period_end in period_ends
            or not report.HasField("fiscalYear")
            or fiscal_year <= 0
            or fiscal_year in fiscal_years
            or not report.HasField("financialType")
            or int(report.financialType) != 7
            or int(report.financialType) != requested_financial_type
            or not report.HasField("periodText")
            or not vendor_period
            or vendor_period != vendor_period.strip()
            or len(vendor_period.encode("utf-8")) > 256
            or not report.HasField("currencyCode")
            or str(report.currencyCode) != "USD"
            or not report.HasField("accountingStandards")
            or not accounting_standard
            or accounting_standard != accounting_standard.strip()
            or len(accounting_standard.encode("utf-8")) > 128
            or len(auditor_report.encode("utf-8")) > 4096
            or not report.itemList
        ):
            raise ProtobufParserError("financial report lacks its typed period or currency")
        period_ends.add(period_end)
        fiscal_years.add(fiscal_year)
        report_items: list[Message] = []
        field_ids: set[int] = set()
        for item in report.itemList:
            field_id = int(item.fieldId)
            if (
                not item.HasField("fieldId")
                or field_id <= 0
                or field_id in field_ids
                or field_id not in descriptors
                or not item.HasField("data")
            ):
                raise ProtobufParserError("financial report item lacks a bound numeric value")
            field_ids.add(field_id)
            used_field_ids.add(field_id)
            report_items.append(item)
        reports.append((report, period_end, fiscal_year, report_items))
    if used_field_ids != set(descriptors):
        raise ProtobufParserError("financial structureList and report fields differ")

    ordered_periods = sorted(
        ((period_end, fiscal_year) for _, period_end, fiscal_year, _ in reports),
        key=lambda item: calendar_date.fromisoformat(item[0]),
    )
    starts: dict[str, str | None] = {period_end: None for period_end, _ in ordered_periods}
    if period_kind == "flow":
        for previous, current in zip(ordered_periods, ordered_periods[1:], strict=False):
            previous_end = calendar_date.fromisoformat(previous[0])
            current_end = calendar_date.fromisoformat(current[0])
            if current[1] == previous[1] + 1 and 350 <= (current_end - previous_end).days <= 380:
                starts[current[0]] = calendar_date.fromordinal(
                    previous_end.toordinal() + 1
                ).isoformat()

    for report, period_end, fiscal_year, report_items in reports:
        vendor_accounting_standard = str(report.accountingStandards)
        normalized_accounting_standard = re.sub(
            r"[^A-Z0-9]+", "_", vendor_accounting_standard.upper()
        ).strip("_")
        qualifiers = {
            "accounting_standard": (
                "US_GAAP"
                if normalized_accounting_standard == "US_GAAP"
                else vendor_accounting_standard
            ),
            "auditor_report": str(report.auditorReport),
            "financial_type": int(report.financialType),
            "fiscal_year": fiscal_year,
            "period_kind": period_kind,
            "statement_type": statement_type,
            "vendor_period": str(report.periodText),
        }
        currency = str(report.currencyCode)
        for item in report_items:
            values.append(
                _number_observation(
                    field_id=str(item.fieldId),
                    value=float(item.data),
                    period_start=starts[period_end],
                    period_end=period_end,
                    unit="currency_units",
                    currency=currency,
                    qualifiers=qualifiers,
                )
            )
    return tuple(values)


def _revenue_breakdown_observations(s2c: Message) -> tuple[dict[str, Any], ...]:
    if not s2c.breakdownList:
        return (
            _observation(
                field_id="revenue_breakdown_segment_set",
                value_type="null",
                value=None,
                qualifiers={
                    "reason_code": "official_no_data",
                    "segment_set_status": "empty",
                },
            ),
        )
    vendor_period = str(s2c.period).strip() if s2c.HasField("period") else ""
    currency = str(s2c.currencyCode).strip() if s2c.HasField("currencyCode") else ""
    if (
        re.fullmatch(r"[1-9][0-9]{3}/FY", vendor_period) is None
        or currency != "USD"
        or bool(s2c.screenDateList)
    ):
        raise ProtobufParserError("revenue breakdown lacks a typed period or USD currency")
    values: list[dict[str, Any]] = []
    identities: set[str] = set()
    dimension_types: set[int] = set()
    for group in s2c.breakdownList:
        dimension_type = int(group.type)
        if (
            not group.HasField("type")
            or dimension_type not in _REVENUE_BREAKDOWN_DIMENSION_TYPES
            or dimension_type in dimension_types
            or not group.itemList
        ):
            raise ProtobufParserError("revenue breakdown dimension type is invalid")
        dimension_types.add(dimension_type)
        rows: list[tuple[str, str, float, float]] = []
        normalized_names: set[str] = set()
        for item in group.itemList:
            segment_name = str(item.name).strip() if item.HasField("name") else ""
            normalized_segment_name = " ".join(
                unicodedata.normalize("NFKC", segment_name).casefold().split()
            )
            if (
                not segment_name
                or len(segment_name.encode("utf-8")) > 512
                or not normalized_segment_name
                or normalized_segment_name in normalized_names
                or not item.HasField("mainOperIncome")
                or not item.HasField("ratio")
            ):
                raise ProtobufParserError("revenue breakdown segment is incomplete")
            income = float(item.mainOperIncome)
            ratio = float(item.ratio)
            if (
                not math.isfinite(income)
                or income < 0
                or not math.isfinite(ratio)
                or ratio < 0
                or ratio > 100
            ):
                raise ProtobufParserError("revenue breakdown values are outside the typed range")
            normalized_names.add(normalized_segment_name)
            rows.append((segment_name, normalized_segment_name, income, ratio))
        total_income = math.fsum(row[2] for row in rows)
        total_ratio = math.fsum(row[3] for row in rows)
        if total_income <= 0 or not math.isclose(
            total_ratio,
            100.0,
            rel_tol=0.0,
            abs_tol=_REVENUE_RATIO_ABSOLUTE_TOLERANCE,
        ):
            raise ProtobufParserError("revenue breakdown group does not reconcile to its total")
        for segment_name, normalized_segment_name, income, ratio in rows:
            expected_ratio = income / total_income * 100.0
            if not math.isclose(
                ratio,
                expected_ratio,
                rel_tol=0.0,
                abs_tol=_REVENUE_RATIO_ABSOLUTE_TOLERANCE,
            ):
                raise ProtobufParserError(
                    "revenue breakdown ratio does not reconcile to operating income"
                )
            segment_identity = canonical_sha256(
                {
                    "dimension_type": dimension_type,
                    "normalized_segment_name": normalized_segment_name,
                    "vendor_period": vendor_period,
                    "currency": currency,
                }
            )
            if segment_identity in identities:
                raise ProtobufParserError("revenue breakdown segment identity is duplicated")
            identities.add(segment_identity)
            qualifiers = {
                "dimension_type": dimension_type,
                "normalized_segment_name": normalized_segment_name,
                "segment_identity": segment_identity,
                "segment_name": segment_name,
                "vendor_period": vendor_period,
            }
            values.extend(
                (
                    _number_observation(
                        field_id="revenue_breakdown_main_operating_income",
                        value=income,
                        unit="currency_units",
                        currency=currency,
                        qualifiers=qualifiers,
                    ),
                    _number_observation(
                        field_id="revenue_breakdown_ratio",
                        value=ratio,
                        unit="percent",
                        qualifiers={**qualifiers, "ratio_basis": "main_operating_income"},
                    ),
                )
            )
    return tuple(values)


def _vendor_calendar_date(value: str, label: str) -> str:
    normalized = value.replace("/", "-")
    if not _is_canonical_date(normalized):
        raise ProtobufParserError(f"dividend {label} is not a canonical calendar date")
    return normalized


def _optional_vendor_calendar_date(message: Message, name: str) -> str | None:
    if not message.HasField(name):
        return None
    raw = str(getattr(message, name)).strip()
    if not raw:
        raise ProtobufParserError(f"dividend {name} is explicitly empty")
    return _vendor_calendar_date(raw, name)


def _dividend_observations(s2c: Message) -> tuple[dict[str, Any], ...]:
    if not s2c.dividendList:
        return (
            _observation(
                field_id="dividend_event_set",
                value_type="null",
                value=None,
                qualifiers={
                    "event_set_status": "empty",
                    "reason_code": "official_no_data",
                },
            ),
        )
    values: list[dict[str, Any]] = []
    identities: set[str] = set()
    for item in s2c.dividendList:
        publication = _optional_vendor_calendar_date(item, "pubDate")
        statement = str(item.statement).strip() if item.HasField("statement") else ""
        if publication is None or not statement or len(statement.encode("utf-8")) > 2048:
            raise ProtobufParserError("dividend event lacks publication date or statement")
        record_date = _optional_vendor_calendar_date(item, "recordDate")
        ex_date = _optional_vendor_calendar_date(item, "exDate")
        payable_date = _optional_vendor_calendar_date(item, "dividendPayableDate")
        process = str(item.process).strip() if item.HasField("process") else None
        fiscal_year = str(item.fiscalYear).strip() if item.HasField("fiscalYear") else None
        if process or fiscal_year:
            raise ProtobufParserError(
                "US common-stock dividend contains a market- or fund-specific field"
            )
        identity_payload = {
            "publication_date": publication,
            "statement": statement,
            "record_date": record_date,
            "ex_date": ex_date,
            "payable_date": payable_date,
            "process": process,
            "fiscal_year": fiscal_year,
        }
        event_identity = canonical_sha256(identity_payload)
        if event_identity in identities:
            raise ProtobufParserError("dividend event identity is duplicated")
        identities.add(event_identity)
        values.append(
            _text_observation(
                field_id="dividend_event",
                value=statement,
                period_end=ex_date or publication,
                qualifiers={
                    "event_identity": event_identity,
                    "ex_date": ex_date,
                    "fiscal_year": fiscal_year,
                    "payable_date": payable_date,
                    "process": process,
                    "publication_date": publication,
                    "record_date": record_date,
                },
            )
        )
    return tuple(values)


def _stock_split_observations(
    s2c: Message,
    request: Message,
) -> tuple[dict[str, Any], ...]:
    first_page = not request.HasField("nextKey")
    values: list[dict[str, Any]] = []
    if first_page:
        values.append(
            _observation(
                field_id="current_common_shares",
                value_type="null",
                value=None,
                qualifiers={
                    "reason_code": "us_3236_shares_after_effect_not_supported",
                    "verification_status": "vendor_not_supported",
                },
            )
        )
    identities: set[tuple[str, str | None, str, str, str]] = set()
    for item in s2c.splitItemList:
        announcement = str(item.dirDeciPubDateStr)
        effective = None
        reform_type = str(item.reformType)
        rate_raw = str(item.rate)
        if (
            not item.HasField("dirDeciPubDateStr")
            or not _is_canonical_date(announcement)
            or not item.HasField("reformType")
            or not reform_type
            or reform_type != reform_type.strip()
            or len(reform_type.encode("utf-8")) > 256
            or not item.HasField("rate")
        ):
            raise ProtobufParserError("stock-split event lacks typed dates or reform data")
        if any(item.HasField(name) for name in _US_STOCK_SPLIT_FORBIDDEN_FIELDS):
            raise ProtobufParserError("US stock-split response contains a Hong Kong-only field")
        if item.HasField("dirDeciPubDate"):
            try:
                timestamp_date = datetime.fromtimestamp(
                    int(item.dirDeciPubDate),
                    tz=ZoneInfo("America/New_York"),
                ).date().isoformat()
            except (OSError, OverflowError, ValueError) as error:
                raise ProtobufParserError(
                    "stock-split announcement timestamp is outside the supported range"
                ) from error
            if timestamp_date != announcement:
                raise ProtobufParserError(
                    "stock-split announcement timestamp and calendar date differ"
                )
        numerator, denominator = _split_rate_ratio(rate_raw)
        if numerator == denominator:
            raise ProtobufParserError("stock-split event cannot carry a one-for-one ratio")
        event_type = (
            "stock_split_completed"
            if int(numerator) > int(denominator)
            else "reverse_stock_split_completed"
        )
        identity = (announcement, effective, reform_type, numerator, denominator)
        if identity in identities:
            raise ProtobufParserError("stock-split event is duplicated")
        identities.add(identity)
        values.append(
            _text_observation(
                field_id="stock_split_event",
                value=f"{numerator}/{denominator}",
                period_end=announcement,
                unit="split_ratio",
                qualifiers={
                    "announcement_date": announcement,
                    "current_shares_status": "vendor_not_supported",
                    "effective_date": effective,
                    "event_type": event_type,
                    "rate_denominator": denominator,
                    "rate_numerator": numerator,
                    "rate_raw": rate_raw,
                    "reform_type": reform_type,
                },
            )
        )
    terminal = not s2c.HasField("nextKey") or str(s2c.nextKey) in {"", "-1"}
    if not identities and not first_page:
        raise ProtobufParserError("stock-split continuation page is empty")
    if first_page and terminal and len(values) == 1:
        values.append(
            _observation(
                field_id="stock_split_event_set",
                value_type="null",
                value=None,
                qualifiers={
                    "event_set_status": "empty",
                    "reason_code": "official_no_data",
                },
            )
        )
    return tuple(values)


def _split_rate_ratio(value: str) -> tuple[str, str]:
    if (
        not isinstance(value, str)
        or value != value.strip()
        or len(value.encode("utf-8")) > 128
    ):
        raise ProtobufParserError("stock-split raw rate is invalid")
    matched = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)->([0-9]+(?:\.[0-9]+)?)", value)
    if matched is None:
        raise ProtobufParserError("stock-split rate is not an exact before-to-after ratio")
    before, after = (Decimal(part) for part in matched.groups())
    if before <= 0 or after <= 0:
        raise ProtobufParserError("stock-split ratio members must be positive")
    ratio = Fraction(after) / Fraction(before)
    return str(ratio.numerator), str(ratio.denominator)


def _consensus_observations(s2c: Message) -> tuple[dict[str, Any], ...]:
    required = ("average", "highest", "lowest", "rating")
    present = tuple(s2c.HasField(name) for name in required)
    if not any(present):
        return ()
    if not all(present):
        raise ProtobufParserError("analyst consensus is only partially populated")
    average = float(s2c.average)
    highest = float(s2c.highest)
    lowest = float(s2c.lowest)
    rating = int(s2c.rating)
    if not (highest >= average >= lowest > 0) or rating not in {1, 3, 4}:
        raise ProtobufParserError("analyst consensus values are outside the US shape")
    return (
        _number_observation(
            field_id="average_target_price",
            value=average,
            unit="currency_per_share",
            currency="USD",
        ),
        _number_observation(
            field_id="highest_target_price",
            value=highest,
            unit="currency_per_share",
            currency="USD",
        ),
        _number_observation(
            field_id="lowest_target_price",
            value=lowest,
            unit="currency_per_share",
            currency="USD",
        ),
        _integer_observation(field_id="rating", value=rating),
    )


def _valuation_observations(s2c: Message) -> tuple[dict[str, Any], ...]:
    if not s2c.HasField("valuationType") and not s2c.HasField("trend"):
        return ()
    if (
        not s2c.HasField("valuationType")
        or int(s2c.valuationType) not in {1, 2, 3}
        or not s2c.HasField("trend")
        or not s2c.trend.HasField("currentValue")
        or float(s2c.trend.currentValue) <= 0
    ):
        raise ProtobufParserError("valuation detail lacks one positive current multiple")
    names = {1: "pe_ttm", 2: "pb", 3: "ps_ttm"}
    field_id = names.get(int(s2c.valuationType), f"valuation_{int(s2c.valuationType)}")
    return (
        _number_observation(
            field_id=field_id,
            value=float(s2c.trend.currentValue),
            unit="multiple",
            qualifiers={"valuation_type": int(s2c.valuationType)},
        ),
    )


def _profile_observations(s2c: Message) -> tuple[dict[str, Any], ...]:
    values: list[dict[str, Any]] = []
    for index, item in enumerate(s2c.itemList):
        if (
            not item.HasField("name")
            or not str(item.name).strip()
            or not item.HasField("value")
            or not str(item.value).strip()
            or not item.HasField("fieldType")
        ):
            raise ProtobufParserError("company profile item is partially populated")
        field_id = str(item.name).strip() or f"profile_item_{index}"
        values.append(
            _text_observation(
                field_id=field_id,
                value=str(item.value),
                qualifiers={"field_type": int(item.fieldType)},
            )
        )
    return tuple(values)


def _flatten_message(
    message: Message,
    *,
    prefix: str = "",
    inherited: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    values: list[dict[str, Any]] = []
    context = dict(inherited or {})
    period_end = _period_end(message)
    if period_end is not None:
        context["vendor_period"] = period_end
    for field, field_value in message.ListFields():
        name = f"{prefix}.{field.name}" if prefix else field.name
        if field.type == FieldDescriptor.TYPE_MESSAGE:
            children = field_value if field.is_repeated else (field_value,)
            for index, child in enumerate(children):
                child_prefix = f"{name}[{index}]" if field.is_repeated else name
                values.extend(_flatten_message(child, prefix=child_prefix, inherited=context))
            continue
        scalars = field_value if field.is_repeated else (field_value,)
        for index, scalar in enumerate(scalars):
            scalar_name = f"{name}[{index}]" if field.is_repeated else name
            if field.type in {FieldDescriptor.TYPE_DOUBLE, FieldDescriptor.TYPE_FLOAT}:
                values.append(
                    _number_observation(
                        field_id=scalar_name,
                        value=float(scalar),
                        period_end=period_end,
                        qualifiers=context,
                    )
                )
            elif field.type == FieldDescriptor.TYPE_BOOL:
                values.append(
                    _observation(
                        field_id=scalar_name,
                        value_type="boolean",
                        value=bool(scalar),
                        period_end=period_end,
                        qualifiers=context,
                    )
                )
            elif field.type in {
                FieldDescriptor.TYPE_INT32,
                FieldDescriptor.TYPE_INT64,
                FieldDescriptor.TYPE_UINT32,
                FieldDescriptor.TYPE_UINT64,
                FieldDescriptor.TYPE_SINT32,
                FieldDescriptor.TYPE_SINT64,
                FieldDescriptor.TYPE_FIXED32,
                FieldDescriptor.TYPE_FIXED64,
                FieldDescriptor.TYPE_SFIXED32,
                FieldDescriptor.TYPE_SFIXED64,
                FieldDescriptor.TYPE_ENUM,
            }:
                values.append(
                    _integer_observation(
                        field_id=scalar_name,
                        value=int(scalar),
                        period_end=period_end,
                        qualifiers=context,
                    )
                )
            elif field.type == FieldDescriptor.TYPE_BYTES:
                values.append(
                    _text_observation(
                        field_id=scalar_name,
                        value="b64:" + base64.urlsafe_b64encode(bytes(scalar)).decode("ascii"),
                        period_end=period_end,
                        qualifiers=context,
                    )
                )
            else:
                values.append(
                    _text_observation(
                        field_id=scalar_name,
                        value=str(scalar),
                        period_end=period_end,
                        qualifiers=context,
                    )
                )
    return values


def _next_key(protocol_id: int, s2c: Message) -> str | None:
    if protocol_id == 3103:
        value = bytes(s2c.nextReqKey)
        return None if not value else "b64:" + base64.urlsafe_b64encode(value).decode("ascii")
    for name in ("nextKey", "next_key"):
        descriptor = s2c.DESCRIPTOR.fields_by_name.get(name)
        if descriptor is not None:
            value = str(getattr(s2c, name))
            return value or None
    return None


def _period_end(message: Message) -> str | None:
    for name in ("dateTimeStr", "reportDateStr", "timeStr", "time", "date"):
        descriptor = message.DESCRIPTOR.fields_by_name.get(name)
        if descriptor is not None:
            value = str(getattr(message, name))
            if value:
                return value[:10]
    return None


def _number_observation(
    *,
    field_id: str,
    value: float,
    period_start: str | None = None,
    period_end: str | None = None,
    unit: str | None = None,
    currency: str | None = None,
    qualifiers: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not math.isfinite(value):
        raise ProtobufParserError("OpenD returned a non-finite binary64 value")
    binary = struct.pack(">d", value).hex()
    return _observation(
        field_id=field_id,
        value_type="number",
        value=str(value),
        period_start=period_start,
        period_end=period_end,
        unit=unit,
        currency=currency,
        qualifiers=qualifiers,
        binary64_hex=binary,
        exact_binary64_decimal=str(Decimal.from_float(value)),
    )


def _integer_observation(
    *,
    field_id: str,
    value: int,
    period_end: str | None = None,
    unit: str | None = None,
    qualifiers: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return _observation(
        field_id=field_id,
        value_type="number",
        value=str(value),
        period_end=period_end,
        unit=unit,
        qualifiers=qualifiers,
    )


def _text_observation(
    *,
    field_id: str,
    value: str,
    period_end: str | None = None,
    unit: str | None = None,
    qualifiers: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return _observation(
        field_id=field_id,
        value_type="text",
        value=value,
        period_end=period_end,
        unit=unit,
        qualifiers=qualifiers,
    )


def _observation(
    *,
    field_id: str,
    value_type: str,
    value: str | bool | None,
    period_start: str | None = None,
    period_end: str | None = None,
    unit: str | None = None,
    currency: str | None = None,
    qualifiers: dict[str, Any] | None = None,
    binary64_hex: str | None = None,
    exact_binary64_decimal: str | None = None,
) -> dict[str, Any]:
    return {
        "field_id": field_id,
        "period": {"start": period_start, "end": period_end},
        "qualifiers": dict(qualifiers or {}),
        "value_type": value_type,
        "value": value,
        "unit": unit,
        "currency": currency,
        "binary64_hex": binary64_hex,
        "exact_binary64_decimal": exact_binary64_decimal,
    }


__all__ = (
    "GlobalStateResult",
    "ParsedDataResult",
    "ProtobufParserError",
    "parse_data_response",
    "parse_global_state",
)
