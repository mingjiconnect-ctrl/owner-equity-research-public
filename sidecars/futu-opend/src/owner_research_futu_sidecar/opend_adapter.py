from __future__ import annotations

import base64
import re
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date as calendar_date
from pathlib import Path
from typing import Any

from .canonical import SidecarContractError
from .frame_guard import DEFAULT_US_QUOTE_PROTOCOL_IDS, FrameGuardProxy
from .operation_registry import load_operation_registry, verify_installed_sdk
from .protobuf_parser import (
    GlobalStateResult,
    ParsedDataResult,
    parse_data_response,
    parse_global_state,
)
from .sdk_logging import FutuSdkLogBoundary

_US_CODE = re.compile(r"US\.[A-Z0-9][A-Z0-9.-]{0,31}\Z")


class OfficialFutuAdapterError(SidecarContractError):
    """Raised when the pinned quote-only SDK cannot complete exactly once."""


@dataclass(frozen=True, slots=True)
class AdapterDataCall:
    parsed: ParsedDataResult
    sdk_result_kind: str


class OfficialFutuAdapter:
    """Closed operation facade over one official OpenQuoteContext connection."""

    def __init__(self, *, guard: FrameGuardProxy, private_home: Path) -> None:
        if not isinstance(guard, FrameGuardProxy) or guard.quarantined:
            raise OfficialFutuAdapterError("adapter requires a healthy frame guard")
        if guard.allowed_quote_protocol_ids != DEFAULT_US_QUOTE_PROTOCOL_IDS:
            raise OfficialFutuAdapterError("frame guard operation scope differs from the facade")
        self._log_boundary = FutuSdkLogBoundary(private_home=private_home)
        self._log_boundary.activate_environment()
        verify_installed_sdk()
        context_type = _build_quote_only_context_class(log_boundary=self._log_boundary)
        self.guard = guard
        self._lock = threading.Lock()
        self._closed = False
        before = guard.sequence
        context = context_type(host=guard.host, port=guard.port)
        self._context = context
        try:
            result = context._init_connect_sync()
            if result != 0:
                raise OfficialFutuAdapterError("official SDK InitConnect failed")
            guard.require_single_exchange(protocol_id=1001, after_sequence=before, timeout=20)
        except Exception:
            try:
                context.close()
                guard.close()
            finally:
                self._log_boundary.assert_quiescent()
            raise

    @property
    def connect_attempts(self) -> int:
        return self._context.connect_attempts

    def global_state(self) -> GlobalStateResult:
        with self._query_lock():
            before = self.guard.sequence
            result = self._context.get_global_state()
            _require_success(result, protocol_id=1002)
            exchange = self.guard.require_single_exchange(
                protocol_id=1002,
                after_sequence=before,
                timeout=20,
            )
            return parse_global_state(exchange)

    def fetch(
        self,
        *,
        protocol_id: int,
        code: str,
        parameters: dict[str, Any],
        page_key: str | None,
    ) -> AdapterDataCall:
        _validate_fetch(protocol_id, code, parameters, page_key)
        with self._query_lock():
            before = self.guard.sequence
            result = self._invoke(
                protocol_id=protocol_id,
                code=code,
                parameters=parameters,
                page_key=page_key,
            )
            _require_success(result, protocol_id=protocol_id)
            exchange = self.guard.require_single_exchange(
                protocol_id=protocol_id,
                after_sequence=before,
                timeout=20,
            )
            return AdapterDataCall(
                parsed=parse_data_response(exchange),
                sdk_result_kind=type(result[1]).__name__,
            )

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._context.close()
        self.guard.close()
        self._log_boundary.assert_quiescent()

    def _invoke(
        self,
        *,
        protocol_id: int,
        code: str,
        parameters: dict[str, Any],
        page_key: str | None,
    ) -> tuple[Any, ...]:
        context = self._context
        if protocol_id == 3103:
            from futu.common.constant import (  # type: ignore[import-not-found]
                KL_FIELD,
                AuType,
                KLType,
                Session,
            )

            return context.request_history_kline(
                code,
                parameters["start"],
                parameters["end"],
                KLType.K_DAY,
                AuType.NONE,
                [KL_FIELD.CLOSE, KL_FIELD.TRADE_VOL],
                parameters["max_count"],
                _decode_page_key(page_key),
                parameters["extended_time"],
                Session.RTH,
            )
        if protocol_id == 3104:
            return context.get_history_kl_quota(get_detail=True)
        if protocol_id == 3202:
            from futu.common.constant import (  # type: ignore[import-not-found]
                Market,
                SecurityType,
            )

            return context.get_stock_basicinfo(Market.US, SecurityType.STOCK, [code])
        if protocol_id == 3227:
            from futu.common.constant import (  # type: ignore[import-not-found]
                Currency,
                F10Type,
            )

            return context.get_financials_statements(
                code,
                parameters["statement_type"],
                _f10_type(parameters["financial_type"], F10Type),
                Currency.USD,
                page_key,
                parameters["num"],
            )
        if protocol_id == 3228:
            from futu.common.constant import (  # type: ignore[import-not-found]
                Currency,
                F10Type,
            )

            return context.get_financials_revenue_breakdown(
                code,
                parameters["date"],
                _f10_type(parameters["financial_type"], F10Type),
                Currency.USD,
            )
        if protocol_id == 3229:
            return context.get_research_analyst_consensus(code)
        if protocol_id == 3230:
            from futu.common.constant import (  # type: ignore[import-not-found]
                ResearchRatingDimensionType,
            )

            return context.get_research_rating_summary(
                code,
                ResearchRatingDimensionType.INSTITUTION,
                parameters["uid"],
                parameters["num"],
                page_key,
            )
        if protocol_id == 3232:
            return context.get_valuation_detail(code, None, None)
        if protocol_id == 3234:
            return context.get_corporate_actions_dividends(code)
        if protocol_id == 3236:
            return context.get_corporate_actions_stock_splits(code, page_key, None)
        if protocol_id == 3243:
            return context.get_company_profile(code)
        if protocol_id == 3244:
            return context.get_company_executives(code)
        if protocol_id == 3245:
            return context.get_company_executive_background(code, parameters["leader_name"])
        if protocol_id == 3246:
            from futu.common.constant import Currency  # type: ignore[import-not-found]

            return context.get_company_operational_efficiency(
                code,
                parameters["num"],
                page_key,
                Currency.USD,
            )
        raise OfficialFutuAdapterError("protocol is not exposed by the US quote facade")

    def _query_lock(self) -> _QueryLock:
        return _QueryLock(self)


class _QueryLock:
    def __init__(self, adapter: OfficialFutuAdapter) -> None:
        self.adapter = adapter

    def __enter__(self) -> None:
        if self.adapter._closed:
            raise OfficialFutuAdapterError("official SDK adapter is closed")
        if not self.adapter._lock.acquire(blocking=False):
            raise OfficialFutuAdapterError("concurrent SDK calls are forbidden")

    def __exit__(self, *_: object) -> None:
        self.adapter._lock.release()


def _require_success(result: Any, *, protocol_id: int) -> None:
    if (
        not isinstance(result, tuple)
        or len(result) not in {2, 3}
        or type(result[0]) is not int
        or result[0] != 0
    ):
        raise OfficialFutuAdapterError(
            f"official SDK call for protocol {protocol_id} was not successful"
        )


def _validate_fetch(
    protocol_id: int,
    code: str,
    parameters: dict[str, Any],
    page_key: str | None,
) -> None:
    if type(protocol_id) is not int:
        raise OfficialFutuAdapterError("protocol identifier must be one exact integer")
    registry = load_operation_registry()
    operation = registry.operations.get(protocol_id)
    if (
        operation is None
        or protocol_id in {1002, 3235}
        or protocol_id not in DEFAULT_US_QUOTE_PROTOCOL_IDS
    ):
        raise OfficialFutuAdapterError("protocol is outside the US quote-only facade")
    if not isinstance(code, str) or _US_CODE.fullmatch(code) is None:
        raise OfficialFutuAdapterError("security code must be one bounded US vendor code")
    if not isinstance(parameters, dict) or set(parameters) != set(operation.host_parameter_names):
        raise OfficialFutuAdapterError("operation parameters differ from the pinned registry")
    if page_key is not None and (
        not isinstance(page_key, str) or not 1 <= len(page_key.encode("utf-8")) <= 4096
    ):
        raise OfficialFutuAdapterError("pagination key is invalid")
    if page_key == "-1":
        raise OfficialFutuAdapterError("terminal pagination sentinel cannot be requested")
    if page_key is not None and (
        operation.internal_pagination_parameter is None or operation.pagination_mode != "internal"
    ):
        raise OfficialFutuAdapterError("non-paginated operation received a page key")
    _validate_operation_values(protocol_id, parameters)


def _validate_operation_values(protocol_id: int, values: dict[str, Any]) -> None:
    if protocol_id == 3103 and (
        values["ktype"] != "K_DAY"
        or values["autype"] != "NONE"
        or values["fields"] != ["CLOSE", "VOLUME"]
        or type(values["max_count"]) is not int
        or values["max_count"] != 1
        or type(values["extended_time"]) is not bool
        or values["extended_time"] is not False
        or values["session"] != "RTH"
    ):
        raise OfficialFutuAdapterError("history request is not the fixed daily close shape")
    if protocol_id == 3103 and (
        type(values["start"]) is not str
        or type(values["end"]) is not str
        or values["start"] != values["end"]
        or len(values["start"]) != 10
        or not _is_canonical_date(values["start"])
    ):
        raise OfficialFutuAdapterError("history request date is invalid")
    if protocol_id == 3104 and (
        type(values["get_detail"]) is not bool or values["get_detail"] is not True
    ):
        raise OfficialFutuAdapterError("history quota request must include exact detail")
    if protocol_id == 3227 and (
        type(values["statement_type"]) is not int
        or type(values["financial_type"]) is not int
        or values["statement_type"] not in {1, 2, 3, 4}
        or values["financial_type"] != 7
        or values["currency_code"] != "USD"
        or type(values["num"]) is not int
        or not 1 <= values["num"] <= 50
    ):
        raise OfficialFutuAdapterError("financial statement parameters are unsafe")
    if protocol_id == 3228 and (
        type(values["date"]) is not int
        or values["date"] != 0
        or type(values["financial_type"]) is not int
        or values["financial_type"] != 7
        or values["currency_code"] != "USD"
    ):
        raise OfficialFutuAdapterError("revenue breakdown parameters are unsafe")
    if protocol_id == 3230 and (
        type(values["rating_dimension_type"]) is not int
        or values["rating_dimension_type"] != 1
        or values["uid"] is not None
        or type(values["num"]) is not int
        or values["num"] != 20
    ):
        raise OfficialFutuAdapterError("rating summary parameters are unsafe")
    if protocol_id == 3245 and (
        not isinstance(values["leader_name"], str)
        or not values["leader_name"].strip()
        or len(values["leader_name"].encode("utf-8")) > 512
    ):
        raise OfficialFutuAdapterError("executive leader name is invalid")
    if protocol_id == 3246 and (
        type(values["num"]) is not int or values["num"] != 50 or values["currency_code"] != "USD"
    ):
        raise OfficialFutuAdapterError("operational efficiency parameters are unsafe")


def _decode_page_key(value: str | None) -> bytes | None:
    if value is None:
        return None
    if not value.startswith("b64:"):
        raise OfficialFutuAdapterError("history pagination key is not binary-safe")
    try:
        encoded = value[4:].encode("ascii")
        decoded = base64.b64decode(encoded, altchars=b"-_", validate=True)
    except (UnicodeEncodeError, ValueError) as exc:
        raise OfficialFutuAdapterError("history pagination key is malformed") from exc
    if not decoded:
        raise OfficialFutuAdapterError("history pagination key is empty")
    if base64.urlsafe_b64encode(decoded) != encoded:
        raise OfficialFutuAdapterError("history pagination key is malformed")
    return decoded


def _is_canonical_date(value: str) -> bool:
    try:
        return calendar_date.fromisoformat(value).isoformat() == value
    except ValueError:
        return False


def _f10_type(value: int, enum_type: Any) -> str:
    if type(value) is not int or value != 7:
        raise OfficialFutuAdapterError("financial type lacks a pinned annual SDK mapping")
    return enum_type.ANNUAL


def _build_quote_only_context_class(*, log_boundary: FutuSdkLogBoundary) -> type[Any]:
    from futu.common import ft_logger  # type: ignore[import-not-found]

    log_boundary.silence(ft_logger)
    from futu.common.constant import RET_OK  # type: ignore[import-not-found]
    from futu.common.sys_config import SysConfig  # type: ignore[import-not-found]
    from futu.quote.open_quote_context import (  # type: ignore[import-not-found]
        OpenQuoteContext,
    )
    from futu.quote.quote_query import InitConnect  # type: ignore[import-not-found]

    class QuoteOnlyContext(OpenQuoteContext):
        """Pinned SDK context with reconnect and notification push disabled."""

        def __init__(self, *, host: str, port: int) -> None:
            self.connect_attempts = 0
            super().__init__(
                host=host,
                port=port,
                is_encrypt=False,
                is_async_connect=True,
            )
            self._auto_reconnect = False
            self._reconnect_interval = 0
            self._query_timeout = 20
            self._conn_alive_timeout = 15 * 60
            self._keep_alive_interval = 15 * 60

        def _wait_reconnect(self, wait_reconnect_interval: float = 6) -> None:
            del wait_reconnect_interval

        def _init_connect_sync(self) -> int:
            self.connect_attempts += 1
            if self.connect_attempts != 1:
                raise OfficialFutuAdapterError("official SDK attempted a second connection")
            return int(super()._init_connect_sync())

        def _send_init_connect_sync(self) -> tuple[int, str]:
            arguments = {
                "client_ver": int(SysConfig.get_client_ver()),
                "client_id": str(SysConfig.get_client_id()),
                "recv_notify": False,
                "is_encrypt": self.is_encrypt(),
                "push_proto_fmt": SysConfig.get_proto_fmt(),
                "ai_type": self._ai_type,
            }
            ret, message, response = self._query_sync(
                InitConnect.pack_req,
                InitConnect.unpack_rsp,
                **arguments,
            )
            if ret == RET_OK:
                self._handle_init_connect_rsp(response)
            return int(ret), str(message)

    return QuoteOnlyContext


verify_pinned_sdk: Callable[[], dict[str, Any]] = verify_installed_sdk

__all__ = (
    "AdapterDataCall",
    "OfficialFutuAdapter",
    "OfficialFutuAdapterError",
    "verify_pinned_sdk",
)
