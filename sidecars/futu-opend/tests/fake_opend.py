from __future__ import annotations

import socket
import threading
from dataclasses import dataclass, field

from owner_research_futu_sidecar.frame_guard import (
    FutuFrame,
    pack_futu_frame,
    receive_futu_frame,
)


@dataclass(slots=True)
class FakeOpenD:
    push_notify_before_profile: bool = True
    trade_on_global_state_call: int | None = None
    trade_logined: bool = False
    quote_lost_on_global_state_call: int | None = None
    history_empty_then_next: bool = False
    server_version: int = 101007008
    server_build_no: int = 1
    global_state_server_identity_overrides: dict[int, tuple[int, int]] = field(
        default_factory=dict
    )
    protocols: list[int] = field(default_factory=list)
    init_recv_notify: bool | None = None
    connection_count: int = 0
    global_state_calls: int = 0
    global_state_user_ids: list[int] = field(default_factory=list)
    request_bodies: dict[int, list[bytes]] = field(default_factory=dict)
    history_request_shapes: list[dict[str, object]] = field(default_factory=list)
    quota_request_shapes: list[dict[str, object]] = field(default_factory=list)
    static_info_request_shapes: list[dict[str, object]] = field(default_factory=list)
    error: BaseException | None = None
    _listener: socket.socket = field(init=False, repr=False)
    _stop: threading.Event = field(init=False, repr=False)
    _thread: threading.Thread = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(2)
        self._listener.settimeout(0.25)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    @property
    def port(self) -> int:
        return int(self._listener.getsockname()[1])

    def start(self) -> None:
        self._thread.start()

    def close(self) -> None:
        self._stop.set()
        self._listener.close()
        self._thread.join(timeout=5)
        if self.error is not None:
            raise self.error

    def _serve(self) -> None:
        try:
            while not self._stop.is_set():
                try:
                    connection, _ = self._listener.accept()
                except TimeoutError:
                    continue
                except OSError:
                    return
                self.connection_count += 1
                with connection:
                    while not self._stop.is_set():
                        frame = receive_futu_frame(connection)
                        if frame is None:
                            return
                        self.protocols.append(frame.protocol_id)
                        self._respond(connection, frame)
        except BaseException as exc:  # test server must propagate thread failures
            self.error = exc

    def _respond(self, connection: socket.socket, frame: FutuFrame) -> None:
        self.request_bodies.setdefault(frame.protocol_id, []).append(frame.body)
        if frame.protocol_id == 1001:
            from futu.common.pb import InitConnect_pb2

            request = InitConnect_pb2.Request()
            request.ParseFromString(frame.body)
            self.init_recv_notify = bool(request.c2s.recvNotify)
            response = InitConnect_pb2.Response(retType=0, errCode=0)
            response.s2c.serverVer = self.server_version
            response.s2c.loginUserID = 42
            response.s2c.connID = 84
            response.s2c.connAESKey = ""
            response.s2c.keepAliveInterval = 600
        elif frame.protocol_id == 1002:
            from futu.common.pb import GetGlobalState_pb2

            request = GetGlobalState_pb2.Request()
            request.ParseFromString(frame.body)
            self.global_state_user_ids.append(int(request.c2s.userID))
            self.global_state_calls += 1
            response = GetGlobalState_pb2.Response(retType=0, errCode=0)
            response.s2c.marketHK = 0
            response.s2c.marketUS = 0
            response.s2c.marketSH = 0
            response.s2c.marketSZ = 0
            response.s2c.marketHKFuture = 0
            response.s2c.qotLogined = (
                self.global_state_calls != self.quote_lost_on_global_state_call
            )
            response.s2c.trdLogined = (
                self.trade_logined or self.global_state_calls == self.trade_on_global_state_call
            )
            server_version, server_build_no = self.global_state_server_identity_overrides.get(
                self.global_state_calls,
                (self.server_version, self.server_build_no),
            )
            response.s2c.serverVer = server_version
            response.s2c.serverBuildNo = server_build_no
            response.s2c.time = 1_782_000_000
            response.s2c.connID = 84
        elif frame.protocol_id == 3103:
            from futu.common.pb import Qot_RequestHistoryKL_pb2

            request = Qot_RequestHistoryKL_pb2.Request()
            request.ParseFromString(frame.body)
            self.history_request_shapes.append(
                {
                    "rehab_type": int(request.c2s.rehabType),
                    "kl_type": int(request.c2s.klType),
                    "market": int(request.c2s.security.market),
                    "code": str(request.c2s.security.code),
                    "begin_time": str(request.c2s.beginTime),
                    "end_time": str(request.c2s.endTime),
                    "maximum_rows": int(request.c2s.maxAckKLNum),
                    "field_mask": int(request.c2s.needKLFieldsFlag),
                    "next_key": bytes(request.c2s.nextReqKey),
                    "extended_time": bool(request.c2s.extendedTime),
                    "session": int(request.c2s.session),
                }
            )
            response = Qot_RequestHistoryKL_pb2.Response(retType=0, errCode=0)
            response.s2c.security.market = request.c2s.security.market
            response.s2c.security.code = request.c2s.security.code
            response.s2c.name = request.c2s.security.code
            if self.history_empty_then_next and len(self.history_request_shapes) == 1:
                response.s2c.nextReqKey = b"hidden-sdk-page-2"
            else:
                row = response.s2c.klList.add()
                row.time = "2026-08-14 00:00:00"
                row.isBlank = False
                row.closePrice = 220.25
                row.volume = 123_456
        elif frame.protocol_id == 3104:
            from futu.common.pb import Qot_RequestHistoryKLQuota_pb2

            request = Qot_RequestHistoryKLQuota_pb2.Request()
            request.ParseFromString(frame.body)
            self.quota_request_shapes.append(
                {
                    "get_detail": bool(request.c2s.bGetDetail),
                    "security_firm": int(request.c2s.header.securityFirm),
                }
            )
            response = Qot_RequestHistoryKLQuota_pb2.Response(retType=0, errCode=0)
            response.s2c.usedQuota = 1
            response.s2c.remainQuota = 299
            detail = response.s2c.detailList.add()
            detail.security.market = 11
            detail.security.code = "AAPL"
            detail.requestTime = "2026-08-14 14:17:17"
            detail.requestTimeStamp = 1_786_731_437
        elif frame.protocol_id == 3202:
            from futu.common.pb import Qot_GetStaticInfo_pb2

            request = Qot_GetStaticInfo_pb2.Request()
            request.ParseFromString(frame.body)
            self.static_info_request_shapes.append(
                {
                    "market": int(request.c2s.market),
                    "security_type": int(request.c2s.secType),
                    "codes": [
                        {
                            "market": int(security.market),
                            "code": str(security.code),
                        }
                        for security in request.c2s.securityList
                    ],
                }
            )
            response = Qot_GetStaticInfo_pb2.Response(retType=0, errCode=0)
            requested_security = request.c2s.securityList[0]
            basic = response.s2c.staticInfoList.add().basic
            basic.security.market = requested_security.market
            basic.security.code = requested_security.code
            basic.id = 1
            basic.lotSize = 1
            basic.secType = 3
            basic.name = requested_security.code
            basic.listTime = "1980-12-12"
            basic.delisting = False
            basic.exchType = 5
        elif frame.protocol_id == 3243:
            from futu.common.pb import Notify_pb2, Qot_GetCompanyProfile_pb2

            if self.push_notify_before_profile:
                notify = Notify_pb2.Response(retType=0, errCode=0)
                notify.s2c.type = 1
                connection.sendall(
                    pack_futu_frame(1003, frame.serial_number + 100_000, notify.SerializeToString())
                )
            response = Qot_GetCompanyProfile_pb2.Response(retType=0, errCode=0)
            item = response.s2c.itemList.add()
            item.name = "business_summary"
            item.value = "Pinned fake OpenD company profile"
            item.fieldType = 0
        elif frame.protocol_id == 3227:
            from futu.common.pb import Qot_GetFinancialsStatements_pb2

            request = Qot_GetFinancialsStatements_pb2.Request()
            request.ParseFromString(frame.body)
            response = Qot_GetFinancialsStatements_pb2.Response(retType=0, errCode=0)
            structure = response.s2c.structureList.add()
            structure.fieldId = 5001
            structure.displayName = "Total Revenue"
            report = response.s2c.reportList.add()
            report.dateTimeStr = "2025-09-27"
            report.fiscalYear = 2025
            report.financialType = request.c2s.financialType
            report.periodText = "2025/FY"
            report.currencyCode = "USD"
            report.accountingStandards = "US_GAAP"
            report.auditorReport = "UNQUALIFIED"
            item = report.itemList.add()
            item.fieldId = 5001
            item.data = 391_035_000_000.0
            response.s2c.nextKey = "-1"
        elif frame.protocol_id == 3228:
            from futu.common.pb import Qot_GetFinancialsRevenueBreakdown_pb2

            response = Qot_GetFinancialsRevenueBreakdown_pb2.Response(retType=0, errCode=0)
            response.s2c.period = "2025/FY"
            response.s2c.currencyCode = "USD"
            group = response.s2c.breakdownList.add()
            group.type = 1
            item = group.itemList.add()
            item.name = "Products"
            item.mainOperIncome = 250_000_000_000.0
            item.ratio = 62.5
            item = group.itemList.add()
            item.name = "Services"
            item.mainOperIncome = 150_000_000_000.0
            item.ratio = 37.5
        elif frame.protocol_id == 3229:
            from futu.common.pb import Qot_GetResearchAnalystConsensus_pb2

            response = Qot_GetResearchAnalystConsensus_pb2.Response(retType=0, errCode=0)
            response.s2c.average = 215.0
            response.s2c.highest = 250.0
            response.s2c.lowest = 180.0
            response.s2c.rating = 4
            response.s2c.total = 40
            response.s2c.updateTimeStr = "2026-08-14"
        elif frame.protocol_id == 3230:
            from futu.common.pb import Qot_GetResearchRatingSummary_pb2

            response = Qot_GetResearchRatingSummary_pb2.Response(retType=0, errCode=0)
            summary = response.s2c.instRatingSummaryList.add()
            summary.institutionInfo.institutionUid = "institution:fake"
            summary.institutionInfo.institutionName = "Pinned Institution"
            rating = summary.ratingItemList.add()
            rating.institutionUid = "institution:fake"
            rating.rating = 1
            rating.targetPrice = 225.0
            rating.recommendationDateStr = "2026-08-14"
            response.s2c.nextKey = "-1"
        elif frame.protocol_id == 3232:
            from futu.common.pb import Qot_GetValuationDetail_pb2

            response = Qot_GetValuationDetail_pb2.Response(retType=0, errCode=0)
            response.s2c.valuationType = 1
            response.s2c.lastUpdateTimeStr = "2026-08-14"
            response.s2c.trend.currentValue = 31.5
        elif frame.protocol_id == 3234:
            from futu.common.pb import Qot_GetCorporateActionsDividends_pb2

            response = Qot_GetCorporateActionsDividends_pb2.Response(retType=0, errCode=0)
            dividend = response.s2c.dividendList.add()
            dividend.pubDate = "2026/07/31"
            dividend.statement = "USD 0.25 cash dividend"
            dividend.recordDate = "2026/08/10"
            dividend.exDate = "2026/08/09"
            dividend.dividendPayableDate = "2026/08/15"
        elif frame.protocol_id == 3236:
            from futu.common.pb import Qot_GetCorporateActionsStockSplits_pb2

            response = Qot_GetCorporateActionsStockSplits_pb2.Response(retType=0, errCode=0)
            split = response.s2c.splitItemList.add()
            split.dirDeciPubDateStr = "2020-07-30"
            split.reformType = "Split"
            split.rate = "1->4"
            response.s2c.nextKey = "-1"
        elif frame.protocol_id == 3244:
            from futu.common.pb import Qot_GetCompanyExecutives_pb2

            response = Qot_GetCompanyExecutives_pb2.Response(retType=0, errCode=0)
            director = response.s2c.directorList.add()
            director.displayLeaderName = "Test Executive"
            director.leaderName = "Test Executive"
            director.positionName = "Chief Executive Officer"
            director.beginDateStr = "2011-08-24"
        elif frame.protocol_id == 3245:
            from futu.common.pb import Qot_GetCompanyExecutiveBackground_pb2

            response = Qot_GetCompanyExecutiveBackground_pb2.Response(retType=0, errCode=0)
            response.s2c.briefBackground = "Pinned fake executive background"
        elif frame.protocol_id == 3246:
            from futu.common.pb import Qot_GetCompanyOperationalEfficiency_pb2

            response = Qot_GetCompanyOperationalEfficiency_pb2.Response(retType=0, errCode=0)
            response.s2c.currencyCode = "USD"
            item = response.s2c.itemList.add()
            item.fiscalYear = 2025
            item.financialType = 7
            item.periodText = "2025/FY"
            item.endDateStr = "2025-09-27"
            item.employeeNum = 166_000
            item.incomePerCapita = 2_355_632.53
            response.s2c.nextKey = "-1"
        else:
            raise AssertionError(f"unexpected fake OpenD protocol: {frame.protocol_id}")
        connection.sendall(
            pack_futu_frame(
                frame.protocol_id,
                frame.serial_number,
                response.SerializeToString(),
            )
        )


__all__ = ("FakeOpenD",)
