"""One-shot native OpenD connection check; no research, prices, or account APIs."""

from __future__ import annotations

import argparse
import os
import signal
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .canonical import SidecarContractError, canonical_json
from .frame_guard import FrameGuardProxy
from .opend_adapter import OfficialFutuAdapter
from .runtime_authorization import require_runtime_platform

_HOME_KEYS = ("HOME", "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME")


def probe_native_opend() -> dict[str, Any]:
    """Return observed connection status, never a signed valuation authority."""
    require_runtime_platform("2.0.0")
    if os.geteuid() == 0:
        raise SidecarContractError("native OpenD preflight refuses root execution")
    previous_home = {key: os.environ.get(key) for key in _HOME_KEYS}
    try:
        with tempfile.TemporaryDirectory(prefix="owner-opend-preflight-") as temporary:
            guard = FrameGuardProxy(upstream_host="127.0.0.1", upstream_port=11111)
            adapter = None
            try:
                guard.start()
                adapter = OfficialFutuAdapter(guard=guard, private_home=Path(temporary))
                state = adapter.global_state()
                if guard.quarantined or guard.sequence != 2 or adapter.connect_attempts != 1:
                    raise SidecarContractError(
                        "native preflight was not one init and one status call"
                    )
                return {
                    "schema_version": "1.0.0",
                    "artifact_type": "futu-native-connection-observation",
                    "runtime_profile": "macos_local_read_only",
                    "observed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                    "endpoint": "127.0.0.1:11111",
                    "status": "connected" if state.qot_logined else "quote_login_required",
                    "qot_logined": state.qot_logined,
                    "trd_logined": state.trd_logined,
                    "opend_server_version": state.server_version,
                    "opend_server_build_no": state.server_build_no,
                    "protocol_ids": [1001, 1002],
                    "connection_attempts": adapter.connect_attempts,
                    "global_state_request_sha256": state.exchange.request.sha256,
                    "global_state_response_sha256": state.exchange.response.sha256,
                    "research_data_fetched": False,
                    "canary_completed": False,
                    "release_authority": False,
                }
            finally:
                if adapter is not None:
                    adapter.close()
                else:
                    guard.close()
    finally:
        for key, value in previous_home.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _timeout(_signum: int, _frame: object) -> None:
    raise TimeoutError("native OpenD preflight exceeded 45 seconds")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args(argv)
    sys.dont_write_bytecode = True
    previous_handler = signal.signal(signal.SIGALRM, _timeout)
    signal.alarm(45)
    try:
        result = probe_native_opend()
        print(canonical_json(result))
        return 0 if result["status"] == "connected" else 2
    except (OSError, SidecarContractError) as exc:
        print(f"owner-research-futu-native-preflight: {exc}", file=sys.stderr)
        return 2
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous_handler)


if __name__ == "__main__":
    raise SystemExit(main())
