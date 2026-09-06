# Futu sidecar wire v3

The framing, four closed commands, signed receipts, sequenced sessions, protocol allowlist,
and 1 MiB request / 16 MiB response limits remain unchanged from wire v2.

Requests require quote login but no longer prescribe a value for `trd_logined`.
Every response and signed checkpoint retains the actual boolean trading-server connection
state. Either value is allowed; it never authorizes a trade or account API. Quote login loss,
unknown protocols, and trade/account/holdings/balance requests still fail closed.

Wire v2 descriptors remain historical; v3 peers require exact v3 framing and descriptors.
