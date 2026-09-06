# Futu sidecar wire v2

Each AF_UNIX message is one four-byte big-endian unsigned length followed by one canonical UTF-8 JSON object. Requests are limited to 1 MiB and responses to 16 MiB. The server proves the peer UID before parsing a request.

The only commands are `open_quote_only_session`, `fetch_quote_data_with_global_state_guards`, `finalize_quote_only_session`, and `abort_quote_only_session`. A successful fetch is signed over its entire top-level object with `signature_hex` omitted. Boot, runtime, execution, and abort receipts are separately signed. Session ID, boot receipt ID, and strict sequence prevent replay or reordering.

No trade, account, order, position, balance, raw-send, credential, or generic protocol command exists on this wire.
