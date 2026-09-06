# Third-party notices index

The authoritative component versions, source-distribution hashes, and SPDX-style
license expressions are in `dependency-lock-v1.json`. Release assembly must obtain
and bundle the exact upstream license/notice files from the same hashed source
archives. This index does not replace those texts.

The runtime closure consists of cffi, cryptography, futu-api, NumPy, pandas,
protobuf, pycparser, PyCryptodome, python-dateutil, simplejson, and six. Build and
test-only components are separately marked in the lock and must not be copied into
the runtime image unless the final SBOM and runtime member inventory are regenerated.

Futu API is an official vendor SDK dependency. Its inclusion does not grant market-
data, account, or redistribution rights. Those rights remain a separate signed,
expiring runtime authorization gate.
