# Rootless launcher contract

The production entrypoint is the installed
`owner-research-futu-preopen-and-launch` console script (the bundled
`launch-rootless.sh` is an equivalent service wrapper). The compatibility alias
`owner-research-futu-launch` has the same closed contract. It runs as a
non-root UID and consumes five
one-shot, preopened, non-regular handles:

- FD 3: canonical launch configuration, whose runtime claims exactly mirror the authority;
- FD 4: exactly 32 bytes of the private encrypted-CAS key;
- FD 5: exactly 32 bytes of the Ed25519 attestor seed, visible only to the supervisor.
- FD 6: canonical signed runtime authorization bytes, visible only to the supervisor;
- FD 7: canonical authorization-role public keyring bytes, visible only to the supervisor.

The supervisor forks before reading the seed. The data child closes FDs 5, 6, and 7 and receives
only an AF_UNIX signing socket. It starts Python with isolated mode and bytecode writes
disabled. The supervisor must independently verify the authorization/keyring and keep
the one-shot plan/sequence ledger. Before every SDK data call, the child asks the
supervisor for a private authorization ticket binding the next exact plan item. The
data child cannot propose signing authority or query an unplanned security/protocol.

The orchestrator must create a new private per-run HOME, CAS root, and UDS parent,
all owned by the executing UID with mode `0700`. The UDS itself is exactly `0600`.
There are exactly two runtime profiles:

- `linux_vm_read_only`: v1 signed supply/runtime receipts, a pinned VM image,
  a dedicated non-root UID, tmpfs HOME, and OpenD on loopback in the isolated VM.
- `macos_local_read_only`: v2 signed supply/runtime receipts, `vm_image_sha256: null`,
  `credentials_location: user_managed_macos_opend`, and a separate non-root sidecar
  on Darwin using only `127.0.0.1:11111`. The desktop OpenD keeps its existing login;
  the sidecar never receives account credentials. This is process/protocol isolation,
  not VM or network-namespace isolation. SDK logs are disabled; this claim does not
  describe desktop OpenD's own UI logs. The Linux service template is not used on Mac.

Both profiles use the same closed request plan, protocol guard, supervisor, and
private encrypted CAS. Neither admits trading/account operations or public binds.
FDs must be one-shot pipes, connected local sockets, or equivalent non-regular
supervisor handles; paths, ordinary or sealed regular files, environment secrets,
inherited account credentials, and command-line secrets are rejected.

Install the exact release wheel with `--no-compile`. Any `futu/__pycache__` or `.pyc`
member is a pre-import hard failure. Use the signed platform artifact lock; the source
distribution lock alone is not authority for an arbitrary wheel.

Cross-process one-shot authorization consumption belongs to the external supervisor
ledger. Re-launching the process with the same authorization fingerprint is forbidden
even though the in-process controller also rejects a second open.

The service manager or canary orchestrator must pass the five already-open handles as
descriptors 3 through 7. The launcher will not open a credential path or accept secret
bytes on the command line. It rejects missing descriptors, ordinary files, and device
handles before forking. `OWNER_RESEARCH_FUTU_PRIVATE_HOME` must name an existing,
non-linked, mode-`0700` directory owned by the executing UID.

For an explicit Mac setup check only, run the exact installed sidecar environment's
`python -I -B -m owner_research_futu_sidecar.native_preflight`. It makes one
InitConnect and one GlobalState call, times out after 45 seconds, closes the
connection, and prints only status, server identity, and response hashes. It does
not read prices, financial data, or account APIs and does not issue signed authority.
Ordinary research must not run this probe implicitly.
