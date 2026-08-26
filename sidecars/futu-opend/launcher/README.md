# Rootless launcher contract

The production entrypoint is the installed
`owner-research-futu-preopen-and-launch` console script (the bundled
`launch-rootless.sh` is an equivalent service wrapper). The compatibility alias
`owner-research-futu-launch` has the same closed contract. It runs as a dedicated
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

The orchestrator must create a new private tmpfs HOME, CAS root, and UDS parent for
each run, all owned by the dedicated UID with mode `0700`. The UDS itself is exactly
`0600`. OpenD is reachable only on loopback in the same isolated network namespace.
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
non-linked, mode-`0700` directory owned by the dedicated UID.
