# Supply-chain inputs

This directory is a release input, not a substitute for the final signed release
manifest. `dependency-lock-v1.json` pins every selected runtime, build, and test
source distribution by exact version and SHA-256. A release may use a binary wheel
only when that platform wheel is added to a separately signed platform lock.

`sbom.cdx.json` is the deterministic CycloneDX inventory generated from the lock.
`source-inputs-v1.json` binds the pinned Futu registry, descriptor set, installed SDK
tree, and dependency lock. The release pipeline must add exact commit/tree, wheel,
sdist, launcher bundle, and repository hashes; this source bundle intentionally does
not self-assert those final values.

No credential, account identifier, OpenD response, licensed raw vendor payload, CAS
key, or attestor private key is permitted in any file in this directory.

The project-original sidecar code is governed by
`LicenseRef-Owner-Research-Proprietary` and the exact `../LICENSE` notice. This is
an all-rights-reserved private-distribution policy, not an open-source grant. It
does not relicense the official Futu SDK or any other dependency; those materials
remain under their own recorded terms.

An exact sidecar artifact may be built, verified, and used only inside the
separately authorized private canary/runtime boundary. The wheel, sdist, source,
or raw Futu data must not be attached to a public GitHub Release or included in the
public research wheel or Plugin. A public release may publish only the approved
cryptographic identity, SBOM/provenance projection, and signed canary evidence.
