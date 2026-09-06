"""Private, quote-only Futu OpenD sidecar.

This package is deliberately separate from the public ``owner_research`` wheel.  It
contains no trading or account operation and exposes only a versioned Unix-domain
socket protocol.
"""

from .attestation import Ed25519Attestor, SessionController
from .cas import EncryptedCas
from .frame_guard import FrameGuardProxy

__all__ = (
    "Ed25519Attestor",
    "EncryptedCas",
    "FrameGuardProxy",
    "SessionController",
)

__version__ = "1.0.0.dev0"
