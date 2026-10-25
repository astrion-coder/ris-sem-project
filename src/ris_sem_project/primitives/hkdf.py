"""HKDF (Definitions 9-10): Krawczyk's extract-then-expand [81] with the BP lattice PRF
[80] in place of HMAC, so dsk = HKDF(K_u, w) is Hkdf(bp, K_u).derive(w).

Each output is one PRF block of ell * n bits, already the full key length.
"""

from .bp_prf import BPPRF
from .prf import prf

SALT = bytes(32)
"""The fixed public salt, all zeros as in RFC 5869 when no salt is given."""


class Hkdf:
    """HKDF keyed by the input key material ikm, with PRK computed once."""

    def __init__(self, bp: BPPRF, ikm: bytes, salt: bytes = SALT) -> None:
        """Extract: PRK = PRF(ikm, "QPASE/HKDF/extract" || salt)."""
        self._bp = bp
        self._prk = prf(bp, ikm, b"QPASE/HKDF/extract" + salt)

    def derive(self, info: bytes) -> bytes:
        """Expand: PRF(PRK, "QPASE/HKDF/expand" || info || 0x01)."""
        return prf(self._bp, self._prk, b"QPASE/HKDF/expand" + info + b"\x01")
