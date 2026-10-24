"""The ring R_q = Z_q[X]/(X^n + 1) of Section II-B.

A ring element is an int64 array whose last axis holds its n coefficients in [0, q).
A row vector in R_q^{1 x ell} has shape (ell, n), and further leading axes are batches.

Products use the twisted (negacyclic) complex FFT, which needs neither an NTT-friendly
q (q = 2^28 - 57 is not one) nor a power-of-two n (PARAM II has n = 595, plan
decision 1). Coefficients are split into 14-bit limbs so that every limb product has
integer coefficients below n * 2^29, which float64 rounds back exactly (plan decision 2).
"""

import math
from dataclasses import dataclass
from functools import cache

import numpy as np
from numpy.typing import ArrayLike, NDArray

type Poly = NDArray[np.int64]
"""Ring elements: coefficients in [0, q) on the last axis (length n), e.g. (n,) or (ell, n)."""

type Bits = NDArray[np.uint8]
"""0/1 values, e.g. an (ell, n) extractor output or its row-major flattening."""

LIMB_BITS = 14
"""Two limbs of this width cover every coefficient of R_q for q < 2^28."""


@cache
def _twist(n: int) -> NDArray[np.complex128]:
    """psi^i for i in [0, n) with psi = exp(i pi / n), so psi^n = -1."""
    return np.exp(1j * np.pi * np.arange(n) / n)


@dataclass(frozen=True, slots=True)
class Ring:
    """R_q = Z_q[X]/(X^n + 1) for odd q < 2^28."""

    q: int
    n: int

    def __post_init__(self) -> None:
        if self.q % 2 == 0 or not 3 <= self.q < 1 << (2 * LIMB_BITS):
            raise ValueError(f"q must be odd and in [3, 2^{2 * LIMB_BITS}), got {self.q}")
        if self.n < 1:
            raise ValueError(f"n must be positive, got {self.n}")

    @property
    def ell(self) -> int:
        """ell = ceil(log2 q), the width of the gadget vector G."""
        return (self.q - 1).bit_length()

    def add(self, a: Poly, b: Poly) -> Poly:
        return (a + b) % self.q

    def sub(self, a: Poly, b: Poly) -> Poly:
        return (a - b) % self.q

    def neg(self, a: Poly) -> Poly:
        return -a % self.q

    def small(self, x: ArrayLike) -> Poly:
        """The mod-q representation of signed integer coefficients, such as a Gaussian sample."""
        return np.asarray(x, dtype=np.int64) % self.q

    def centered(self, a: ArrayLike) -> NDArray[np.int64]:
        """The representative of a mod q in (-q/2, q/2]."""
        a = np.asarray(a, dtype=np.int64) % self.q
        return np.where(a > self.q // 2, a - self.q, a)

    def mul(self, a: Poly, b: Poly) -> Poly:
        """The exact product a * b in R_q, broadcast over leading axes, so (ell, n) x (n,) works."""
        sa, sb = self.limb_spectra(a), self.limb_spectra(b)
        lo = self.from_spectrum(sa[0] * sb[0])
        mid = self.from_spectrum(sa[0] * sb[1] + sa[1] * sb[0])
        hi = self.from_spectrum(sa[1] * sb[1])
        return self.join_limbs(lo, self.join_limbs(mid, hi))

    def spectrum(self, a: ArrayLike) -> NDArray[np.complex128]:
        """The twisted FFT on the last axis, under which negacyclic products are pointwise."""
        return np.fft.fft(a * _twist(self.n), axis=-1)

    def from_spectrum(self, s: NDArray[np.complex128]) -> NDArray[np.int64]:
        """The integer coefficients, not reduced mod q, of the polynomial whose twisted FFT is s.

        Rounding is exact while the true coefficients stay far below 2^53 in magnitude;
        sums of 14-bit limb products stay below n * 2^29 (under 2^39 for PARAM I and II).
        """
        return np.rint((np.fft.ifft(s, axis=-1) / _twist(self.n)).real).astype(np.int64)

    def limb_spectra(self, a: Poly) -> NDArray[np.complex128]:
        """The spectra of the limbs a mod 2^14 and a >> 14, stacked on a new leading axis."""
        return self.spectrum(np.stack([a & ((1 << LIMB_BITS) - 1), a >> LIMB_BITS]))

    def join_limbs(self, lo: NDArray[np.int64], hi: NDArray[np.int64]) -> Poly:
        """lo + 2^14 hi mod q, for exact integer limb products lo and hi."""
        return (lo + ((hi % self.q) << LIMB_BITS)) % self.q

    def to_bytes(self, a: Poly) -> bytes:
        """Little-endian uint32 per coefficient, C order."""
        return a.astype("<u4").tobytes()

    def from_bytes(self, data: bytes, shape: tuple[int, ...]) -> Poly:
        """Parse to_bytes output of the given shape. Raise ValueError on a wrong length or a coefficient >= q."""
        size = 4 * math.prod(shape)
        if len(data) != size:
            raise ValueError(f"expected {size} bytes for shape {shape}, got {len(data)}")
        a = np.frombuffer(data, dtype="<u4").astype(np.int64).reshape(shape)
        if (a >= self.q).any():
            raise ValueError("coefficient not below q")
        return a

    def pack_bits(self, bits: Bits) -> bytes:
        """The ell * n bits of an (ell, n) bit array (or its flattening), row-major, packed into bytes."""
        return np.packbits(bits, axis=None).tobytes()

    def unpack_bits(self, data: bytes) -> Bits:
        """Inverse of pack_bits, as an (ell, n) array. Raise ValueError on a wrong length or nonzero padding."""
        count = self.ell * self.n
        size = -(-count // 8)
        if len(data) != size:
            raise ValueError(f"expected {size} bytes for {count} bits, got {len(data)}")
        bits = np.unpackbits(np.frombuffer(data, dtype=np.uint8))
        if bits[count:].any():
            raise ValueError("nonzero padding bits")
        return bits[:count].reshape(self.ell, self.n)
