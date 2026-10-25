"""Offline password test against PARAM II through the root X = -1 of X^n + 1 (finding on Fig. 2 and Fig. 3, attack 1).

The paper claims a semi-honest server that sees the blinded request b = a r + a_x + 2e learns
nothing that lets it test password guesses offline. That rests on b being ring-LWE samples
in R_q. PARAM II takes n = 595, which is odd, so (-1)^595 + 1 = 0 and X = -1 is a root of
X^595 + 1. Then phi(a) = a(-1) = sum_i (-1)^i a_i mod q is a ring homomorphism R_q -> Z_q, and
for a guess x' with a_x' its encoding,

    phi(b_j) - phi(a_x',j) = phi(a_j) phi(r) + 2 phi(e_j) + phi(a_x,j - a_x',j).

For the real password the last term is 0. The server searches rho in [-R, R] for
c_j - rho phi(a_j) small in every row j, which is a one-dimensional LWE instance with a
secret of about 78 in size. A wrong x' leaves phi(a_x,j - a_x',j) uniform in Z_q, so no rho
fits. PARAM I has n = 512 and X^512 + 1 has no root in Z_q because 1024 does not divide
q - 1, so phi is not a homomorphism there and nothing matches.
"""

import math
from collections.abc import Iterable
from dataclasses import dataclass

import numpy as np

from .params import Lattice
from .parties.types import PublicParams, TOPRFRequest
from .primitives.bp_prf import encode_input
from .primitives.ring import Poly, Ring

TAIL_SIGMAS = 8
"""The match threshold sits this many standard deviations of 2 phi(e_j) above 0."""

DEFAULT_RADIUS = 1500
"""R: phi(r) has standard deviation sigma sqrt(n), about 78 at PARAM II, so [-R, R] holds it at 19 sigma."""


@dataclass(frozen=True, slots=True, kw_only=True)
class GuessResult:
    """The outcome of testing one password guess against one blinded request."""

    password: str
    residual: int
    """min over rho in [-R, R] of max_j |centered(c_j - rho phi(a_j))|."""
    phi_r: int | None
    """The rho that attains the residual, the recovered phi(r), or None when the guess did not match."""
    matched: bool


def evaluate_at_minus_one(ring: Ring, a: Poly) -> np.ndarray:
    """phi(a) = a(-1) = sum_i (-1)^i a_i mod q on the last axis. A ring homomorphism only when n is odd."""
    signs = np.where(np.arange(ring.n) % 2 == 0, 1, -1)
    return (a * signs).sum(axis=-1) % ring.q


def match_threshold(pp: PublicParams) -> int:
    """tau = 2 * z * sigma sqrt(n) for z = TAIL_SIGMAS.

    At the real password the residual in row j is 2 phi(e_j), a sum of n coefficients of
    chi_sigma times 2, so close to N(0, (2 sigma sqrt(n))^2). It exceeds tau with probability
    about 1.2e-15 per row, so a true match is missed with probability below 2^-44 over ell rows.
    A wrong rho or wrong password leaves each row uniform in Z_q, so a row falls within tau
    with probability (2 tau + 1) / q, about 1e-5 at PARAM II, and all ell rows with
    probability below 1e-100 even after the 2R + 1 values of rho.
    """
    return math.ceil(2 * TAIL_SIGMAS * pp.sigma * math.sqrt(pp.n))


def offline_password_test(
    pp: PublicParams,
    request: TOPRFRequest,
    guesses: Iterable[str],
    *,
    radius: int = DEFAULT_RADIUS,
    threshold: int | None = None,
) -> list[GuessResult]:
    """Test each guess x' against the blinded request, using only pp and the request.

    Raise ValueError if pp or the request bytes are malformed. A guess matches when its
    residual is below threshold, which defaults to match_threshold(pp).
    """
    if radius < 0:
        raise ValueError(f"radius must be non-negative, got {radius}")
    lattice = Lattice.from_pp(pp)
    ring = lattice.ring
    tau = match_threshold(pp) if threshold is None else threshold
    b = ring.from_bytes(request.blinded_input, (ring.ell, ring.n))
    phi_b, phi_a = evaluate_at_minus_one(ring, b), evaluate_at_minus_one(ring, lattice.a)
    rhos = np.arange(-radius, radius + 1, dtype=np.int64)
    fitted = rhos[:, None] * phi_a[None, :] % ring.q
    results = []
    for password in guesses:
        a_x = lattice.prf.a_x(encode_input(password.encode(), pp.L))
        c = (phi_b - evaluate_at_minus_one(ring, a_x)) % ring.q
        worst = np.abs(ring.centered(c[None, :] - fitted)).max(axis=1)
        best = int(worst.argmin())
        residual = int(worst[best])
        matched = residual < tau
        results.append(
            GuessResult(password=password, residual=residual, phi_r=int(rhos[best]) if matched else None, matched=matched)
        )
    return results
