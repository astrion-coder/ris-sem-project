# Unit U1: lattice primitives, parameters, TOPRF, lattice PRF/HKDF

Read `.audit/briefs/common.md` first. Paper refs: Sec. II-B (Lemma 1, Def. 8, Fig. 1-2, Thm 1),
Sec. II-D (Def. 11-12), Sec. IV-A (Setup), Table II. Plan refs: Part 2 decisions 1-5 and 7, Part 3.

## Files you own

- `src/ris_sem_project/params.py`
- `src/ris_sem_project/primitives/__init__.py` (export nothing beyond what callers need; may be empty docstring)
- `src/ris_sem_project/primitives/ring.py`, `sampling.py`, `gadget.py`, `bp_prf.py`, `extractor.py`,
  `secret_sharing.py`, `toprf.py`, `prf.py`, `hkdf.py`
- `tests/test_ring.py`, `tests/test_bp_prf.py`, `tests/test_extractor.py`, `tests/test_secret_sharing.py`,
  `tests/test_toprf.py`, `tests/test_hkdf_prf.py`

Do NOT create `signature.py`, `symmetric.py`, `encoding.py` (another worker owns them in parallel) and do not
touch `src/ris_sem_project/parties/`.

## Data shapes (decided; keep them)

- A ring element of R_q = Z_q[X]/(X^n + 1) is an `np.ndarray` of `np.int64`, last axis length n, every
  coefficient in `[0, q)`. A vector in R_q^{1 x ell} has shape `(ell, n)`. Batches put extra axes in front.
- `Ring` is a frozen dataclass `(q: int, n: int)` with `ell = ceil(log2 q)` (28 for q = 2^28 - 57). It owns:
  `mul(a, b)` exact negacyclic product broadcasting over leading axes (so `(ell, n) x (n,)` works),
  `add`, `sub`, `neg`, `small(int_array) -> mod-q array`, `centered(a) -> int64 in (-q/2, q/2]`,
  `to_bytes(a)` (little-endian uint32 per coefficient, C order) and `from_bytes(data, shape)` which
  validates length and that every coefficient is `< q` (raise `ValueError`).
- Bit strings (PRF outputs, extractor outputs, K_u, dsk, PRK) are packed `bytes` from `np.packbits` of
  `ell * n` bits in row-major order of the `(ell, n)` array. Helpers to pack/unpack live in one place.

## Exact multiplication (measured feasible)

Use the twisted negacyclic FFT: multiply coefficient i by psi^i with psi = exp(i*pi/n), complex FFT of
length n, pointwise product, inverse FFT, divide by psi^i, `np.rint`. Split each operand into 14-bit limbs
(`x & 0x3FFF`, `x >> 14`) so every limb-pair product has coefficient sums below about 2^38 and rounds
exactly. A throwaway prototype at n = 512 measured 4.8 ms per BP-PRF gadget step (20-step average, one run)
with this method and matched a pure-Python schoolbook product. Works for any n (PARAM II n = 595 uses
X^595 + 1 per plan decision 1 and is not a power of two; numpy FFT handles it).

Tests: `Ring.mul` equals a pure-Python object-dtype schoolbook negacyclic product for random uniform
operands at n = 512 and n = 595 (a few pairs), and for uniform x small (Gaussian) operands.

## Sampling (`sampling.py`)

- `uniform(ring, shape)`: 4 bytes per coefficient from `os.urandom`, mask to 28 bits (generally
  `ell` bits), reject `>= q`, refill rejected slots until done. Vectorized.
- `gaussian(ring, shape, sigma)`: centered discrete Gaussian chi_sigma via a cumulative distribution table
  over |x| <= ceil(12 sigma) with 64-bit uniforms from `os.urandom` plus a random sign (handle x = 0 so it is
  not double-counted). Returns the mod-q representation.
- `uniform_zq(q) -> int` via `secrets.randbelow`.

## Gadget (`gadget.py`)

`g_inverse(ring, v)` for v of shape `(ell, n)` returns the binary array `B` of shape `(ell, ell, n)` with
`B[k, j]` = bit k of every coefficient of v_j, so `sum_k 2^k B[k, j] == v_j` (i.e. G * G^{-1}(v) = v with
G = (1, 2, ..., 2^{ell-1})). Test that identity.

## BP lattice PRF (`bp_prf.py`, Lemma 1 / [80])

`class BPPRF(ring, a0, a1)` with a0, a1 of shape `(ell, n)` (from pp). Precompute the limb FFTs of a0, a1.

- `a_x(x)`: x is a uint8 array of L bits `(x_1, ..., x_L)`. Return
  `a_x = a_{x_1} G^{-1}(a_{x_2} G^{-1}( ... G^{-1}(a_{x_L})))`, i.e. start v = a_{x_L}, then for
  i = L-1 down to 1: v = a_{x_i} * G^{-1}(v), where `(1 x ell) * (ell x ell)` is
  `out_j = sum_k a_{x_i,k} * B[k, j]`. Batch the ell x ell products in the frequency domain (einsum).
- `evaluate(k, x)`: `round_p(a_x(x) * k)` with p = 2, `round_p(y) = floor((p*y + floor(q/2)) / q) mod p`
  per coefficient, flattened to `ell * n` bits. k is any R_q element (uniform keys are fine; Lemma 1 samples
  k uniformly).
- `encode_input(data: bytes, L) -> bits`: first L bits (big-endian, `np.unpackbits`) of SHA3-256(data).
  Callers add their own domain-separation prefix to `data`.

Tests: at small parameters (e.g. q = 2^28 - 57, n = 8, L = 6) `a_x` equals a slow pure-Python reference
that builds G^{-1} and multiplies by schoolbook; `evaluate` is deterministic; different x give different
outputs. One full-size timing is fine to print in the report, not in the tests.

## Robust extractor (`extractor.py`, Def. 8 / Ding et al. [69])

Work per coefficient on centered representatives c in [-(q-1)/2, (q-1)/2] (q odd).
- sigma_0(c) = 0 if c in [-floor(q/4), floor(q/4)] else 1;
  sigma_1(c) = 0 if c in [-floor(q/4)+1, floor(q/4)+1] else 1.
- `hint(ring, y)`: per coefficient pick b uniformly in {0,1} and output sigma_b(y) (uint8 array, same shape).
- `extract(ring, x, sigma)`: E(x, s) = centered((x + s*(q-1)/2) mod q) mod 2 (uint8). The paper prints
  "(x+sigma)*(q-1)/2 mod 2"; that is a typesetting slip, Ding's definition above is the one to implement.
Test the defining property: for random y and random even perturbations 2e with |2e| < q/8,
`extract(y + 2e, hint(y)) == extract(y, hint(y))` everywhere.

## Secret sharing and DKG (`secret_sharing.py`, Def. 11-12, plan decisions 3 and 5)

- `lagrange_at_zero(ids) -> dict[int, int]`: exact integer Lagrange coefficients at 0 using
  `fractions.Fraction`; raise `NonIntegerLagrangeError(ValueError)` if any is not an integer. Example:
  {1,2} -> {1: 2, 2: -1}; {2,3} -> {2: 3, 3: -2}; {1,3} raises.
- `genshare(ring, t, ids, sigma) -> dict[int, ndarray]`: S_i samples f_i(X) = s_i + sum_{k=1}^{t-1} c_k X^k
  with s_i <- chi_sigma (small, plan decision 3) and c_k uniform in R_q, and returns {j: f_i(j)} for every
  server id j. Degree t-1 so any t servers suffice (decision 5).
- `genkey(ring, shares) -> ndarray`: k_j = sum_i [s_i]_j mod q.
- `reconstruct(ring, shares: dict[int, ndarray])`: sum lambda_i * share_i mod q (used by tests).
Test: reconstruct from every integer-lambda t-subset of N = 3, t = 2 and N = 4, t = 3 equals sum_i s_i.

## TOPRF (`toprf.py`, Fig. 1-2, Thm 1, plan decisions 3-4)

Messages are unrounded; all noise is even.
- `blind(ring, a, ax, sigma) -> (b, r)`: r <- chi_sigma (n,), e <- chi_sigma (ell, n), b = a*r + ax + 2e.
- `server_public_key(ring, a, k_i, sigma)`: pk_i = a*k_i + 2e_i, e_i <- chi_sigma (ell, n).
- `evaluate(ring, b, k_i, sigma)`: b_{k_i} = b*k_i + 2e'_i, e'_i <- chi_sigma (ell, n).
- `combine(ring, evaluations: dict[int, ndarray], public_keys: dict[int, ndarray], r)`:
  F = sum_i lambda_i b_{k_i} - r * sum_i lambda_i pk_i (mod q), lambda from `lagrange_at_zero` over the
  responding ids (so a non-integer subset raises). Algebra: F = a_x K + 2e'', e'' = eK + sum lambda_i e'_i
  - r sum lambda_i e_i. The minus sign is deliberate (plan decision 3).
- `finalize(ring, F, hint=None) -> (k_u: bytes, hint: ndarray)`: Register calls it with no hint and gets
  sigma = hint(F) back with K_u = extract(F, sigma); Login passes the stored hint and gets
  K_u = extract(F, hint). Shape `(ell, n)`, K_u packed as `ell * n` bits.
Tests (full PARAM I, N = 3, t = 2, DKG keys): same password bits give byte-identical K_u over at least
10 independent blind/evaluate/combine runs and over subsets {1,2} and {2,3}; F_login - F_reg is even and its
max |centered| is far below q/4 (report the observed max); a different password gives a K_u that differs in
roughly half the bits; subset {1,3} raises.

## Lattice PRF and HKDF (`prf.py`, `hkdf.py`, plan Part 3 "lattice instantiation (user decision)")

- `key_to_ring(ring, key: bytes)`: unpack `ell * n` bits, read each consecutive ell-bit group as a big-endian
  integer for one coefficient, reduce mod q. Reject a key of the wrong length.
- `prf(bp, key: bytes, data: bytes) -> bytes`: packed `bp.evaluate(key_to_ring(key), encode_input(data))`.
  This is PRF(dsk, rho) in Outsource/Retrieve.
- `class Hkdf(bp, ikm: bytes, salt: bytes = <module constant>)`: Krawczyk extract-then-expand with the BP
  PRF in place of HMAC. Extract once at construction: PRK = prf(ikm, b"QPASE/HKDF/extract" + salt).
  `derive(info: bytes) -> bytes` = prf(PRK, b"QPASE/HKDF/expand" + info + b"\x01"). Output is one block of
  `ell * n` bits, which is the full key length, so no further blocks are needed. dsk = Hkdf(K_u).derive(w).
Tests: deterministic; different info gives different keys; different ikm gives different keys; output length.

## Parameters (`params.py`, Table II, Sec. IV-A, plan decision 7)

- `ParamSet` frozen dataclass: name, q, n, p, sigma, L. `PARAM_I` (q = 2^28 - 57, n = 512, p = 2,
  sigma = 3.2, L = 128) is the default; `PARAM_II` (n = 595, same q/p/sigma/L), docstring noting X^595 + 1
  is not a power-of-two cyclotomic (decision 1).
- `setup(params=PARAM_I, *, N, t, mu) -> PublicParams`: validate 1 <= t <= N and mu >= 1 (boundary), sample
  a, a0, a1 uniform of shape `(ell, n)`, serialize with `Ring.to_bytes`, return
  `ris_sem_project.parties.types.PublicParams` (do not change that class).
- `Lattice` frozen dataclass with `ring`, `a` (ndarray), `prf` (BPPRF) and `Lattice.from_pp(pp)` that parses
  pp once (this is the boundary parse every party will call).

## Report

Also report: full-size timings of `BPPRF.a_x` and `Ring.mul` (median of >= 5 runs each), the observed
TOPRF noise max, and the whole-suite runtime.
