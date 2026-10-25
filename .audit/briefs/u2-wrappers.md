# Unit U2: signature, symmetric encryption, wire encoding

Read `.audit/briefs/common.md` first. Paper refs: Def. 13 (Dilithium), Def. 14 (symmetric encryption).
Plan refs: Part 2 decision 7 (AES-256-GCM, ML-DSA-44), Part 3 `signature.py`, `symmetric.py`.

## Files you own

- `src/ris_sem_project/primitives/signature.py`
- `src/ris_sem_project/primitives/symmetric.py`
- `src/ris_sem_project/primitives/encoding.py`
- `tests/test_signature.py`, `tests/test_symmetric.py`, `tests/test_encoding.py`

Another worker is writing the lattice modules in `src/ris_sem_project/primitives/` at the same time, and owns
`primitives/__init__.py`. Do not create or edit it or any other file. If `primitives/__init__.py` does not
exist yet when you run tests, the namespace-package import still works; do not create it.

## `signature.py` (CRYSTALS-Dilithium as ML-DSA-44 via `dilithium_py.ml_dsa.ML_DSA_44`)

- `keypair_from_seed(seed: bytes) -> tuple[bytes, bytes]` returning `(pk, sk)`. Requires a 32-byte seed
  (raise `ValueError` otherwise). Uses `ML_DSA_44.key_derive(seed)`, which is deterministic: this is
  Gen(1^kappa, K_u) once the caller turns K_u into a seed.
- `sign(sk: bytes, message: bytes) -> bytes` (randomized signing, the library default).
- `verify(pk: bytes, message: bytes, signature: bytes) -> bool`. Must return False, never raise, for a
  malformed signature or key, because it runs on bytes received from another party.
Tests: same seed gives the same pk; sign/verify round trip; a modified message, a modified signature, a
truncated signature, and a different key all verify False.

## `symmetric.py` (AES-256-GCM via `cryptography`)

- `aes_key(material: bytes) -> bytes`: the plan's rule "AES-256 keys are the first 256 bits of the derived
  key string". Raise `ValueError` if material is shorter than 32 bytes. The one place this truncation lives.
- `encrypt(key: bytes, plaintext: bytes) -> bytes`: key must be exactly 32 bytes. Output
  `nonce (12 random bytes) || ciphertext || tag`.
- `decrypt(key: bytes, blob: bytes) -> bytes | None`: None when the tag does not verify or the blob is too
  short. A wrong key is an expected outcome in the Retrieve scan, so it is a return value, not an exception.
Tests: round trip; wrong key -> None; flipped byte -> None; truncated blob -> None; two encryptions of the
same plaintext differ.

## `encoding.py` (deterministic wire encoding of tuples that get signed or encrypted)

- `pack(*fields: bytes) -> bytes`: each field as a 4-byte big-endian length followed by its bytes.
- `unpack(data: bytes, count: int) -> tuple[bytes, ...]`: inverse; raise `ValueError` if the data does not
  hold exactly `count` well-formed fields (short, trailing bytes, length overflow).
- `int_bytes(value: int, size: int = 4) -> bytes` and `bytes_int(data: bytes) -> int` big-endian helpers for
  item ids and rho in Z_q.
Tests: round trip with empty fields; every malformed shape raises; pack is injective on the cases where
naive concatenation would collide (e.g. (b"ab", b"c") vs (b"a", b"bc")).
