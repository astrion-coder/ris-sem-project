"""The searchable index of one outsourced item (Sec. IV-D, IV-E, Fig. 6).

Outsource step O1 builds Ct = Enc(dsk, (rho, v, sig_C)) with v = PRF(dsk, rho) and
sig_C = Sign(sk_u, (rho, v, C)). Retrieve steps R2 (at S_i) and R3 (at U) run the same check on
it: (rho, v, sig_C) = Dec(dsk, Ct), Ver(pk_u, (rho, v, C), sig_C), and v == PRF(dsk, rho).
"""

import hmac
from dataclasses import dataclass
from enum import Enum, auto

from .params import Lattice
from .parties.types import StoredItem
from .primitives.encoding import bytes_int, int_bytes, pack, unpack
from .primitives.prf import prf
from .primitives.sampling import uniform_zq
from .primitives.signature import sign, verify
from .primitives.symmetric import aes_key, decrypt, encrypt

RHO_SIZE = 4
"""Bytes of rho in Z_q on the wire (q < 2^32)."""


class ScanOutcome(Enum):
    """Where the check of one stored (Ct, C, i) under one dsk stopped."""

    DECRYPT_FAILED = auto()
    """Dec(dsk, Ct) failed: Ct was made under another keyword's or another user's dsk."""
    MALFORMED = auto()
    """Ct decrypted, but its plaintext is not an encoded triple (rho, v, sig_C)."""
    SIGNATURE_INVALID = auto()
    """Ver(pk_u, (rho, v, C), sig_C) failed."""
    PRF_MISMATCH = auto()
    """sig_C verified, but v != PRF(dsk, rho)."""
    MATCH = auto()
    """Every check passed: the item belongs to the queried keyword."""


@dataclass(frozen=True, slots=True, kw_only=True)
class ItemScan:
    """The check of one item. A field is None exactly when the step that produces it did not run."""

    item_id: int
    outcome: ScanOutcome
    rho: int | None = None
    v: bytes | None = None
    """v as stored in Ct."""
    v_recomputed: bytes | None = None
    """PRF(dsk, rho), computed only after sig_C verified."""
    sig_c: bytes | None = None


def build_item(lattice: Lattice, sk_u: bytes, k_enc: bytes, dsk: bytes, data: bytes, item_id: int) -> StoredItem:
    """O1 without sig_Ct: rho <- Z_q, v = PRF(dsk, rho), C = Enc(K_u, d),
    sig_C = Sign(sk_u, (rho, v, C)), Ct = Enc(dsk, (rho, v, sig_C)).

    k_enc is the AES key for C derived from K_u.
    """
    rho = int_bytes(uniform_zq(lattice.ring.q), RHO_SIZE)
    v = _v(lattice, dsk, rho)
    data_ct = encrypt(k_enc, data)
    sig_c = sign(sk_u, pack(rho, v, data_ct))
    return StoredItem(index_ct=encrypt(aes_key(dsk), pack(rho, v, sig_c)), data_ct=data_ct, item_id=item_id)


def scan_item(lattice: Lattice, pk_u: bytes, dsk: bytes, item: StoredItem) -> ItemScan:
    """The R2 / R3 check of item under dsk, stopping at the first step that fails."""
    plaintext = decrypt(aes_key(dsk), item.index_ct)
    if plaintext is None:
        return ItemScan(item_id=item.item_id, outcome=ScanOutcome.DECRYPT_FAILED)
    try:
        rho, v, sig_c = unpack(plaintext, 3)
    except ValueError:
        return ItemScan(item_id=item.item_id, outcome=ScanOutcome.MALFORMED)
    if not verify(pk_u, pack(rho, v, item.data_ct), sig_c):
        return ItemScan(
            item_id=item.item_id, outcome=ScanOutcome.SIGNATURE_INVALID, rho=bytes_int(rho), v=v, sig_c=sig_c
        )
    v_recomputed = _v(lattice, dsk, rho)
    return ItemScan(
        item_id=item.item_id,
        outcome=ScanOutcome.MATCH if hmac.compare_digest(v, v_recomputed) else ScanOutcome.PRF_MISMATCH,
        rho=bytes_int(rho),
        v=v,
        v_recomputed=v_recomputed,
        sig_c=sig_c,
    )


def _v(lattice: Lattice, dsk: bytes, rho: bytes) -> bytes:
    """v = PRF(dsk, rho) for rho encoded in RHO_SIZE bytes."""
    return prf(lattice.prf, dsk, b"QPASE/v/" + rho)
