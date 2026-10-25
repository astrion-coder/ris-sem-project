"""The concrete QPASE server S_i (Sec. IV-A to IV-E, Definition 12, Fig. 5-6).

S_i holds its DKG key share k_i and pk_i = a k_i + 2e_i, one UserRecord per registered user,
and at most M = capacity outsourced (Ct, C, i) per user. Outsource and Retrieve are authorized
by sig_Ct and sig_dsk under pk_u, as the paper prints them: Retrieve reaches all N servers,
while Login reaches only t.

Server key update (Sec. IV-F, plan decision 6): every S_j deals F_ji = [F]_j(i) for a fresh
zero-constant polynomial [F]_j of degree t - 1, committing to its coefficients with the linear
hash H. S_i checks each share, adds sum_j F_ji to k_i, and K = sum_i lambda_i k_i is unchanged.
"""

import hmac
import os
from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum, auto

import numpy as np

from ..index import ItemScan, ScanOutcome, scan_item
from ..params import Lattice
from ..primitives import symmetric, toprf
from ..primitives.encoding import int_bytes, pack
from ..primitives.linear_hash import linear_hash
from ..primitives.ring import Poly, Ring
from ..primitives.sampling import uniform
from ..primitives.secret_sharing import genkey, genshare
from ..primitives.signature import SEED_SIZE, keypair_from_seed, sign, verify
from .server import Server
from .types import (
    DKGShare,
    KeyUpdateShare,
    LoginProof,
    OutsourceRequest,
    ProtocolAbort,
    PublicParams,
    RegisterKeyMessage,
    RetrieveRequest,
    RetrieveResponse,
    ServerID,
    SessionID,
    TOPRFRequest,
    TOPRFResponse,
    UserID,
    UserRecord,
)

SESSION_ID_SIZE = 32


@dataclass(frozen=True, slots=True, kw_only=True)
class ServerKey:
    """S_i's TOPRF key share k_i from Genkey and its public key pk_i = a k_i + 2e_i."""

    k_i: Poly
    pk_i: Poly


@dataclass(frozen=True, slots=True, kw_only=True)
class PeerLink:
    """What S_i holds about a server S_j (S_i itself included) for key update.

    E(i, .) of step 3 stands in for the secure server-to-server channel that Sec. III-A assumes:
    AES-256-GCM under channel_key, a 32-byte key shared by the two ends. It is not a scheme
    contribution. protocol.setup_servers generates the keys and hands them out.
    """

    verification_key: bytes
    """pk_j of S_j's ML-DSA-44 signing key, which signs S_j's key update shares."""
    channel_key: bytes


class ShareOutcome(Enum):
    """Where step 4's check of one received key update share stopped."""

    MALFORMED = auto()
    """Not addressed to this server, from an unknown sender, an epoch outside [0, 2^32), the wrong number
    of commitments, or a commitment or share that is not n coefficients below q."""
    BAD_SIGNATURE = auto()
    """Ver(pk_j, (j, omega, h, E(i, F_ji)), sig_j) failed."""
    WRONG_EPOCH = auto()
    """The signature verified, but omega is not this server's current epoch (a replay)."""
    DECRYPT_FAILED = auto()
    """The ciphertext E(i, F_ji) does not decrypt under the channel key."""
    COMMITMENT_MISMATCH = auto()
    """F_ji decrypted, but H(F_ji) != sum_k i^k h_k."""
    ACCEPTED = auto()
    """Every check passed."""


@dataclass(frozen=True, slots=True, kw_only=True)
class ShareCheck:
    """Step 4 for the share S_j sent to S_i. A field is None exactly when the step that produces it did not run."""

    sender: ServerID
    receiver: ServerID
    outcome: ShareOutcome
    recomputed: bytes | None = None
    """H(F_ji), computed from the decrypted share."""
    committed: bytes | None = None
    """sum_{k=1}^{t-1} i^k h_k, computed from the commitments."""


@dataclass(frozen=True, slots=True, kw_only=True)
class RetrieveScan:
    """R2 at one S_i: the check of every item it stores for the user, and the list L_i it returns."""

    server_id: ServerID
    items: tuple[ItemScan, ...]
    response: RetrieveResponse


class QPASEServer(Server):
    """S_i for the lattice TOPRF, ML-DSA-44 and AES-256-GCM. Single-keyword search only."""

    def __init__(self, pp: PublicParams, server_id: ServerID, capacity: int = 1000) -> None:
        """capacity is M, the storage slots S_i provides per user."""
        super().__init__(pp, server_id)
        self._lattice = Lattice.from_pp(pp)
        if not 1 <= server_id <= pp.N:
            raise ValueError(f"server id must be in [1, {pp.N}], got {server_id}")
        if capacity < 1:
            raise ValueError(f"capacity must be positive, got {capacity}")
        self.capacity = capacity
        self.key: ServerKey | None = None
        """None until the DKG has run."""
        self._sessions: dict[UserID, SessionID] = {}
        self.verification_key, self._signing_key = keypair_from_seed(os.urandom(SEED_SIZE))
        """(pk_i, sk_i) of this server's ML-DSA-44 key pair, which signs its key update shares."""
        self.peers: dict[ServerID, PeerLink] = {}
        """The link to each server S_j, S_i itself included, that key update can use."""

    def add_peer(self, peer_id: ServerID, link: PeerLink) -> None:
        """Record, or replace, the link to server S_j."""
        if not 1 <= peer_id <= self.pp.N:
            raise ValueError(f"peer id must be in [1, {self.pp.N}], got {peer_id}")
        if len(link.channel_key) != symmetric.KEY_SIZE:
            raise ValueError(f"channel key must be {symmetric.KEY_SIZE} bytes, got {len(link.channel_key)}")
        self.peers[peer_id] = link

    def dkg_genshare(self) -> dict[ServerID, DKGShare]:
        """Genshare: [s_i]_j = f_i(j) for every S_j, this server included."""
        ring = self._lattice.ring
        shares = genshare(ring, self.pp.t, range(1, self.pp.N + 1), self.pp.sigma)
        return {
            j: DKGShare(sender=self.server_id, receiver=j, share=ring.to_bytes(share)) for j, share in shares.items()
        }

    def dkg_genkey(self, shares: Sequence[DKGShare]) -> None:
        """Genkey: k_i = sum_j [s_j]_i over one share from each of the N servers, then pk_i."""
        if sorted(s.sender for s in shares) != list(range(1, self.pp.N + 1)):
            raise ProtocolAbort(f"need exactly one DKG share from each of the {self.pp.N} servers")
        if any(s.receiver != self.server_id for s in shares):
            raise ProtocolAbort(f"a DKG share is not addressed to S_{self.server_id}")
        ring = self._lattice.ring
        try:
            k_i = genkey(ring, [ring.from_bytes(s.share, (ring.n,)) for s in shares])
        except ValueError as error:
            raise ProtocolAbort(f"malformed DKG share: {error}") from error
        self.key = ServerKey(k_i=k_i, pk_i=toprf.server_public_key(ring, self._lattice.a, k_i, self.pp.sigma))

    def toprf_evaluate(self, request: TOPRFRequest) -> TOPRFResponse:
        """b_{k_i} = b k_i + 2e'_i.

        Login L1 (the user has a pk_u): abort if mu_u >= mu, then mu_u += 1, and return pk_u and sigma.
        Register step 1 (no pk_u yet) is not counted.
        """
        if self.key is None:
            raise ProtocolAbort(f"S_{self.server_id} has no key share: run the DKG first")
        record = self.users.get(request.user_id)
        if record is None:
            raise ProtocolAbort(f"unknown user {request.user_id!r}")
        ring = self._lattice.ring
        try:
            b = ring.from_bytes(request.blinded_input, (ring.ell, ring.n))
        except ValueError as error:
            raise ProtocolAbort(f"malformed blinded input: {error}") from error
        if record.user_pk is not None:
            if record.fail_count >= self.pp.mu:
                raise ProtocolAbort(f"mu_u = {record.fail_count} reached the limit mu = {self.pp.mu}")
            record.fail_count += 1
        return TOPRFResponse(
            server_id=self.server_id,
            evaluation=ring.to_bytes(toprf.evaluate(ring, b, self.key.k_i, self.pp.sigma)),
            server_pk=ring.to_bytes(self.key.pk_i),
            user_pk=record.user_pk,
            hint=record.hint,
        )

    def register_user(self, user_id: UserID) -> None:
        """Register step 1: reject a duplicate ID_u, else store it."""
        if user_id in self.users:
            raise ProtocolAbort(f"{user_id!r} is already registered")
        self.users[user_id] = UserRecord(user_id=user_id)

    def register_store_key(self, message: RegisterKeyMessage) -> None:
        """Register step 3: store pk_u and sigma, and set mu_u = 0."""
        record = self.users.get(message.user_id)
        if record is None or record.user_pk is not None:
            raise ProtocolAbort(f"{message.user_id!r} is not waiting for Register step 3")
        try:
            self._lattice.ring.unpack_bits(message.hint)
        except ValueError as error:
            raise ProtocolAbort(f"malformed hint: {error}") from error
        record.user_pk = message.user_pk
        record.hint = message.hint
        record.fail_count = 0

    def new_session(self, user_id: UserID) -> SessionID:
        """A fresh sid for L2. It replaces any sid still outstanding for this user."""
        self._registered(user_id)
        sid = os.urandom(SESSION_ID_SIZE)
        self._sessions[user_id] = sid
        return sid

    def login_verify(self, proof: LoginProof) -> bool:
        """L3: the outstanding sid is consumed; accept iff it matches and Ver(pk_u, (ID_u, sid), sig_u).

        On failure mu_u += 1.
        """
        record = self._registered(proof.user_id)
        sid = self._sessions.pop(proof.user_id, None)
        accepted = (
            sid is not None
            and hmac.compare_digest(sid, proof.session_id)
            and verify(record.user_pk, pack(proof.user_id.encode(), proof.session_id), proof.signature)
        )
        if not accepted:
            record.fail_count += 1
        return accepted

    def outsource_store(self, request: OutsourceRequest) -> bool:
        """O2: store (Ct, C, i) iff Ver(pk_u, (Ct, C, i), sig_Ct).

        An item with the same i is replaced and counts as the newest. When all M slots are full, the
        oldest item is evicted.
        """
        record = self._registered(request.user_id)
        item = request.item
        if not 0 <= item.item_id < 1 << 32:
            return False
        if not verify(record.user_pk, pack(item.index_ct, item.data_ct, int_bytes(item.item_id)), request.signature):
            return False
        kept = [stored for stored in self.storage.get(request.user_id, []) if stored.item_id != item.item_id]
        self.storage[request.user_id] = (kept + [item])[-self.capacity :]
        return True

    def retrieve_scan(self, request: RetrieveRequest) -> RetrieveScan:
        """R2: abort unless Ver(pk_u, dsk, sig_dsk); scan every stored item; L_i = the MATCH items."""
        record = self._registered(request.user_id)
        if not verify(record.user_pk, pack(*request.search_keys), request.signature):
            raise ProtocolAbort("sig_dsk does not verify under pk_u")
        if len(request.search_keys) != 1:
            raise ProtocolAbort(f"single-keyword queries only, got {len(request.search_keys)} search keys")
        (dsk,) = request.search_keys
        try:
            self._lattice.ring.unpack_bits(dsk)
        except ValueError as error:
            raise ProtocolAbort(f"malformed dsk: {error}") from error
        stored = self.storage.get(request.user_id, [])
        scans = tuple(scan_item(self._lattice, record.user_pk, dsk, item) for item in stored)
        matches = tuple(item for item, scan in zip(stored, scans) if scan.outcome is ScanOutcome.MATCH)
        return RetrieveScan(
            server_id=self.server_id, items=scans, response=RetrieveResponse(server_id=self.server_id, results=matches)
        )

    def retrieve_search(self, request: RetrieveRequest) -> RetrieveResponse:
        return self.retrieve_scan(request).response

    def key_update_shares(self) -> dict[ServerID, KeyUpdateShare]:
        """Steps 1-3: sample [F]_j(X) = sum_{k=1}^{t-1} alpha_k X^k with alpha_k <- R_q, then for every S_i
        (this server included) send F_ji = [F]_j(i) as E(i, F_ji) with h = {H(alpha_k)} and sig_j.
        """
        ring = self._lattice.ring
        alphas = [uniform(ring, (ring.n,)) for _ in range(self.pp.t - 1)]
        commitments = tuple(ring.to_bytes(linear_hash(ring, alpha)) for alpha in alphas)
        shares = {}
        for i in range(1, self.pp.N + 1):
            link = self.peers.get(i)
            if link is None:
                raise ProtocolAbort(f"S_{self.server_id} is not linked to S_{i}")
            encrypted = symmetric.encrypt(link.channel_key, ring.to_bytes(_zero_constant_eval(ring, alphas, i)))
            signed = _signed_bytes(self.server_id, self.epoch, commitments, encrypted)
            shares[i] = KeyUpdateShare(
                sender=self.server_id,
                receiver=i,
                epoch=self.epoch,
                commitments=commitments,
                encrypted_share=encrypted,
                signature=sign(self._signing_key, signed),
            )
        return shares

    def key_update_check(self, shares: Sequence[KeyUpdateShare]) -> tuple[ShareCheck, ...]:
        """Step 4's verdict on each share in turn, without changing any state."""
        return tuple(self._open_share(share)[0] for share in shares)

    def key_update_apply(self, shares: Sequence[KeyUpdateShare]) -> None:
        """Steps 4-5: one share from each of the N servers, each checked by key_update_check, then
        k_i' = k_i + sum_j F_ji, pk_i' = a k_i' + 2e_i, mu_u = 0 for every user, and omega + 1.

        Any rejected share raises ProtocolAbort before anything changes.
        """
        if self.key is None:
            raise ProtocolAbort(f"S_{self.server_id} has no key share: run the DKG first")
        if sorted(share.sender for share in shares) != list(range(1, self.pp.N + 1)):
            raise ProtocolAbort(f"need exactly one key update share from each of the {self.pp.N} servers")
        ring = self._lattice.ring
        k_i = self.key.k_i
        for share in shares:
            check, f_ji = self._open_share(share)
            if f_ji is None:
                raise ProtocolAbort(f"key update share from S_{share.sender} rejected: {check.outcome.name}")
            k_i = (k_i + f_ji) % ring.q
        pk_i = toprf.server_public_key(ring, self._lattice.a, k_i, self.pp.sigma)
        self.key = ServerKey(k_i=k_i, pk_i=pk_i)
        for record in self.users.values():
            record.fail_count = 0
        self.epoch += 1

    def _open_share(self, share: KeyUpdateShare) -> tuple[ShareCheck, Poly | None]:
        """Step 4 for one share: its check, and F_ji only when the check ACCEPTED it."""
        ring = self._lattice.ring
        link = self.peers.get(share.sender)

        def check(outcome: ShareOutcome, **values: bytes) -> ShareCheck:
            return ShareCheck(sender=share.sender, receiver=share.receiver, outcome=outcome, **values)

        if (
            link is None
            or share.receiver != self.server_id
            or not 0 <= share.epoch < 1 << 32
            or len(share.commitments) != self.pp.t - 1
        ):
            return check(ShareOutcome.MALFORMED), None
        signed = _signed_bytes(share.sender, share.epoch, share.commitments, share.encrypted_share)
        if not verify(link.verification_key, signed, share.signature):
            return check(ShareOutcome.BAD_SIGNATURE), None
        if share.epoch != self.epoch:
            return check(ShareOutcome.WRONG_EPOCH), None
        plaintext = symmetric.decrypt(link.channel_key, share.encrypted_share)
        if plaintext is None:
            return check(ShareOutcome.DECRYPT_FAILED), None
        try:
            f_ji = ring.from_bytes(plaintext, (ring.n,))
            h = [ring.from_bytes(commitment, (ring.n,)) for commitment in share.commitments]
        except ValueError:
            return check(ShareOutcome.MALFORMED), None
        recomputed = ring.to_bytes(linear_hash(ring, f_ji))
        committed = ring.to_bytes(_zero_constant_eval(ring, h, self.server_id))
        if recomputed != committed:
            return check(ShareOutcome.COMMITMENT_MISMATCH, recomputed=recomputed, committed=committed), None
        return check(ShareOutcome.ACCEPTED, recomputed=recomputed, committed=committed), f_ji

    def _registered(self, user_id: UserID) -> UserRecord:
        """The record of a user who completed Register, else abort."""
        record = self.users.get(user_id)
        if record is None or record.user_pk is None:
            raise ProtocolAbort(f"{user_id!r} is not registered")
        return record


def _zero_constant_eval(ring: Ring, coefficients: Sequence[Poly], i: int) -> Poly:
    """sum_{k=1}^{len(coefficients)} i^k c_k mod q: a polynomial with constant term 0 evaluated at i."""
    total = np.zeros(ring.n, dtype=np.int64)
    for k, c in enumerate(coefficients, start=1):
        total = (total + pow(i, k, ring.q) * c) % ring.q
    return total


def _signed_bytes(sender: ServerID, epoch: int, commitments: Sequence[bytes], encrypted_share: bytes) -> bytes:
    """What sig_j covers: (j, omega, h, E(i, F_ji))."""
    return pack(int_bytes(sender), int_bytes(epoch), *commitments, encrypted_share)
