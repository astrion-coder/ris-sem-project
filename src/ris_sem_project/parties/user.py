"""The QPASE user U (Section III-A): the data owner.

U remembers only (ID_u, psw_u). All long-term key material (K_u, pk_u, sk_u)
is re-derived from the password at every Login through the TOPRF; nothing is
stored on the device.

Each protocol phase is split into the steps U performs locally between
message exchanges, so the caller (e.g. a notebook) moves the messages between
parties and can show every one of them.
"""

from abc import abstractmethod
from collections.abc import Sequence

from .base import Party
from .types import (
    Keyword,
    LoginProof,
    OutsourceRequest,
    PublicParams,
    RegisterKeyMessage,
    RetrieveRequest,
    RetrieveResponse,
    ServerID,
    SessionID,
    TOPRFRequest,
    TOPRFResponse,
    UserID,
)


class User(Party):
    """Abstract QPASE user. Implements RegisterU, LoginU, OutsourceU, RetrieveU."""

    def __init__(self, pp: PublicParams, user_id: UserID, password: str) -> None:
        super().__init__(pp)
        self.user_id = user_id
        self.password = password

    # ---- password encoding ------------------------------------------------

    @abstractmethod
    def encode_password(self, password: str) -> bytes:
        """Convert psw_u to the binary input x = (x_1, ..., x_L) in {0,1}^L."""

    # ---- TOPRF client (shared by Register step 1 and Login step L1) -------

    @abstractmethod
    def toprf_request(self, server_ids: Sequence[ServerID]) -> dict[ServerID, TOPRFRequest]:
        """Blind x and build one TOPRF request per contacted server."""

    @abstractmethod
    def toprf_finalize(self, responses: Sequence[TOPRFResponse]) -> bytes:
        """Unblind and Lagrange-combine >= t responses into K_u = F_K(x)."""

    # ---- Register (Section IV-B) ------------------------------------------

    @abstractmethod
    def register_keygen(self, k_u: bytes) -> RegisterKeyMessage:
        """Register step 2: (pk_u, sk_u) <- Gen(1^kappa, K_u); send pk_u to every S_i."""

    # ---- Login (Section IV-C) ---------------------------------------------

    @abstractmethod
    def login_verify(self, k_u: bytes, stored_pk: bytes, session_id: SessionID) -> LoginProof:
        """Login step L2: re-derive (pk_u', sk_u') from K_u and check pk_u' == pk_u.

        On success, sign (ID_u, sid) with sk_u'. On mismatch the password was
        wrong; raise :class:`ProtocolAbort` so the caller can prompt again.
        """

    # ---- Outsource (Section IV-D) -----------------------------------------

    @abstractmethod
    def outsource(self, keyword: Keyword, data: bytes, item_id: int) -> OutsourceRequest:
        """Outsource step O1.

        dsk <- HKDF(K_u, w), rho <- Z_q, v <- PRF(dsk, rho),
        C <- Enc(K_u, d), sig_C <- Sign(sk_u, (rho, v, C)),
        Ct <- Enc(dsk, (rho, v, sig_C)), sig_Ct <- Sign(sk_u, (Ct, C, i)).
        """

    # ---- Retrieve (Section IV-E) ------------------------------------------

    @abstractmethod
    def retrieve_request(self, keywords: Sequence[Keyword]) -> RetrieveRequest:
        """Retrieve step R1: dsk <- HKDF(K_u, w) and sig_dsk <- Sign(sk_u, dsk)."""

    @abstractmethod
    def retrieve_finalize(
        self, keywords: Sequence[Keyword], responses: Sequence[RetrieveResponse]
    ) -> list[bytes]:
        """Retrieve step R3: re-check each (rho, v, sig_C) in Ct and decrypt C to d."""
