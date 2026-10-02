"""The QPASE adversary and the challenger of its security experiments.

Adversarial model (Section III-B.1): a quantum-capable A fully controls the
network and may corrupt at most t' < t of the N servers. It mounts
(1) offline password guessing, (2) online password guessing, and
(3) chosen-keyword attacks (Fig. 3). A interacts with honest parties only
through the BPR-model oracles, which the :class:`Challenger` exposes.
"""

from abc import ABC, abstractmethod
from collections.abc import Sequence
from typing import Any

from .base import Party
from .server import Server
from .types import Keyword, PublicParams, ServerID, UserID


class Challenger(ABC):
    """Runs a security experiment (Fig. 4) and answers A's oracle queries."""

    def __init__(self, pp: PublicParams) -> None:
        self.pp = pp

    # ---- BPR oracles (Section III-B.2) ------------------------------------

    @abstractmethod
    def execute(self, user_id: UserID, server_id: ServerID) -> list[Any]:
        """Execute(U^i, S^j): run an honest session; return its transcript (passive attack)."""

    @abstractmethod
    def send(self, instance: str, message: Any) -> Any:
        """Send(I, m): deliver m to instance I and return its response (active attack)."""

    @abstractmethod
    def reveal(self, instance: str) -> bytes:
        """Reveal(I): return the session key of instance I."""

    @abstractmethod
    def test(self, instance: str) -> bytes:
        """Test(I): real-or-random session key, depending on the hidden bit b. Allowed once."""

    @abstractmethod
    def corrupt(self, party: UserID | ServerID) -> Any:
        """Corrupt(I): psw_u for a user, the key share k_i for a server.

        Must refuse once t' servers are already corrupted.
        """

    # ---- IND-CKA oracle ---------------------------------------------------

    @abstractmethod
    def challenge(self, w0: Keyword, w1: Keyword) -> Any:
        """Challenge(b, sid, w): outsource under w_b and return the result to A."""

    # ---- outcome ----------------------------------------------------------

    @abstractmethod
    def adversary_wins(self, output: Any) -> bool:
        """Decide whether A's final output breaks the property being tested."""


class Adversary(Party):
    """Abstract quantum adversary A. Subclass once per attack in Fig. 3."""

    def __init__(self, pp: PublicParams) -> None:
        super().__init__(pp)
        self.corrupted: dict[ServerID, Server] = {}

    @abstractmethod
    def attack(self, challenger: Challenger) -> Any:
        """Run the attack against the challenger's oracles and return A's output
        (a password guess, a bit b', ...)."""


class PasswordGuessingAdversary(Adversary):
    """Common shape of the offline (1) and online (2) guessing attacks.

    Theorem 2 bounds the success of q_s online guesses by C' * q_s^{s'} + eps,
    with the password dictionary following Zipf's law.
    """

    @abstractmethod
    def guesses(self, dictionary: Sequence[str]) -> Sequence[str]:
        """Order candidate passwords, most likely first."""
