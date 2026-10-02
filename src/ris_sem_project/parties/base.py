"""Common base for every party in a QPASE run."""

from abc import ABC

from .types import PublicParams


class Party(ABC):
    """A participant that holds the public parameters pp from Setup."""

    def __init__(self, pp: PublicParams) -> None:
        self.pp = pp
