"""Deterministic wire encoding for tuples that are signed or encrypted.

Each field is a 4-byte big-endian length followed by its bytes, so distinct
tuples never encode to the same string.
"""

LEN_SIZE = 4


def pack(*fields: bytes) -> bytes:
    return b"".join(len(f).to_bytes(LEN_SIZE, "big") + f for f in fields)


def unpack(data: bytes, count: int) -> tuple[bytes, ...]:
    """Inverse of `pack`; ValueError unless `data` holds exactly `count` fields."""
    fields = []
    pos = 0
    for _ in range(count):
        if len(data) - pos < LEN_SIZE:
            raise ValueError("truncated length prefix")
        size = int.from_bytes(data[pos : pos + LEN_SIZE], "big")
        pos += LEN_SIZE
        if size > len(data) - pos:
            raise ValueError("field length exceeds data")
        fields.append(bytes(data[pos : pos + size]))
        pos += size
    if pos != len(data):
        raise ValueError("trailing bytes after last field")
    return tuple(fields)


def int_bytes(value: int, size: int = 4) -> bytes:
    return value.to_bytes(size, "big")


def bytes_int(data: bytes) -> int:
    return int.from_bytes(data, "big")
