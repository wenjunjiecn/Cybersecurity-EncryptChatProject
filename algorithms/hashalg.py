"""Hash helpers."""

from __future__ import annotations

import hashlib
from typing import Union


BytesLike = Union[bytes, bytearray]


def hash_sha256(datas: Union[str, BytesLike]) -> str:
    """Return SHA-256 hex digest for str/bytes input."""
    if isinstance(datas, str):
        payload = datas.encode("utf-8")
    elif isinstance(datas, (bytes, bytearray)):
        payload = bytes(datas)
    else:
        raise TypeError(f"Unsupported data type: {type(datas)!r}")

    return hashlib.sha256(payload).hexdigest()


if __name__ == "__main__":
    print(hash_sha256("你好"))
