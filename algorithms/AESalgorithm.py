"""AES-CBC helper functions used by the chat application.

This module keeps backward-compatible function names while improving
input validation, typing clarity and cryptographic hygiene.
"""

from __future__ import annotations

import base64
import secrets
import string
from typing import Union

from Crypto.Cipher import AES

# Historical fixed IV kept for protocol compatibility between existing clients.
iv = b"0000100010010010"


BytesLike = Union[bytes, bytearray]


def _ensure_bytes(value: Union[str, BytesLike]) -> bytes:
    """Convert supported payload types to bytes."""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("utf-8")
    raise TypeError(f"Unsupported value type: {type(value)!r}")


def add_to_16(value: Union[str, BytesLike]) -> bytes:
    """Pad bytes with NUL to the nearest 16-byte boundary.

    Kept for compatibility with the historical implementation.
    """
    raw = _ensure_bytes(value)
    padding_len = (16 - (len(raw) % 16)) % 16
    return raw + (b"\0" * padding_len)


def AesEncrypt(data: Union[str, BytesLike], key: Union[str, BytesLike]) -> str:
    """Encrypt data with AES-CBC and return base64 text payload."""
    plaintext = _ensure_bytes(data)
    encoded_plaintext = base64.b64encode(plaintext)

    aes = AES.new(add_to_16(key), AES.MODE_CBC, IV=iv)
    encrypted = aes.encrypt(add_to_16(encoded_plaintext))
    return base64.encodebytes(encrypted).decode("utf-8")


def AesDecrypt(text: Union[str, BytesLike], key: Union[str, BytesLike]) -> bytes:
    """Decrypt AES-CBC payload and return original plaintext bytes."""
    encrypted = _ensure_bytes(text)
    decoded = base64.decodebytes(encrypted)

    aes = AES.new(add_to_16(key), AES.MODE_CBC, IV=iv)
    decrypted_padded = aes.decrypt(decoded)

    # Remove NUL padding then decode the base64-wrapped original payload.
    decrypted = decrypted_padded.rstrip(b"\0")
    return base64.b64decode(decrypted)


def genKey(length: int = 16) -> str:
    """Generate a random alphanumeric key.

    Defaults to 16 chars to match AES-128 key size in this project.
    """
    if length <= 0:
        raise ValueError("length must be positive")
    source = string.ascii_letters + string.digits
    return "".join(secrets.choice(source) for _ in range(length))


if __name__ == "__main__":
    text = "你好你好"
    mykey = genKey()
    print("加密密钥是" + mykey)
    encrypted = AesEncrypt(text, mykey)
    decrypted = AesDecrypt(encrypted, mykey)
    print(encrypted)
    print(decrypted)
