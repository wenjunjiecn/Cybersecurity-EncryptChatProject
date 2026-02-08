"""RSA encryption/signature helpers."""

from __future__ import annotations

import base64
from typing import Union

from Crypto.Cipher import PKCS1_v1_5 as CipherPKCS1v15
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5 as SignaturePKCS1v15

BytesLike = Union[bytes, bytearray]


def _to_bytes(value: Union[str, BytesLike]) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("utf-8")
    raise TypeError(f"Unsupported value type: {type(value)!r}")


def _import_key(key: Union[str, BytesLike]):
    return RSA.import_key(_to_bytes(key))


def RsaEncrypt(message: Union[str, BytesLike], key: Union[str, BytesLike]) -> bytes:
    """Encrypt plaintext using RSA public key, returning base64 bytes."""
    rsa_key = _import_key(key)
    cipher = CipherPKCS1v15.new(rsa_key)
    cipher_text = cipher.encrypt(_to_bytes(message))
    return base64.b64encode(cipher_text)


def RsaDecrypt(encrypt_text: Union[str, BytesLike], key: Union[str, BytesLike]) -> bytes:
    """Decrypt RSA ciphertext (base64 text/bytes), returning plaintext bytes."""
    rsa_key = _import_key(key)
    cipher = CipherPKCS1v15.new(rsa_key)

    encrypted_bytes = _to_bytes(encrypt_text)
    try:
        encrypted_bytes = base64.b64decode(encrypted_bytes)
    except Exception as exc:  # noqa: BLE001 - preserve behavior with clearer error
        raise ValueError("Invalid RSA ciphertext: expected base64 input") from exc

    sentinel = b""
    plain = cipher.decrypt(encrypted_bytes, sentinel)
    if plain == sentinel:
        raise ValueError("RSA decryption failed")
    return plain


def RsaSignal(message: Union[str, BytesLike], key: Union[str, BytesLike]) -> bytes:
    """Sign message and return base64 signature bytes."""
    rsa_key = _import_key(key)
    signer = SignaturePKCS1v15.new(rsa_key)

    digest = SHA.new()
    digest.update(_to_bytes(message))
    signature = signer.sign(digest)
    return base64.b64encode(signature)


def VerRsaSignal(
    message: Union[str, BytesLike],
    signature: Union[str, BytesLike],
    key: Union[str, BytesLike],
) -> bool:
    """Verify base64 signature for message with RSA public key."""
    rsa_key = _import_key(key)
    verifier = SignaturePKCS1v15.new(rsa_key)

    digest = SHA.new()
    digest.update(_to_bytes(message))

    signature_bytes = base64.b64decode(_to_bytes(signature))
    return verifier.verify(digest, signature_bytes)
