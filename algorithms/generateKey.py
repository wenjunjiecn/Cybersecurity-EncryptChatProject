"""RSA key generation utilities."""

from __future__ import annotations

from pathlib import Path
from typing import Tuple

from Crypto.PublicKey import RSA


def generateMyKey(prefix: str, bits: int = 2048) -> Tuple[bytes, bytes]:
    """Generate RSA keypair and write to `<prefix>private.pem/public.pem`."""
    if bits < 1024:
        raise ValueError("bits must be >= 1024")

    key = RSA.generate(bits)
    private_key = key.export_key("PEM")
    public_key = key.publickey().export_key("PEM")

    private_path = Path(f"{prefix}private.pem")
    public_path = Path(f"{prefix}public.pem")
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)

    private_path.write_bytes(private_key)
    public_path.write_bytes(public_key)

    return private_key, public_key
