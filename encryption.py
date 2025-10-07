from __future__ import annotations

from base64 import urlsafe_b64encode
from typing import Final

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


PBKDF2_ITERATIONS: Final[int] = 390_000


def derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derive a Fernet-compatible key from a passphrase and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))


def encrypt_data(key: bytes, data: bytes) -> bytes:
    return Fernet(key).encrypt(data)


def decrypt_data(key: bytes, token: bytes) -> bytes:
    return Fernet(key).decrypt(token)
