import json
import os
from pathlib import Path
from typing import Any, List

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class VaultInitializationError(RuntimeError):
    """Raised when vault initialization fails."""


class VaultAuthenticationError(RuntimeError):
    """Raised when authentication to the vault fails."""


class VaultManager:
    """Handle encrypted data storage for the application."""

    def __init__(self, storage_dir: Path | None = None) -> None:
        self.storage_dir = storage_dir or Path.cwd()
        self.config_path = self.storage_dir / "vault_config.json"
        self.data_path = self.storage_dir / "vault.dat"
        self._key: bytes | None = None
        self._data: List[dict[str, Any]] = []

    # ---------------------------
    # Properties and state checks
    # ---------------------------
    @property
    def data(self) -> List[dict[str, Any]]:
        return self._data

    def is_initialized(self) -> bool:
        return self.config_path.exists() and self.data_path.exists()

    # ---------------------------
    # Key derivation and encryption helpers
    # ---------------------------
    def _derive_key(self, password: str, salt: bytes, iterations: int) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
        )
        return base64_urlsafe(kdf.derive(password.encode("utf-8")))

    def _fernet(self) -> Fernet:
        if self._key is None:
            raise VaultInitializationError("Encryption key is not available. Authenticate first.")
        return Fernet(self._key)

    def _load_config(self) -> dict[str, Any]:
        if not self.config_path.exists():
            raise VaultInitializationError("Vault configuration is missing. Initialize the vault first.")
        with self.config_path.open("r", encoding="utf-8") as fh:
            return json.load(fh)

    def _save_config(self, config: dict[str, Any]) -> None:
        with self.config_path.open("w", encoding="utf-8") as fh:
            json.dump(config, fh)

    # ---------------------------
    # Public API
    # ---------------------------
    def initialize(self, password: str, iterations: int = 390_000) -> None:
        if self.is_initialized():
            raise VaultInitializationError("Vault has already been initialized.")
        salt = os.urandom(16)
        key = self._derive_key(password, salt, iterations)
        self._key = key
        self._data = []
        config = {"salt": salt.hex(), "iterations": iterations}
        self._save_config(config)
        self._write_data()

    def authenticate(self, password: str) -> None:
        config = self._load_config()
        salt = bytes.fromhex(config["salt"])
        iterations = config.get("iterations", 390_000)
        key = self._derive_key(password, salt, iterations)
        fernet = Fernet(key)
        try:
            encrypted = self.data_path.read_bytes()
        except FileNotFoundError as exc:
            raise VaultInitializationError("Encrypted vault is missing. Initialize again.") from exc
        try:
            decrypted = fernet.decrypt(encrypted)
        except InvalidToken as exc:
            raise VaultAuthenticationError("Неверный пароль.") from exc
        self._key = key
        self._data = json.loads(decrypted.decode("utf-8"))

    def add_entry(self, entry: dict[str, Any]) -> None:
        self._data.append(entry)
        self._write_data()

    def update_entry(self, index: int, entry: dict[str, Any]) -> None:
        self._data[index] = entry
        self._write_data()

    def delete_entry(self, index: int) -> None:
        del self._data[index]
        self._write_data()

    def export_to(self, destination: Path) -> None:
        destination.write_text(json.dumps(self._data, ensure_ascii=False, indent=2), encoding="utf-8")

    # ---------------------------
    # Internal helpers
    # ---------------------------
    def _write_data(self) -> None:
        serialized = json.dumps(self._data, ensure_ascii=False).encode("utf-8")
        encrypted = self._fernet().encrypt(serialized)
        self.data_path.write_bytes(encrypted)


def base64_urlsafe(raw_key: bytes) -> bytes:
    """Convert raw key bytes to a value accepted by Fernet."""
    import base64

    return base64.urlsafe_b64encode(raw_key)

