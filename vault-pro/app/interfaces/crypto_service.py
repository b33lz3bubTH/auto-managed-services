from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True)
class EncryptionResult:
    ciphertext_b64: str
    nonce_b64: str


class CryptoService(ABC):
    """Local symmetric encryption — used for encrypting payloads with DEKs.
    Implementations must use authenticated encryption (e.g. AES-256-GCM).
    """

    @abstractmethod
    def generate_dek(self) -> bytes:
        """Generate a cryptographically random Data Encryption Key."""

    @abstractmethod
    def encrypt(self, plaintext: str, dek: bytes) -> EncryptionResult:
        """Encrypt plaintext with the given DEK. Returns ciphertext + nonce."""

    @abstractmethod
    def decrypt(self, ciphertext_b64: str, nonce_b64: str, dek: bytes) -> str:
        """Decrypt ciphertext using the DEK and nonce. Returns plaintext."""
