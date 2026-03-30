from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True)
class KeyInfo:
    name: str
    latest_version: int
    min_decryption_version: int
    supports_encryption: bool


class KeyManager(ABC):
    """Abstraction over key lifecycle — wrapping, unwrapping, rotation, revocation.
    The application NEVER sees raw KEKs; only wrapped/unwrapped DEKs flow through here.
    """

    @abstractmethod
    async def provision_key(self, tenant_id: str) -> None:
        """Create a new isolated transit key for a tenant."""

    @abstractmethod
    async def wrap_dek(self, tenant_id: str, dek: bytes) -> str:
        """Encrypt a DEK using the tenant's transit key. Returns opaque ciphertext."""

    @abstractmethod
    async def unwrap_dek(self, tenant_id: str, wrapped_dek: str) -> bytes:
        """Decrypt a wrapped DEK back to raw bytes."""

    @abstractmethod
    async def rewrap_dek(self, tenant_id: str, wrapped_dek: str) -> str:
        """Re-encrypt a DEK under the latest key version without exposing plaintext."""

    @abstractmethod
    async def rotate_key(self, tenant_id: str) -> int:
        """Rotate the tenant's transit key. Returns the new version number."""

    @abstractmethod
    async def update_min_decryption_version(self, tenant_id: str, version: int) -> None:
        """Set the minimum decryption version, effectively revoking older key versions."""

    @abstractmethod
    async def get_key_info(self, tenant_id: str) -> KeyInfo:
        """Return metadata about a tenant's key."""

    @abstractmethod
    async def delete_key(self, tenant_id: str) -> None:
        """Permanently destroy a tenant's key. Irreversible — all data becomes unrecoverable."""
