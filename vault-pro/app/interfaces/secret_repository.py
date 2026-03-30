from abc import ABC, abstractmethod

from app.models.domain import SecretRecord


class SecretRepository(ABC):
    """Storage abstraction for encrypted secret records."""

    @abstractmethod
    def save(self, record: SecretRecord) -> None:
        """Persist a new secret record."""

    @abstractmethod
    def get_by_id(self, tenant_id: str, secret_id: str) -> SecretRecord | None:
        """Retrieve a single record by tenant and secret ID."""

    @abstractmethod
    def list_by_tenant(self, tenant_id: str, offset: int = 0, limit: int = 500) -> list[SecretRecord]:
        """List records for a tenant in pages — used during DEK re-wrapping."""

    @abstractmethod
    def update_wrapped_dek(self, secret_id: str, new_wrapped_dek: str) -> None:
        """Update only the wrapped DEK on a record (used during key rotation)."""

    @abstractmethod
    def count_by_tenant(self, tenant_id: str) -> int:
        """Total number of records for a tenant."""
