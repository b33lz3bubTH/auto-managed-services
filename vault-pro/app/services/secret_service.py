import logging

from app.interfaces.key_manager import KeyManager
from app.interfaces.crypto_service import CryptoService
from app.interfaces.secret_repository import SecretRepository
from app.models.domain import SecretRecord

logger = logging.getLogger(__name__)


class SecretService:
    """Orchestrates envelope encryption: local AES for data, Vault for DEK wrapping."""

    def __init__(
        self,
        key_manager: KeyManager,
        crypto: CryptoService,
        repo: SecretRepository,
    ) -> None:
        self._key_manager = key_manager
        self._crypto = crypto
        self._repo = repo

    async def save(self, tenant_id: str, plaintext: str) -> str:
        # 1. Generate a per-record DEK
        dek = self._crypto.generate_dek()

        # 2. Encrypt payload locally — fast, no network round-trip for bulk data
        result = self._crypto.encrypt(plaintext, dek)

        # 3. Wrap DEK with tenant's Vault key — raw DEK never stored
        wrapped_dek = await self._key_manager.wrap_dek(tenant_id, dek)

        # 4. Persist only ciphertext + wrapped DEK
        record = SecretRecord(
            tenant_id=tenant_id,
            encrypted_payload=result.ciphertext_b64,
            encrypted_dek=wrapped_dek,
            nonce=result.nonce_b64,
        )
        self._repo.save(record)

        logger.info("Saved secret id=%s for tenant=%s", record.id, tenant_id)
        return record.id

    async def get(self, tenant_id: str, secret_id: str) -> str | None:
        record = self._repo.get_by_id(tenant_id, secret_id)
        if record is None:
            return None

        # 1. Unwrap DEK via Vault — Vault handles version selection automatically
        dek = await self._key_manager.unwrap_dek(tenant_id, record.encrypted_dek)

        # 2. Decrypt payload locally
        plaintext = self._crypto.decrypt(record.encrypted_payload, record.nonce, dek)

        logger.info("Retrieved secret id=%s for tenant=%s", secret_id, tenant_id)
        return plaintext

    def list_ids(self, tenant_id: str) -> tuple[list[str], int]:
        total = self._repo.count_by_tenant(tenant_id)
        records = self._repo.list_by_tenant(tenant_id, offset=0, limit=1000)
        return [r.id for r in records], total

    def delete(self, tenant_id: str, secret_id: str) -> bool:
        deleted = self._repo.delete(tenant_id, secret_id)
        if deleted:
            logger.info("Deleted secret id=%s for tenant=%s", secret_id, tenant_id)
        return deleted

    def delete_all_by_tenant(self, tenant_id: str) -> int:
        count = self._repo.delete_all_by_tenant(tenant_id)
        logger.info("Deleted %d secrets for tenant=%s", count, tenant_id)
        return count
