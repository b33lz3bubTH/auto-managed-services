import logging
from dataclasses import dataclass

from app.interfaces.key_manager import KeyManager
from app.interfaces.secret_repository import SecretRepository

logger = logging.getLogger(__name__)


@dataclass
class RewrapResult:
    total: int
    rewrapped: int
    failed: int


class RotationService:
    """Handles key rotation and DEK re-wrapping.

    Rotation flow:
      1. rotate_key()    — creates a new key version in Vault
      2. rewrap_deks()   — re-encrypts all DEKs under new version (plaintext never leaves Vault)
      3. revoke_old()    — sets min_decryption_version to block old versions
    """

    def __init__(self, key_manager: KeyManager, repo: SecretRepository) -> None:
        self._key_manager = key_manager
        self._repo = repo

    async def rotate_key(self, tenant_id: str) -> int:
        return await self._key_manager.rotate_key(tenant_id)

    async def rewrap_deks(self, tenant_id: str, batch_size: int = 500) -> RewrapResult:
        """Re-wrap all DEKs for a tenant in batches. Idempotent — safe to re-run."""
        total = self._repo.count_by_tenant(tenant_id)
        rewrapped = 0
        failed = 0
        offset = 0

        while offset < total:
            records = self._repo.list_by_tenant(tenant_id, offset=offset, limit=batch_size)
            if not records:
                break

            for record in records:
                try:
                    # Vault rewrap: old-version ciphertext → new-version ciphertext
                    # The DEK plaintext NEVER leaves Vault during this operation
                    new_wrapped = await self._key_manager.rewrap_dek(tenant_id, record.encrypted_dek)
                    self._repo.update_wrapped_dek(record.id, new_wrapped)
                    rewrapped += 1
                except Exception:
                    logger.exception("Failed to rewrap DEK for secret=%s tenant=%s", record.id, tenant_id)
                    failed += 1

            offset += batch_size
            logger.info(
                "Rewrap progress tenant=%s: %d/%d (failed=%d)", tenant_id, rewrapped, total, failed
            )

        return RewrapResult(total=total, rewrapped=rewrapped, failed=failed)

    async def revoke_old_versions(self, tenant_id: str, min_version: int) -> None:
        """Set minimum decryption version — old key versions become permanently unusable.
        Only call this AFTER rewrap_deks completes with zero failures.
        """
        await self._key_manager.update_min_decryption_version(tenant_id, min_version)
        logger.info("Revoked key versions < %d for tenant=%s", min_version, tenant_id)
