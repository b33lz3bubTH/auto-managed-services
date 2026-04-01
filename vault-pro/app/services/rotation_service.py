import logging
import time
from dataclasses import dataclass

from app.interfaces.key_manager import KeyManager
from app.interfaces.secret_repository import SecretRepository

logger = logging.getLogger(__name__)


@dataclass
class RewrapResult:
    total: int
    rewrapped: int
    failed: int


@dataclass
class FullRotateResult:
    tenant_id: str
    old_version: int
    new_version: int
    total_records: int
    rewrapped: int
    failed: int
    old_versions_revoked: bool
    elapsed_seconds: float


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

    async def full_rotate(
        self,
        tenant_id: str,
        batch_size: int = 500,
        revoke_old: bool = True,
    ) -> FullRotateResult:
        """Enterprise rotation: rotate key + rewrap all DEKs + revoke old versions.

        This is the single-call rotation that handles everything internally in
        batches so callers don't need to manage the multi-step flow.
        """
        t0 = time.monotonic()

        # 1. Snapshot current version
        info_before = await self._key_manager.get_key_info(tenant_id)
        old_version = info_before.latest_version
        logger.info(
            "Full rotation started tenant=%s current_version=%d total_records=%d",
            tenant_id, old_version, self._repo.count_by_tenant(tenant_id),
        )

        # 2. Rotate — creates new key version in Vault
        new_version = await self._key_manager.rotate_key(tenant_id)
        logger.info("Key rotated tenant=%s old_version=%d new_version=%d", tenant_id, old_version, new_version)

        # 3. Rewrap all DEKs under the new version (batched internally)
        rewrap = await self.rewrap_deks(tenant_id, batch_size=batch_size)

        # 4. Revoke old versions only if ALL DEKs rewrapped successfully
        revoked = False
        if revoke_old and rewrap.failed == 0:
            await self._key_manager.update_min_decryption_version(tenant_id, new_version)
            revoked = True
            logger.info(
                "Old key versions revoked tenant=%s min_decryption_version=%d", tenant_id, new_version,
            )
        elif rewrap.failed > 0:
            logger.warning(
                "Skipping revocation tenant=%s — %d DEKs failed rewrap, old versions still needed",
                tenant_id, rewrap.failed,
            )

        elapsed = time.monotonic() - t0
        logger.info(
            "Full rotation complete tenant=%s new_version=%d rewrapped=%d/%d failed=%d revoked=%s elapsed=%.2fs",
            tenant_id, new_version, rewrap.rewrapped, rewrap.total, rewrap.failed, revoked, elapsed,
        )

        return FullRotateResult(
            tenant_id=tenant_id,
            old_version=old_version,
            new_version=new_version,
            total_records=rewrap.total,
            rewrapped=rewrap.rewrapped,
            failed=rewrap.failed,
            old_versions_revoked=revoked,
            elapsed_seconds=round(elapsed, 3),
        )

    async def revoke_old_versions(self, tenant_id: str, min_version: int) -> None:
        """Set minimum decryption version — old key versions become permanently unusable.
        Only call this AFTER rewrap_deks completes with zero failures.
        """
        await self._key_manager.update_min_decryption_version(tenant_id, min_version)
        logger.info("Revoked key versions < %d for tenant=%s", min_version, tenant_id)
