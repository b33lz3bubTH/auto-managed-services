import base64
import logging

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from app.config import VAULT_ADDR, VAULT_TOKEN, VAULT_KEY_PREFIX, VAULT_MOUNT
from app.interfaces.key_manager import KeyManager, KeyInfo

logger = logging.getLogger(__name__)


class VaultError(Exception):
    pass


class VaultKeyManager(KeyManager):
    """Vault Transit-backed key manager. Raw KEKs never leave Vault."""

    def __init__(self) -> None:
        self._client = httpx.AsyncClient(
            base_url=VAULT_ADDR,
            headers={"X-Vault-Token": VAULT_TOKEN},
            timeout=10.0,
        )

    def _key_name(self, tenant_id: str) -> str:
        return f"{VAULT_KEY_PREFIX}{tenant_id}"

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=0.5, max=4),
        retry=retry_if_exception_type((httpx.TransportError, httpx.TimeoutException)),
    )
    async def provision_key(self, tenant_id: str) -> None:
        key = self._key_name(tenant_id)
        resp = await self._client.post(
            f"/v1/{VAULT_MOUNT}/keys/{key}",
            json={"type": "aes256-gcm96", "exportable": False, "allow_plaintext_backup": False},
        )
        if resp.status_code not in (200, 204):
            raise VaultError(f"Failed to provision key for tenant {tenant_id}: {resp.status_code}")
        # Enable deletion for lifecycle management, but key is NOT exportable
        await self._client.post(
            f"/v1/{VAULT_MOUNT}/keys/{key}/config",
            json={"deletion_allowed": True},
        )
        logger.info("Provisioned transit key for tenant=%s", tenant_id)

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=0.5, max=4),
        retry=retry_if_exception_type((httpx.TransportError, httpx.TimeoutException)),
    )
    async def wrap_dek(self, tenant_id: str, dek: bytes) -> str:
        key = self._key_name(tenant_id)
        resp = await self._client.post(
            f"/v1/{VAULT_MOUNT}/encrypt/{key}",
            json={"plaintext": base64.b64encode(dek).decode()},
        )
        if resp.status_code != 200:
            logger.error("Vault wrap_dek failed for tenant=%s status=%d", tenant_id, resp.status_code)
            raise VaultError(f"wrap_dek failed: {resp.status_code}")
        return resp.json()["data"]["ciphertext"]

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=0.5, max=4),
        retry=retry_if_exception_type((httpx.TransportError, httpx.TimeoutException)),
    )
    async def unwrap_dek(self, tenant_id: str, wrapped_dek: str) -> bytes:
        key = self._key_name(tenant_id)
        resp = await self._client.post(
            f"/v1/{VAULT_MOUNT}/decrypt/{key}",
            json={"ciphertext": wrapped_dek},
        )
        if resp.status_code != 200:
            logger.error("Vault unwrap_dek failed for tenant=%s status=%d", tenant_id, resp.status_code)
            raise VaultError(f"unwrap_dek failed: {resp.status_code}")
        return base64.b64decode(resp.json()["data"]["plaintext"])

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=0.5, max=4),
        retry=retry_if_exception_type((httpx.TransportError, httpx.TimeoutException)),
    )
    async def rewrap_dek(self, tenant_id: str, wrapped_dek: str) -> str:
        """Re-encrypt a DEK under the latest key version — plaintext never leaves Vault."""
        key = self._key_name(tenant_id)
        resp = await self._client.post(
            f"/v1/{VAULT_MOUNT}/rewrap/{key}",
            json={"ciphertext": wrapped_dek},
        )
        if resp.status_code != 200:
            logger.error("Vault rewrap_dek failed for tenant=%s status=%d", tenant_id, resp.status_code)
            raise VaultError(f"rewrap_dek failed: {resp.status_code}")
        return resp.json()["data"]["ciphertext"]

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=0.5, max=4),
        retry=retry_if_exception_type((httpx.TransportError, httpx.TimeoutException)),
    )
    async def rotate_key(self, tenant_id: str) -> int:
        key = self._key_name(tenant_id)
        resp = await self._client.post(f"/v1/{VAULT_MOUNT}/keys/{key}/rotate")
        if resp.status_code != 200:
            raise VaultError(f"rotate_key failed: {resp.status_code}")
        info = await self.get_key_info(tenant_id)
        logger.info("Rotated key for tenant=%s new_version=%d", tenant_id, info.latest_version)
        return info.latest_version

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=0.5, max=4),
        retry=retry_if_exception_type((httpx.TransportError, httpx.TimeoutException)),
    )
    async def update_min_decryption_version(self, tenant_id: str, version: int) -> None:
        key = self._key_name(tenant_id)
        resp = await self._client.post(
            f"/v1/{VAULT_MOUNT}/keys/{key}/config",
            json={"min_decryption_version": version},
        )
        if resp.status_code != (200):
            raise VaultError(f"update_min_decryption_version failed: {resp.status_code}")
        logger.info("Set min_decryption_version=%d for tenant=%s", version, tenant_id)

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=0.5, max=4),
        retry=retry_if_exception_type((httpx.TransportError, httpx.TimeoutException)),
    )
    async def get_key_info(self, tenant_id: str) -> KeyInfo:
        key = self._key_name(tenant_id)
        resp = await self._client.get(f"/v1/{VAULT_MOUNT}/keys/{key}")
        if resp.status_code != 200:
            raise VaultError(f"get_key_info failed: {resp.status_code}")
        data = resp.json()["data"]
        return KeyInfo(
            name=data["name"],
            latest_version=data["latest_version"],
            min_decryption_version=data["min_decryption_version"],
            supports_encryption=data.get("supports_encryption", True),
        )

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=0.5, max=4),
        retry=retry_if_exception_type((httpx.TransportError, httpx.TimeoutException)),
    )
    async def delete_key(self, tenant_id: str) -> None:
        key = self._key_name(tenant_id)
        resp = await self._client.delete(f"/v1/{VAULT_MOUNT}/keys/{key}")
        if resp.status_code not in (200, 204):
            raise VaultError(f"delete_key failed: {resp.status_code}")
        logger.info("Deleted transit key for tenant=%s", tenant_id)

    async def health_check(self) -> bool:
        try:
            resp = await self._client.get("/v1/sys/health")
            return resp.status_code == 200
        except (httpx.TransportError, httpx.TimeoutException):
            return False
