import logging

from fastapi import FastAPI, Depends, HTTPException

from app.db import init_db
from app.dependencies import get_key_manager, get_secret_service, get_rotation_service
from app.services.vault_key_manager import VaultKeyManager, VaultError
from app.services.secret_service import SecretService
from app.services.rotation_service import RotationService
from app.models.schemas import (
    SaveRequest, SaveResponse,
    GetResponse,
    ProvisionRequest, ProvisionResponse,
    KeyInfoResponse,
    RotateResponse,
    RewrapRequest, RewrapResponse,
    RevokeRequest,
    HealthResponse,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

app = FastAPI(title="Vault Pro", version="2.0.0")


@app.on_event("startup")
def on_startup():
    init_db()
    logger.info("Database initialized")


# ──────────────────────────────────────────────
# Health
# ──────────────────────────────────────────────

@app.get("/health", response_model=HealthResponse)
async def health(km: VaultKeyManager = Depends(get_key_manager)):
    vault_ok = await km.health_check()
    return HealthResponse(status="ok", vault="connected" if vault_ok else "unreachable")


# ──────────────────────────────────────────────
# Tenant provisioning
# ──────────────────────────────────────────────

@app.post("/tenants", response_model=ProvisionResponse)
async def provision_tenant(req: ProvisionRequest, km: VaultKeyManager = Depends(get_key_manager)):
    try:
        await km.provision_key(req.tenant_id)
    except VaultError as e:
        raise HTTPException(status_code=502, detail=str(e))
    return ProvisionResponse(tenant_id=req.tenant_id, key_name=f"tenant-{req.tenant_id}")


# ──────────────────────────────────────────────
# Secret CRUD
# ──────────────────────────────────────────────

@app.post("/tenants/{tenant_id}/secrets", response_model=SaveResponse)
async def save_secret(tenant_id: str, req: SaveRequest, svc: SecretService = Depends(get_secret_service)):
    try:
        secret_id = await svc.save(tenant_id, req.payload)
    except VaultError:
        raise HTTPException(status_code=502, detail="Encryption service unavailable")
    return SaveResponse(id=secret_id)


@app.get("/tenants/{tenant_id}/secrets/{secret_id}", response_model=GetResponse)
async def get_secret(tenant_id: str, secret_id: str, svc: SecretService = Depends(get_secret_service)):
    try:
        plaintext = await svc.get(tenant_id, secret_id)
    except VaultError:
        raise HTTPException(status_code=502, detail="Decryption service unavailable")
    if plaintext is None:
        raise HTTPException(status_code=404, detail="Secret not found")
    return GetResponse(id=secret_id, payload=plaintext)


# ──────────────────────────────────────────────
# Key rotation & revocation
# ──────────────────────────────────────────────

@app.post("/tenants/{tenant_id}/rotate", response_model=RotateResponse)
async def rotate_key(tenant_id: str, svc: RotationService = Depends(get_rotation_service)):
    try:
        new_version = await svc.rotate_key(tenant_id)
    except VaultError as e:
        raise HTTPException(status_code=502, detail=str(e))
    return RotateResponse(tenant_id=tenant_id, new_version=new_version)


@app.post("/tenants/{tenant_id}/rewrap", response_model=RewrapResponse)
async def rewrap_deks(
    tenant_id: str,
    req: RewrapRequest = RewrapRequest(),
    svc: RotationService = Depends(get_rotation_service),
):
    try:
        result = await svc.rewrap_deks(tenant_id, batch_size=req.batch_size)
    except VaultError as e:
        raise HTTPException(status_code=502, detail=str(e))
    return RewrapResponse(
        tenant_id=tenant_id,
        total_records=result.total,
        rewrapped=result.rewrapped,
        failed=result.failed,
    )


@app.post("/tenants/{tenant_id}/revoke")
async def revoke_old_versions(
    tenant_id: str,
    req: RevokeRequest,
    svc: RotationService = Depends(get_rotation_service),
):
    try:
        await svc.revoke_old_versions(tenant_id, req.min_decryption_version)
    except VaultError as e:
        raise HTTPException(status_code=502, detail=str(e))
    return {"status": "ok", "tenant_id": tenant_id, "min_decryption_version": req.min_decryption_version}


@app.get("/tenants/{tenant_id}/key-info", response_model=KeyInfoResponse)
async def key_info(tenant_id: str, km: VaultKeyManager = Depends(get_key_manager)):
    try:
        info = await km.get_key_info(tenant_id)
    except VaultError as e:
        raise HTTPException(status_code=502, detail=str(e))
    return KeyInfoResponse(
        tenant_id=tenant_id,
        key_name=info.name,
        latest_version=info.latest_version,
        min_decryption_version=info.min_decryption_version,
    )
