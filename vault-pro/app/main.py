import logging
import time
import uuid

from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import PlainTextResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.db import init_db
from app.dependencies import get_key_manager, get_secret_service, get_rotation_service, verify_api_key
from app.services.vault_key_manager import VaultKeyManager, VaultError
from app.services.secret_service import SecretService
from app.services.rotation_service import RotationService
from app.models.schemas import (
    SaveRequest, SaveResponse,
    GetResponse,
    ListSecretsResponse,
    DeleteResponse,
    ProvisionRequest, ProvisionResponse,
    DeprovisionResponse,
    KeyInfoResponse,
    RotateResponse,
    FullRotateRequest, FullRotateResponse,
    RewrapRequest, RewrapResponse,
    RevokeRequest,
    HealthResponse,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────
# Request-ID middleware — every request gets a
# traceable ID logged on entry and exit with timing
# ──────────────────────────────────────────────

class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4())[:8])
        request.state.request_id = request_id

        t0 = time.monotonic()
        logger.info(
            "%s %s started", request.method, request.url.path,
            extra={"request_id": request_id},
        )

        response = await call_next(request)

        elapsed_ms = (time.monotonic() - t0) * 1000
        logger.info(
            "%s %s completed status=%d elapsed=%.1fms",
            request.method, request.url.path, response.status_code, elapsed_ms,
            extra={"request_id": request_id},
        )
        response.headers["X-Request-ID"] = request_id
        return response


app = FastAPI(title="Vault Pro", version="3.0.0")
app.add_middleware(RequestIDMiddleware)


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
# Tenant provisioning & deprovisioning
# ──────────────────────────────────────────────

@app.post("/tenants", response_model=ProvisionResponse, dependencies=[Depends(verify_api_key)])
async def provision_tenant(req: ProvisionRequest, km: VaultKeyManager = Depends(get_key_manager)):
    try:
        await km.provision_key(req.tenant_id)
    except VaultError as e:
        raise HTTPException(status_code=502, detail=str(e))
    return ProvisionResponse(tenant_id=req.tenant_id, key_name=f"tenant-{req.tenant_id}")


@app.delete("/tenants/{tenant_id}", response_model=DeprovisionResponse, dependencies=[Depends(verify_api_key)])
async def deprovision_tenant(
    tenant_id: str,
    km: VaultKeyManager = Depends(get_key_manager),
    svc: SecretService = Depends(get_secret_service),
):
    deleted_count = svc.delete_all_by_tenant(tenant_id)
    try:
        await km.delete_key(tenant_id)
        key_deleted = True
    except VaultError:
        logger.warning("Failed to delete Vault key for tenant=%s (may not exist)", tenant_id)
        key_deleted = False
    return DeprovisionResponse(tenant_id=tenant_id, secrets_deleted=deleted_count, key_deleted=key_deleted)


# ──────────────────────────────────────────────
# Secret CRUD
# ──────────────────────────────────────────────

@app.post("/tenants/{tenant_id}/secrets", response_model=SaveResponse, dependencies=[Depends(verify_api_key)])
async def save_secret(tenant_id: str, req: SaveRequest, svc: SecretService = Depends(get_secret_service)):
    try:
        secret_id = await svc.save(tenant_id, req.payload)
    except VaultError:
        raise HTTPException(status_code=502, detail="Encryption service unavailable")
    return SaveResponse(id=secret_id)


@app.get("/tenants/{tenant_id}/secrets", response_model=ListSecretsResponse, dependencies=[Depends(verify_api_key)])
async def list_secrets(tenant_id: str, svc: SecretService = Depends(get_secret_service)):
    ids, total = svc.list_ids(tenant_id)
    return ListSecretsResponse(tenant_id=tenant_id, secrets=ids, total=total)


@app.get("/tenants/{tenant_id}/secrets/{secret_id}", response_model=GetResponse, dependencies=[Depends(verify_api_key)])
async def get_secret(tenant_id: str, secret_id: str, svc: SecretService = Depends(get_secret_service)):
    try:
        plaintext = await svc.get(tenant_id, secret_id)
    except VaultError:
        raise HTTPException(status_code=502, detail="Decryption service unavailable")
    if plaintext is None:
        raise HTTPException(status_code=404, detail="Secret not found")
    return GetResponse(id=secret_id, payload=plaintext)


@app.delete("/tenants/{tenant_id}/secrets/{secret_id}", response_model=DeleteResponse, dependencies=[Depends(verify_api_key)])
async def delete_secret(tenant_id: str, secret_id: str, svc: SecretService = Depends(get_secret_service)):
    deleted = svc.delete(tenant_id, secret_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Secret not found")
    return DeleteResponse(deleted=True)


# ──────────────────────────────────────────────
# Key rotation & revocation
# ──────────────────────────────────────────────

@app.post("/tenants/{tenant_id}/rotate", response_model=RotateResponse, dependencies=[Depends(verify_api_key)])
async def rotate_key(tenant_id: str, svc: RotationService = Depends(get_rotation_service)):
    try:
        new_version = await svc.rotate_key(tenant_id)
    except VaultError as e:
        raise HTTPException(status_code=502, detail=str(e))
    return RotateResponse(tenant_id=tenant_id, new_version=new_version)


@app.post("/tenants/{tenant_id}/full-rotate", response_model=FullRotateResponse, dependencies=[Depends(verify_api_key)])
async def full_rotate(
    tenant_id: str,
    req: FullRotateRequest = FullRotateRequest(),
    svc: RotationService = Depends(get_rotation_service),
):
    """Enterprise rotation: rotate key + batch rewrap all DEKs + revoke old versions.

    Single call handles the entire lifecycle. Batching is managed internally.
    Old versions are only revoked if ALL DEKs are successfully rewrapped.
    """
    try:
        result = await svc.full_rotate(tenant_id, batch_size=req.batch_size, revoke_old=req.revoke_old)
    except VaultError as e:
        raise HTTPException(status_code=502, detail=str(e))
    return FullRotateResponse(
        tenant_id=result.tenant_id,
        old_version=result.old_version,
        new_version=result.new_version,
        total_records=result.total_records,
        rewrapped=result.rewrapped,
        failed=result.failed,
        old_versions_revoked=result.old_versions_revoked,
        elapsed_seconds=result.elapsed_seconds,
    )


@app.post("/tenants/{tenant_id}/rewrap", response_model=RewrapResponse, dependencies=[Depends(verify_api_key)])
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


@app.post("/tenants/{tenant_id}/revoke", dependencies=[Depends(verify_api_key)])
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


@app.get("/tenants/{tenant_id}/key-info", response_model=KeyInfoResponse, dependencies=[Depends(verify_api_key)])
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


# ──────────────────────────────────────────────
# System test — no auth required
# Exercises the full lifecycle end-to-end
# ──────────────────────────────────────────────

@app.get("/test", response_class=PlainTextResponse)
async def system_test(
    km: VaultKeyManager = Depends(get_key_manager),
    svc: SecretService = Depends(get_secret_service),
    rot: RotationService = Depends(get_rotation_service),
):
    """Full end-to-end system test. Creates a temporary tenant, encrypts 100 secrets,
    rotates keys, rewraps, verifies decryption, revokes old versions, and cleans up.
    Returns a detailed plain-text log of every step.
    """
    lines: list[str] = []
    test_id = uuid.uuid4().hex[:8]
    tenant = f"test-{test_id}"
    secret_count = 100
    t_global = time.monotonic()

    def log(msg: str):
        elapsed = time.monotonic() - t_global
        line = f"[{elapsed:7.3f}s] {msg}"
        lines.append(line)

    log(f"========== VAULT PRO SYSTEM TEST ==========")
    log(f"Tenant:       {tenant}")
    log(f"Secrets:      {secret_count}")
    log("")

    # ── 1. Health check ──
    log("--- Phase 1: Health Check ---")
    vault_ok = await km.health_check()
    log(f"Vault reachable: {vault_ok}")
    if not vault_ok:
        log("ABORT: Vault is not reachable")
        return "\n".join(lines)

    # ── 2. Provision tenant ──
    log("")
    log("--- Phase 2: Provision Tenant ---")
    try:
        await km.provision_key(tenant)
        log(f"Provisioned transit key: tenant-{tenant}")
    except VaultError as e:
        log(f"ABORT: Failed to provision tenant: {e}")
        return "\n".join(lines)

    key_info_v1 = await km.get_key_info(tenant)
    log(f"Key version: {key_info_v1.latest_version}, min_decryption_version: {key_info_v1.min_decryption_version}")

    # ── 3. Encrypt 100 secrets ──
    log("")
    log(f"--- Phase 3: Encrypt {secret_count} Secrets ---")
    secret_ids: list[str] = []
    payloads: list[str] = []
    t0 = time.monotonic()

    for i in range(secret_count):
        payload = f"secret-data-{i:04d}-{uuid.uuid4().hex[:12]}"
        payloads.append(payload)
        try:
            sid = await svc.save(tenant, payload)
            secret_ids.append(sid)
        except Exception as e:
            log(f"  FAIL: encrypt #{i} — {e}")
            secret_ids.append("")

    encrypt_time = time.monotonic() - t0
    success = sum(1 for s in secret_ids if s)
    log(f"Encrypted: {success}/{secret_count} in {encrypt_time:.2f}s ({secret_count / encrypt_time:.0f} ops/sec)")

    # ── 4. Verify decryption (sample first 5) ──
    log("")
    log("--- Phase 4: Verify Decryption (pre-rotation) ---")
    for i in range(min(5, len(secret_ids))):
        if not secret_ids[i]:
            continue
        decrypted = await svc.get(tenant, secret_ids[i])
        match = decrypted == payloads[i]
        log(f"  Secret #{i}: {'PASS' if match else 'FAIL'} (id={secret_ids[i][:8]}...)")

    # ── 5. Rotate key ──
    log("")
    log("--- Phase 5: Key Rotation ---")
    new_version = await rot.rotate_key(tenant)
    log(f"Key rotated: v{key_info_v1.latest_version} -> v{new_version}")

    key_info_v2 = await km.get_key_info(tenant)
    log(f"Key version: {key_info_v2.latest_version}, min_decryption_version: {key_info_v2.min_decryption_version}")

    # ── 6. Verify old secrets still decrypt (using old key version) ──
    log("")
    log("--- Phase 6: Verify Decryption (post-rotation, pre-rewrap) ---")
    for i in range(min(5, len(secret_ids))):
        if not secret_ids[i]:
            continue
        decrypted = await svc.get(tenant, secret_ids[i])
        match = decrypted == payloads[i]
        log(f"  Secret #{i}: {'PASS' if match else 'FAIL'} (still readable with old DEK wrapping)")

    # ── 7. Rewrap all DEKs ──
    log("")
    log("--- Phase 7: Rewrap All DEKs (batch_size=25) ---")
    t0 = time.monotonic()
    rewrap_result = await rot.rewrap_deks(tenant, batch_size=25)
    rewrap_time = time.monotonic() - t0
    log(f"Total:     {rewrap_result.total}")
    log(f"Rewrapped: {rewrap_result.rewrapped}")
    log(f"Failed:    {rewrap_result.failed}")
    log(f"Time:      {rewrap_time:.2f}s ({rewrap_result.total / rewrap_time:.0f} ops/sec)")

    # ── 8. Verify decryption after rewrap ──
    log("")
    log("--- Phase 8: Verify Decryption (post-rewrap) ---")
    verify_pass = 0
    verify_fail = 0
    t0 = time.monotonic()
    for i in range(len(secret_ids)):
        if not secret_ids[i]:
            continue
        try:
            decrypted = await svc.get(tenant, secret_ids[i])
            if decrypted == payloads[i]:
                verify_pass += 1
            else:
                verify_fail += 1
                if verify_fail <= 3:
                    log(f"  MISMATCH: Secret #{i} (id={secret_ids[i][:8]}...)")
        except Exception as e:
            verify_fail += 1
            if verify_fail <= 3:
                log(f"  ERROR: Secret #{i} — {e}")
    verify_time = time.monotonic() - t0
    log(f"Verified: {verify_pass}/{verify_pass + verify_fail} PASS in {verify_time:.2f}s")

    # ── 9. Revoke old key versions ──
    log("")
    log("--- Phase 9: Revoke Old Key Versions ---")
    if rewrap_result.failed == 0:
        await rot.revoke_old_versions(tenant, new_version)
        log(f"Revoked: min_decryption_version set to {new_version}")
        key_info_v3 = await km.get_key_info(tenant)
        log(f"Key version: {key_info_v3.latest_version}, min_decryption_version: {key_info_v3.min_decryption_version}")
    else:
        log(f"SKIPPED: {rewrap_result.failed} DEKs failed rewrap — cannot safely revoke")

    # ── 10. Verify decryption still works after revocation ──
    log("")
    log("--- Phase 10: Verify Decryption (post-revocation) ---")
    post_revoke_pass = 0
    post_revoke_fail = 0
    for i in range(min(10, len(secret_ids))):
        if not secret_ids[i]:
            continue
        try:
            decrypted = await svc.get(tenant, secret_ids[i])
            if decrypted == payloads[i]:
                post_revoke_pass += 1
            else:
                post_revoke_fail += 1
        except Exception as e:
            post_revoke_fail += 1
            log(f"  ERROR: Secret #{i} — {e}")
    log(f"Verified: {post_revoke_pass}/{post_revoke_pass + post_revoke_fail} PASS")

    # ── 11. Second rotation with full-rotate (single call) ──
    log("")
    log("--- Phase 11: Full Rotate (single-call enterprise rotation) ---")
    t0 = time.monotonic()
    full_result = await rot.full_rotate(tenant, batch_size=50, revoke_old=True)
    full_time = time.monotonic() - t0
    log(f"Old version:      {full_result.old_version}")
    log(f"New version:      {full_result.new_version}")
    log(f"Records rewrapped: {full_result.rewrapped}/{full_result.total_records}")
    log(f"Failed:           {full_result.failed}")
    log(f"Old revoked:      {full_result.old_versions_revoked}")
    log(f"Time:             {full_time:.2f}s")

    # ── 12. Final verification ──
    log("")
    log("--- Phase 12: Final Verification (after 2 rotations) ---")
    final_pass = 0
    final_fail = 0
    t0 = time.monotonic()
    for i in range(len(secret_ids)):
        if not secret_ids[i]:
            continue
        try:
            decrypted = await svc.get(tenant, secret_ids[i])
            if decrypted == payloads[i]:
                final_pass += 1
            else:
                final_fail += 1
        except Exception as e:
            final_fail += 1
            if final_fail <= 3:
                log(f"  ERROR: Secret #{i} — {e}")
    final_time = time.monotonic() - t0
    log(f"Verified: {final_pass}/{final_pass + final_fail} PASS in {final_time:.2f}s")

    # ── 13. Cleanup ──
    log("")
    log("--- Phase 13: Cleanup ---")
    deleted_count = svc.delete_all_by_tenant(tenant)
    log(f"Deleted {deleted_count} secrets from database")
    try:
        await km.delete_key(tenant)
        log(f"Deleted transit key: tenant-{tenant}")
    except VaultError as e:
        log(f"Warning: failed to delete key — {e}")

    # ── Summary ──
    total_time = time.monotonic() - t_global
    log("")
    log("========== SUMMARY ==========")
    log(f"Tenant:              {tenant}")
    log(f"Total secrets:       {secret_count}")
    log(f"Encrypt success:     {success}/{secret_count}")
    log(f"Final verify:        {final_pass}/{final_pass + final_fail}")
    log(f"Rotations performed: 2")
    log(f"Total time:          {total_time:.2f}s")
    all_pass = success == secret_count and final_pass == (final_pass + final_fail) and final_fail == 0
    log(f"Result:              {'ALL PASS' if all_pass else 'FAILURES DETECTED'}")
    log("=" * 42)

    return "\n".join(lines)
