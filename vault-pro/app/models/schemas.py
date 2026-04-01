from pydantic import BaseModel, Field


class SaveRequest(BaseModel):
    payload: str = Field(..., min_length=1)


class SaveResponse(BaseModel):
    id: str


class GetResponse(BaseModel):
    id: str
    payload: str


class ListSecretsResponse(BaseModel):
    tenant_id: str
    secrets: list[str]
    total: int


class DeleteResponse(BaseModel):
    deleted: bool


class ProvisionRequest(BaseModel):
    tenant_id: str = Field(..., min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9_-]+$")


class ProvisionResponse(BaseModel):
    tenant_id: str
    key_name: str


class DeprovisionResponse(BaseModel):
    tenant_id: str
    secrets_deleted: int
    key_deleted: bool


class KeyInfoResponse(BaseModel):
    tenant_id: str
    key_name: str
    latest_version: int
    min_decryption_version: int


class RotateResponse(BaseModel):
    tenant_id: str
    new_version: int


class FullRotateRequest(BaseModel):
    batch_size: int = Field(default=500, ge=1, le=5000)
    revoke_old: bool = Field(default=True)


class FullRotateResponse(BaseModel):
    tenant_id: str
    old_version: int
    new_version: int
    total_records: int
    rewrapped: int
    failed: int
    old_versions_revoked: bool
    elapsed_seconds: float


class RewrapRequest(BaseModel):
    batch_size: int = Field(default=500, ge=1, le=5000)


class RewrapResponse(BaseModel):
    tenant_id: str
    total_records: int
    rewrapped: int
    failed: int


class RevokeRequest(BaseModel):
    min_decryption_version: int = Field(..., ge=1)


class HealthResponse(BaseModel):
    status: str
    vault: str
