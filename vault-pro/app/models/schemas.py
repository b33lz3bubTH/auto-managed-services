from pydantic import BaseModel, Field


class SaveRequest(BaseModel):
    payload: str = Field(..., min_length=1)


class SaveResponse(BaseModel):
    id: str


class GetResponse(BaseModel):
    id: str
    payload: str


class ProvisionRequest(BaseModel):
    tenant_id: str = Field(..., min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9_-]+$")


class ProvisionResponse(BaseModel):
    tenant_id: str
    key_name: str


class KeyInfoResponse(BaseModel):
    tenant_id: str
    key_name: str
    latest_version: int
    min_decryption_version: int


class RotateResponse(BaseModel):
    tenant_id: str
    new_version: int


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
