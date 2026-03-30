from dataclasses import dataclass, field
from datetime import datetime, timezone
import uuid


@dataclass
class SecretRecord:
    tenant_id: str
    encrypted_payload: str
    encrypted_dek: str
    nonce: str
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
