from datetime import datetime

from sqlalchemy import String, Text, DateTime, Index
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


class SecretRecordORM(Base):
    __tablename__ = "secrets"
    __table_args__ = (
        Index("ix_secrets_tenant_id", "tenant_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    encrypted_payload: Mapped[str] = mapped_column(Text, nullable=False)
    encrypted_dek: Mapped[str] = mapped_column(Text, nullable=False)
    nonce: Mapped[str] = mapped_column(String(24), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
