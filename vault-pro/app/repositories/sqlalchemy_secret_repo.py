from sqlalchemy.orm import Session
from sqlalchemy import func

from app.interfaces.secret_repository import SecretRepository
from app.models.domain import SecretRecord
from app.models.db_models import SecretRecordORM


class SQLAlchemySecretRepository(SecretRepository):

    def __init__(self, db: Session):
        self._db = db

    def save(self, record: SecretRecord) -> None:
        orm = SecretRecordORM(
            id=record.id,
            tenant_id=record.tenant_id,
            encrypted_payload=record.encrypted_payload,
            encrypted_dek=record.encrypted_dek,
            nonce=record.nonce,
            created_at=record.created_at,
        )
        self._db.add(orm)
        self._db.commit()

    def get_by_id(self, tenant_id: str, secret_id: str) -> SecretRecord | None:
        orm = (
            self._db.query(SecretRecordORM)
            .filter(SecretRecordORM.id == secret_id, SecretRecordORM.tenant_id == tenant_id)
            .first()
        )
        if orm is None:
            return None
        return self._to_domain(orm)

    def list_by_tenant(self, tenant_id: str, offset: int = 0, limit: int = 500) -> list[SecretRecord]:
        rows = (
            self._db.query(SecretRecordORM)
            .filter(SecretRecordORM.tenant_id == tenant_id)
            .order_by(SecretRecordORM.created_at)
            .offset(offset)
            .limit(limit)
            .all()
        )
        return [self._to_domain(r) for r in rows]

    def update_wrapped_dek(self, secret_id: str, new_wrapped_dek: str) -> None:
        self._db.query(SecretRecordORM).filter(
            SecretRecordORM.id == secret_id
        ).update({"encrypted_dek": new_wrapped_dek})
        self._db.commit()

    def count_by_tenant(self, tenant_id: str) -> int:
        return (
            self._db.query(func.count(SecretRecordORM.id))
            .filter(SecretRecordORM.tenant_id == tenant_id)
            .scalar()
        )

    def delete(self, tenant_id: str, secret_id: str) -> bool:
        rows = (
            self._db.query(SecretRecordORM)
            .filter(SecretRecordORM.id == secret_id, SecretRecordORM.tenant_id == tenant_id)
            .delete()
        )
        self._db.commit()
        return rows > 0

    def delete_all_by_tenant(self, tenant_id: str) -> int:
        rows = (
            self._db.query(SecretRecordORM)
            .filter(SecretRecordORM.tenant_id == tenant_id)
            .delete()
        )
        self._db.commit()
        return rows

    @staticmethod
    def _to_domain(orm: SecretRecordORM) -> SecretRecord:
        return SecretRecord(
            id=orm.id,
            tenant_id=orm.tenant_id,
            encrypted_payload=orm.encrypted_payload,
            encrypted_dek=orm.encrypted_dek,
            nonce=orm.nonce,
            created_at=orm.created_at,
        )
