from typing import Generator

from fastapi import Depends
from sqlalchemy.orm import Session

from app.db import get_db
from app.interfaces.key_manager import KeyManager
from app.interfaces.crypto_service import CryptoService
from app.interfaces.secret_repository import SecretRepository
from app.services.vault_key_manager import VaultKeyManager
from app.services.aes_crypto_service import AESCryptoService
from app.repositories.sqlalchemy_secret_repo import SQLAlchemySecretRepository
from app.services.secret_service import SecretService
from app.services.rotation_service import RotationService

# Singletons — stateless, safe to share across requests
_key_manager = VaultKeyManager()
_crypto = AESCryptoService()


def get_key_manager() -> KeyManager:
    return _key_manager


def get_crypto() -> CryptoService:
    return _crypto


def get_repository(db: Session = Depends(get_db)) -> SecretRepository:
    return SQLAlchemySecretRepository(db)


def get_secret_service(
    key_manager: KeyManager = Depends(get_key_manager),
    crypto: CryptoService = Depends(get_crypto),
    repo: SecretRepository = Depends(get_repository),
) -> SecretService:
    return SecretService(key_manager, crypto, repo)


def get_rotation_service(
    key_manager: KeyManager = Depends(get_key_manager),
    repo: SecretRepository = Depends(get_repository),
) -> RotationService:
    return RotationService(key_manager, repo)
