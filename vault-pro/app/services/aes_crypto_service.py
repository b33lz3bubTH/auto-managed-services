import os
import base64

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.interfaces.crypto_service import CryptoService, EncryptionResult

_DEK_SIZE = 32   # 256-bit key
_NONCE_SIZE = 12  # 96-bit nonce per NIST recommendation for GCM


class AESCryptoService(CryptoService):
    """AES-256-GCM authenticated encryption. Each call generates a unique nonce."""

    def generate_dek(self) -> bytes:
        return os.urandom(_DEK_SIZE)

    def encrypt(self, plaintext: str, dek: bytes) -> EncryptionResult:
        nonce = os.urandom(_NONCE_SIZE)
        aesgcm = AESGCM(dek)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
        return EncryptionResult(
            ciphertext_b64=base64.b64encode(ciphertext).decode(),
            nonce_b64=base64.b64encode(nonce).decode(),
        )

    def decrypt(self, ciphertext_b64: str, nonce_b64: str, dek: bytes) -> str:
        aesgcm = AESGCM(dek)
        plaintext = aesgcm.decrypt(
            base64.b64decode(nonce_b64),
            base64.b64decode(ciphertext_b64),
            None,
        )
        return plaintext.decode("utf-8")
