import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


# ======================
# KEY MANAGEMENT
# ======================
def generate_key() -> bytes:
    """Generate a random 32-byte key"""
    return os.urandom(32)


def key_to_str(key: bytes) -> str:
    """Convert key bytes to Base64 string"""
    return base64.b64encode(key).decode()


def str_to_key(key_str: str) -> bytes:
    """Convert Base64 string back to key bytes"""
    return base64.b64decode(key_str)


# ======================
# ENCRYPT / DECRYPT
# ======================
def encrypt_text(plaintext: str, key: bytes) -> dict:
    """Encrypt text using ChaCha20Poly1305"""
    aead = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    ciphertext = aead.encrypt(nonce, plaintext.encode(), None)

    return {
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }


def decrypt_text(ciphertext_b64: str, nonce_b64: str, key: bytes) -> str:
    """Decrypt text using ChaCha20Poly1305"""
    aead = ChaCha20Poly1305(key)
    nonce = base64.b64decode(nonce_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    plaintext = aead.decrypt(nonce, ciphertext, None)
    return plaintext.decode()