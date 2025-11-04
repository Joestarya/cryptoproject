# crypto/xchacha_file.py
import base64
import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305 as XChaCha20Poly1305

def generate_key_b64() -> str:
    """
    Generate a 32-byte key and return as standard base64 string.
    (We use standard base64 for UI consistency)
    """
    key = os.urandom(32)
    return base64.b64encode(key).decode()

def _b64decode_str(s: str) -> bytes:
    if not s:
        return b""
    if isinstance(s, bytes):
        s = s.decode()
    return base64.b64decode(s.strip().replace("\n", "").replace("\r", ""))

def encrypt_file_bytes(file_bytes: bytes, key_b64: str):
    """
    Encrypt raw file bytes using XChaCha20-Poly1305.
    Returns (ciphertext_b64, nonce_b64)
    """
    try:
        key = _b64decode_str(key_b64)
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes when decoded from Base64.")
        aead = XChaCha20Poly1305(key)
        nonce = os.urandom(12)
        ct = aead.encrypt(nonce, file_bytes, associated_data=None)
        return base64.b64encode(ct).decode(), base64.b64encode(nonce).decode()
    except Exception as e:
        raise Exception(f"File encryption failed: {e}")

def decrypt_file_bytes(ciphertext_b64: str, nonce_b64: str, key_b64: str) -> bytes:
    """
    Decrypt ciphertext (Base64) with nonce (Base64) and key (Base64).
    Returns plaintext bytes.
    """
    try:
        key = _b64decode_str(key_b64)
        nonce = _b64decode_str(nonce_b64)
        ct = _b64decode_str(ciphertext_b64)
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes when decoded from Base64.")
        if len(nonce) != 12:
            raise ValueError("Nonce must be 24 bytes when decoded from Base64.")
        if len(ct) < 16:
            raise ValueError("Ciphertext too short / invalid.")
        aead = XChaCha20Poly1305(key)
        pt = aead.decrypt(nonce, ct, associated_data=None)
        return pt
    except Exception as e:
        raise Exception(f"File decryption failed: {e}")
