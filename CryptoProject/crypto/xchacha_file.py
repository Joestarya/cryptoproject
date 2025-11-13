# crypto/xchacha_file.py
import base64
import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305 as XChaCha20Poly1305

def generate_key_b64() -> str:
    key = os.urandom(32)
    return base64.b64encode(key).decode()

# cek tipe data dan hilangkan spasi, dekripsi base64 ke bytes
def _b64decode_str(s: str) -> bytes:
    if not s:
        return b""
    if isinstance(s, bytes):
        s = s.decode()
    return base64.b64decode(s.strip().replace("\n", "").replace("\r", ""))

def encrypt_file_bytes(file_bytes: bytes, key_b64: str):
    try:
        key = _b64decode_str(key_b64)
        if len(key) != 32:
            raise ValueError("Kunci harus berukuran 32 byte saat didekripsi dari base64!")
        aead = XChaCha20Poly1305(key)
        nonce = os.urandom(12)
        ct = aead.encrypt(nonce, file_bytes, associated_data=None)
        return base64.b64encode(ct).decode(), base64.b64encode(nonce).decode()
    except Exception as e:
        raise Exception(f"Enkripsi gagal: {e}")

def decrypt_file_bytes(ciphertext_b64: str, nonce_b64: str, key_b64: str) -> bytes:
    try:
        key = _b64decode_str(key_b64)
        nonce = _b64decode_str(nonce_b64)
        ct = _b64decode_str(ciphertext_b64)
        if len(key) != 32:
            raise ValueError("Kunci harus berukuran 32 byte saat didekripsi dari base64!")
        if len(nonce) != 12:
            raise ValueError("Nonce harus berukuran 12 byte saat didekripsi dari base64!")
        if len(ct) < 16:
            raise ValueError("Ciphertext terlalu pendek / tidak valid.")
        aead = XChaCha20Poly1305(key)
        pt = aead.decrypt(nonce, ct, associated_data=None)
        return pt
    except Exception as e:
        raise Exception(f"Dekripsi gagal: {e}")
