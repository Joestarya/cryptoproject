# crypto/xchacha_file.py
import base64
import os
from nacl.secret import SecretBox #xchacha20-poly1305
from nacl.utils import random as random_bytes

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
            raise ValueError("Kunci harus berukuran 32 byte")
        box = SecretBox(key)
        nonce = os.urandom(24)
        ct = box.encrypt(file_bytes, nonce)
        return base64.b64encode(ct).decode(), base64.b64encode(nonce).decode()
    except Exception as e:
        raise Exception(f"Enkripsi gagal: {e}")

def decrypt_file_bytes(ciphertext_b64: str, nonce_b64: str, key_b64: str) -> bytes:
    try:
        key = _b64decode_str(key_b64)
        nonce = _b64decode_str(nonce_b64)
        ct = _b64decode_str(ciphertext_b64)
        if len(key) != 32:
            raise ValueError("Kunci harus berukuran 32 byte")
        # ct sudah include nonce (24) dan autentikasi (16)
        if len(ct) < 40:
            raise ValueError("Ciphertext terlalu pendek / tidak valid.")
        box = SecretBox(key)
        pt = box.decrypt(ct)
        return pt
    except Exception as e:
        raise Exception(f"Dekripsi gagal: {e}")
