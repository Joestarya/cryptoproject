import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


# ======================
# Key
# ======================

# generate kunci
def generate_key() -> bytes:
    return os.urandom(32)

# konversi bytes kunci ke string base64
def key_to_str(key: bytes) -> str:
    return base64.b64encode(key).decode()

# konversi string base64 kembali ke bytes kunci
def str_to_key(key_str: str) -> bytes:
    return base64.b64decode(key_str)


# ======================
# Encrypt / decrypt
# ======================

def encrypt_text(plaintext: str, key: bytes) -> dict:
    aead = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    ciphertext = aead.encrypt(nonce, plaintext.encode(), None)

    return {
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }


def decrypt_text(ciphertext_b64: str, nonce_b64: str, key: bytes) -> str:
    aead = ChaCha20Poly1305(key)
    nonce = base64.b64decode(nonce_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    plaintext = aead.decrypt(nonce, ciphertext, None)
    return plaintext.decode()