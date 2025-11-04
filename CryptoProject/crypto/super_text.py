# crypto/super_text.py
from cryptography.fernet import Fernet, InvalidToken
import base64

# ===============================
# 🔁 Reverse Text Layer
# ===============================
def reverse_text(text: str) -> str:
    return text[::-1]


# ===============================
# 🔒 Fernet Layer
# ===============================
def encrypt_with_fernet(text: str, base64_key: str):
    try:
        key = base64_key.encode() if isinstance(base64_key, str) else base64_key
        f = Fernet(key)
        token = f.encrypt(text.encode("utf-8"))
        return base64.b64encode(token).decode()
    except Exception as e:
        raise Exception(f"Fernet encryption failed: {e}")


def decrypt_with_fernet(ciphertext_b64: str, base64_key: str):
    try:
        key = base64_key.encode() if isinstance(base64_key, str) else base64_key
        f = Fernet(key)
        token = base64.b64decode(ciphertext_b64)
        plaintext = f.decrypt(token).decode("utf-8")
        return plaintext
    except InvalidToken:
        raise Exception("Invalid key or corrupted ciphertext.")
    except Exception as e:
        raise Exception(f"Fernet decryption failed: {e}")


# ===============================
# 🌀 Super Text (2-Step System)
# ===============================
def step1_reverse_encrypt(plaintext: str):
    """Step 1: reverse plaintext."""
    return reverse_text(plaintext)


def step2_fernet_encrypt(reversed_text: str, base64_key: str):
    """Step 2: encrypt reversed text with Fernet."""
    return encrypt_with_fernet(reversed_text, base64_key)


def super_decrypt(ciphertext_b64: str, base64_key: str):
    """Full decrypt: Fernet decrypt -> reverse back"""
    try:
        decrypted_rev = decrypt_with_fernet(ciphertext_b64, base64_key)
        return reverse_text(decrypted_rev)
    except Exception as e:
        raise Exception(f"Super decrypt failed: {e}")
