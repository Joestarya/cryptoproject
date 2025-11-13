# crypto/super_text.py
from cryptography.fernet import Fernet, InvalidToken
import base64

# ===============================
# Reverse
# ===============================
def reverse_text(text: str) -> str:
    return text[::-1]


# ===============================
# Fernet
# ===============================
def encrypt_with_fernet(text: str, base64_key: str):
    try:
        key = base64_key.encode() if isinstance(base64_key, str) else base64_key
        f = Fernet(key)
        token = f.encrypt(text.encode("utf-8"))
        return base64.b64encode(token).decode()
    except Exception as e:
        raise Exception(f"Enkripsi gagal: {e}")


def decrypt_with_fernet(ciphertext_b64: str, base64_key: str):
    try:
        key = base64_key.encode() if isinstance(base64_key, str) else base64_key
        f = Fernet(key)
        token = base64.b64decode(ciphertext_b64)
        plaintext = f.decrypt(token).decode("utf-8")
        return plaintext
    except InvalidToken:
        raise Exception("Kunci atau ciphertext tidak valid!")
    except Exception as e:
        raise Exception(f"Enkripsi gagal: {e}")


# ===============================
# Super
# ===============================
def step1_reverse_encrypt(plaintext: str):
    return reverse_text(plaintext)


def step2_fernet_encrypt(reversed_text: str, base64_key: str):
    return encrypt_with_fernet(reversed_text, base64_key)


def super_decrypt(ciphertext_b64: str, base64_key: str):
    try:
        decrypted_rev = decrypt_with_fernet(ciphertext_b64, base64_key)
        return reverse_text(decrypted_rev)
    except Exception as e:
        raise Exception(f"Dekripsi gagal: {e}")
