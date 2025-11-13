from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import json
from pathlib import Path

DB_PATH = Path("db/user.json")
ph = PasswordHasher()

# ======================
# Fetch and save
# ======================

# ambil data user dari db
def load_users():
    if not DB_PATH.exists():
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        DB_PATH.write_text(json.dumps({"users": []}))
    with open(DB_PATH, "r") as f:
        return json.load(f)

# simpan data user ke db
def save_users(data):
    with open(DB_PATH, "w") as f:
        json.dump(data, f, indent=4)


# ======================
# Main logic
# ======================

# register user baru
def register_user(username: str, password: str) -> bool:
    users_data = load_users()

    # Cek apakah username sudah ada, jika usn sudah dipakai maka register gagal
    for u in users_data["users"]:
        if u["username"] == username:
            return False

    # Hash password & simpan user baru
    hashed_pw = ph.hash(password)
    users_data["users"].append({
        "username": username,
        "password": hashed_pw
    })
    save_users(users_data)
    return True

# verifikasi data
def verify_user(username: str, password: str) -> bool:
    users_data = load_users()

    for u in users_data["users"]:
        if u["username"] == username:
            try:
                ph.verify(u["password"], password)
                return True
            except VerifyMismatchError:
                return False

    return False