# app.py
import streamlit as st
from crypto import argon2_login, chacha_text
from typing import Dict

from cryptography.fernet import Fernet
from crypto.super_text import step1_reverse_encrypt, step2_fernet_encrypt, super_decrypt

from crypto.steg_dct import embed_dct, extract_dct

import base64
import os


# ======================
#       APP SETUP
# ======================
st.set_page_config(page_title="Crypto Project", page_icon="🧩", layout="centered")

# ======================
# SESSION MANAGEMENT
# ======================
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "username" not in st.session_state:
    st.session_state.username = None


# ======================
# LOGIN PAGE
# ======================
def login_page():
    st.title("🔐 Secure Login System")
    st.subheader("Welcome to the Cryptography Project")

    tab1, tab2 = st.tabs(["🔑 Login", "🧾 Register"])

    with tab1:
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")

        if st.button("Login"):
            if argon2_login.verify_user(username, password):
                st.session_state.logged_in = True
                st.session_state.username = username
                st.success(f"✅ Logged in as {username}")
                st.rerun()
            else:
                st.error("❌ Invalid username or password")

    with tab2:
        new_user = st.text_input("Create Username")
        new_pass = st.text_input("Create Password", type="password")

        if st.button("Register"):
            success = argon2_login.register_user(new_user, new_pass)
            if success:
                st.success("✅ Account created successfully!")
            else:
                st.warning("⚠️ Username already exists!")


# ======================
# MAIN MENU
# ======================
def main_menu():
    st.sidebar.title(f"👋 Welcome, {st.session_state.username}")
    st.sidebar.title(f"👋 Hello, {st.session_state.username}")

    # Pastikan super_key tidak pernah berubah walau rerun
    if "super_key" not in st.session_state or len(st.session_state.get("super_key", "")) != 44:
        st.session_state.super_key = Fernet.generate_key().decode()
        st.session_state.super_key_saved = st.session_state.super_key
    else:
        if "super_key_saved" in st.session_state:
            st.session_state.super_key = st.session_state.super_key_saved

    menu = st.sidebar.selectbox(
        "Navigate",
        [
            "Text Encryption and Decrypt",
            "Super Text Encrypt and Decrypt",
            "File Encryption (XChaCha20)",
            "Steganography (DCT)"
        ]
    )

    # Logout button
    if st.sidebar.button("🚪 Logout"):
        st.session_state.logged_in = False
        st.session_state.username = None
        st.rerun()

    # ======================
    # PAGES
    # ======================
    elif menu == "Text Encryption and Decrypt":
        st.header("ChaCha20 Text Encryption")

    # Generate or reuse session key
        if "text_key" not in st.session_state:
            st.session_state.text_key = chacha_text.generate_key()

        col1, col2 = st.columns([3, 1])
        
        with col1:
            st.text_area(
                "Your secret key (Base64):",
                chacha_text.key_to_str(st.session_state.text_key),
                height=50,
                key=f"display_key_{hash(st.session_state.text_key)}"
            )

        with col2:
            if st.button("🔁 Refresh Key"):
                st.session_state.text_key = chacha_text.generate_key()
                st.rerun()

        st.divider()
        st.subheader("🔒 Encrypt Text")
        plaintext = st.text_area("Enter text to encrypt:", "")

        if st.button("Encrypt"):
            if plaintext.strip() == "":
                st.warning("Please enter some text to encrypt.")
            else:
                result = chacha_text.encrypt_text(plaintext, st.session_state.text_key)
                # simpan hasil ke session_state
                st.session_state.last_ciphertext = result["ciphertext"]
                st.session_state.last_nonce = result["nonce"]

                st.success("✅ Encrypted successfully!")
                st.code(st.session_state.last_ciphertext, language="plaintext")
                st.code(st.session_state.last_nonce, language="plaintext")

        # ====================== Decrypt Text (ChaCha20) ======================
        st.divider()
        st.subheader("🔓 Decrypt Text")

        # Allow manual key input (Base64) so user can re-enter key after restart
        manual_text_key = st.text_input(
            "Key for Text Decryption (Base64) — paste here if you saved it:",
            value=st.session_state.get("text_key_b64", ""), # optional: you may store a string form earlier
            help="Contoh: hasil dari chacha_text.key_to_str(key_bytes)"
        )

        cipher_in = st.text_area("Ciphertext (Base64):", st.session_state.get("last_ciphertext", ""))
        nonce_in = st.text_input("Nonce (Base64):", st.session_state.get("last_nonce", ""))

        if st.button("Decrypt"):
            if cipher_in.strip() == "" or nonce_in.strip() == "":
                st.warning("Please provide both ciphertext and nonce.")
            else:
                # choose key: prefer manual if provided, otherwise use session key
                key_to_use = manual_text_key.strip() if manual_text_key.strip() != "" else chacha_text.key_to_str(st.session_state.text_key)
                try:
                    # chacha_text.decrypt_text expects key bytes or session key depending on your implementation
                    plain = chacha_text.decrypt_text(cipher_in, nonce_in, chacha_text.str_to_key(key_to_use))
                    st.success("✅ Decrypted successfully!")
                    st.code(plain, language="plaintext")
                except Exception as e:
                    st.error(f"❌ Decryption failed: {e}")


    elif menu == "Super Text Encrypt and Decrypt":
        st.title("🌀 Super Text (Reverse + Fernet, 2-Step Mode)")

        # === key setup ===
        if "super_key" not in st.session_state:
            st.session_state.super_key = Fernet.generate_key().decode()
            st.session_state.super_key_saved = st.session_state.super_key
        else:
            if "super_key_saved" in st.session_state:
                st.session_state.super_key = st.session_state.super_key_saved

        st.text_input("Your Fernet Key (Base64):", st.session_state.super_key, disabled=True)

        # ====================================================
        # STEP 1: Reverse Text
        # ====================================================
        st.subheader("Step 1: Reverse Text")
        plaintext = st.text_area("Enter plaintext:")

        if st.button("🔁 Reverse Text"):
            if plaintext.strip() == "":
                st.warning("Please enter some text first.")
            else:
                reversed_text = step1_reverse_encrypt(plaintext)
                st.success("✅ Reversed text generated!")
                st.code(reversed_text, language="text")
                st.session_state.last_reversed = reversed_text

        st.divider()

        # ====================================================
        # STEP 2: Fernet Encrypt
        # ====================================================
        st.subheader("Step 2: Fernet Encrypt")
        reversed_input = st.text_area(
            "Enter reversed text from Step 1:",
            st.session_state.get("last_reversed", "")
        )

        if st.button("🔒 Encrypt with Fernet"):
            if reversed_input.strip() == "":
                st.warning("Please input reversed text.")
            else:
                try:
                    final_cipher = step2_fernet_encrypt(reversed_input, st.session_state.super_key)

                    # simpan hasil ke session agar auto muncul di decrypt section
                    st.session_state.super_cipher = final_cipher

                    st.success("✅ Super Encryption successful!")
                    st.code(st.session_state.super_cipher, language="text")

                except Exception as e:
                    st.error(str(e))

        st.divider()

        # ====================================================
        # 🔓 DECRYPT SECTION (Super Text)
        # ====================================================
        st.subheader("🔓 Decrypt Super Text")

        manual_super_key = st.text_input(
            "Fernet Key (Base64) — paste here if you saved it:",
            value=st.session_state.get("super_key", ""),
            help="Fernet key generated by Fernet.generate_key()"
        )

        # auto-isi ciphertext dari hasil terakhir
        cipher_in = st.text_area(
            "Enter Super Ciphertext (Base64):",
            st.session_state.get("super_cipher", "")
        )

        if st.button("Decrypt Super Text"):
            if cipher_in.strip() == "":
                st.warning("Please input ciphertext.")
            else:
                key_to_use = manual_super_key.strip() if manual_super_key.strip() != "" else st.session_state.super_key
                try:
                    result = super_decrypt(cipher_in, key_to_use)
                    st.success("✅ Decryption successful!")
                    st.text_area("Decrypted Plaintext:", result, height=100)
                except Exception as e:
                    st.error(f"❌ Decryption failed: {e}")

    elif menu == "File Encryption (XChaCha20)":
        st.header("🗂️ File Encryption (XChaCha20-Poly1305)")

        from crypto.xchacha_file import (
            generate_key_b64,
            encrypt_file_bytes,
            decrypt_file_bytes
        )

        # ===== Key management (persistent per session) =====
        if "file_key" not in st.session_state or not st.session_state.get("file_key"):
            st.session_state.file_key = generate_key_b64()
            st.session_state.file_key_saved = st.session_state.file_key
        else:
            if "file_key_saved" in st.session_state:
                st.session_state.file_key = st.session_state.file_key_saved

        colk1, colk2 = st.columns([4, 1])
        with colk1:
            st.text_input("File Encryption Key (Base64):",
                        value=st.session_state.file_key, disabled=True)
        with colk2:
            if st.button("🔁 Regenerate File Key"):
                st.session_state.file_key = generate_key_b64()
                st.session_state.file_key_saved = st.session_state.file_key
                st.success("New file key generated.")

        st.divider()

        # ====== ENCRYPT FILE ======
        st.subheader("🔒 Encrypt File")
        uploaded = st.file_uploader("Upload file to encrypt", type=None, key="upload_enc")

        if uploaded is not None:
            file_bytes = uploaded.read()
            st.write(f"Filename: {uploaded.name} — Size: {len(file_bytes)} bytes")

            if st.button("Encrypt Uploaded File"):
                try:
                    ct_b64, nonce_b64 = encrypt_file_bytes(file_bytes, st.session_state.file_key)
                    st.session_state.file_cipher = ct_b64
                    st.session_state.file_nonce = nonce_b64

                    ct_bytes = base64.b64decode(ct_b64)
                    suggested_name = uploaded.name + ".enc"

                    st.success("✅ File encrypted successfully.")
                    st.code(f"Ciphertext (Base64):\n{st.session_state.file_cipher}", language="text")
                    st.code(f"Nonce (Base64):\n{st.session_state.file_nonce}", language="text")

                    st.download_button(
                        label="⬇️ Download ciphertext (.enc)",
                        data=ct_bytes,
                        file_name=suggested_name,
                        mime="application/octet-stream"
                    )

                except Exception as e:
                    st.error(str(e))

        st.divider()

        # ====== DECRYPT FILE ======
        st.subheader("🔓 Decrypt File")

        manual_file_key = st.text_input(
            "File Key (Base64, 32-byte) — paste here if saved:",
            value=st.session_state.get("file_key", ""),
            help="Key yang dipakai untuk enkripsi file (base64 32 bytes)"
        )

        uploaded_ct = st.file_uploader("Upload ciphertext file (.enc)", type=None, key="upload_dec")

        # auto-fill from previous session
        ct_b64_input = st.text_area(
            "Or paste Ciphertext (Base64):",
            value=st.session_state.get("file_cipher", ""),
            height=80
        )

        nonce_input = st.text_input(
            "Nonce (Base64):",
            value=st.session_state.get("file_nonce", "")
        )

        target_name = st.text_input("Original filename (suggested for download):", value="decrypted_output")

        if st.button("Decrypt File"):
            try:
                # choose key
                key_to_use = manual_file_key.strip() if manual_file_key.strip() != "" else st.session_state.file_key

                # get ciphertext base64
                if uploaded_ct is not None:
                    raw_ct = uploaded_ct.read()
                    ct_b64 = base64.b64encode(raw_ct).decode()
                else:
                    ct_b64 = ct_b64_input.strip()

                if not ct_b64:
                    st.warning("Provide ciphertext (upload .enc or paste Base64).")
                elif not nonce_input.strip():
                    st.warning("Provide nonce (Base64).")
                else:
                    plaintext_bytes = decrypt_file_bytes(ct_b64, nonce_input.strip(), key_to_use)
                    st.success("✅ Decryption successful.")
                    st.download_button(
                        label="⬇️ Download decrypted file",
                        data=plaintext_bytes,
                        file_name=target_name,
                        mime="application/octet-stream"
                    )
            except Exception as e:
                st.error(f"❌ Decryption failed: {e}")

                    
    elif menu == "Steganography (DCT)":
        st.title("Steganografi DCT (Discrete Cosine Transform)")
        st.markdown("Algoritma ini menyembunyikan pesan di domain frekuensi, membuatnya lebih tahan terhadap kompresi dan manipulasi.")

        # Bagian Embed Message
        st.header("Embed Message into Image")
        st.markdown("Algoritma ini berfungsi paling baik dengan gambar PNG untuk menghindari kompresi lossy.")
        
        uploaded_image_embed = st.file_uploader("Upload image (PNG)", type=['png'], key="dct_embed")
        message_to_embed = st.text_area("Enter message to embed:", key="dct_embed_msg")
        
        if st.button("Embed Message", key="dct_btn_embed"):
            if uploaded_image_embed and message_to_embed:
                st.info("Pesan sedang disisipkan...")
                image_bytes = uploaded_image_embed.getvalue()
                stego_bytes = embed_dct(image_bytes, message_to_embed)

                if isinstance(stego_bytes, bytes):
                    st.success("Penyisipan pesan berhasil!")
                    st.image(stego_bytes, caption="Stego-image (Gambar yang sudah disisipi pesan)")
                    
                    st.download_button(
                        label="Download Stego-image",
                        data=stego_bytes,
                        file_name="stego_dct.png",
                        mime="image/png"
                    )
                else:
                    st.error(f"Gagal menyisipkan pesan: {stego_bytes}")
            else:
                st.warning("Mohon unggah gambar dan masukkan pesan terlebih dahulu.")

        st.markdown("---")

        # Bagian Extract Message
        st.header("Extract Message from Image")
        st.markdown("Unggah gambar stego (PNG) untuk mengekstrak pesan rahasia.")

        uploaded_image_extract = st.file_uploader("Upload stego image (PNG)", type=['png'], key="dct_extract")
        
        if st.button("Extract Message", key="dct_btn_extract"):
            if uploaded_image_extract:
                st.info("Pesan sedang diekstrak...")
                image_bytes = uploaded_image_extract.getvalue()
                decrypted_message = extract_dct(image_bytes)

                if "Error" not in decrypted_message:
                    st.success("Ekstraksi pesan selesai!")
                    st.text_area("Decrypted Message:", value=decrypted_message, height=150, disabled=True)
                else:
                    st.error(decrypted_message)
            else:
                st.warning("Mohon unggah gambar stego terlebih dahulu.")
# ======================
# MAIN ENTRY POINT
# ======================
def main():
    if not st.session_state.logged_in:
        login_page()
    else:
        main_menu()


if __name__ == "__main__":
    main()
