# app.py
import streamlit as st
from crypto import argon2_login, chacha_text
from typing import Dict

from cryptography.fernet import Fernet
from crypto.super_text import step1_reverse_encrypt, step2_fernet_encrypt, super_decrypt

import base64
import os

from PIL import Image
from io import BytesIO
import crypto.steg_lsbm as steg_lsbm


# ======================
# Setup
# ======================
st.set_page_config(page_title="Crypto Project", page_icon="🧩", layout="centered")

# ======================
# Session
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
    st.subheader("Selamat Datang di Enkripsi Kriptografi")
    st.text("Situs ")

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
        new_user = st.text_input("Ketik Username")
        new_pass = st.text_input("Ketik Password", type="password")

        if st.button("Register"):
            success = argon2_login.register_user(new_user, new_pass)
            if success:
                st.success("✅ Akun telah terdaftar")
            else:
                st.warning("⚠️ Username telah digunakan!")


# ======================
# Main Menu
# ======================
def main_menu():
    st.sidebar.title(f"👋 Welcome, {st.session_state.username}")
    st.sidebar.title(f"👋 Halo, {st.session_state.username}")

    # Pastikan super_key tidak pernah berubah walau rerun
    if "super_key" not in st.session_state or len(st.session_state.get("super_key", "")) != 44:
        st.session_state.super_key = Fernet.generate_key().decode()
        st.session_state.super_key_saved = st.session_state.super_key
    else:
        if "super_key_saved" in st.session_state:
            st.session_state.super_key = st.session_state.super_key_saved

    menu = st.sidebar.selectbox(
        "Navigasi",
        [
            "Teks Enkripsi dan Dekripsi",
            "Teks Super Enkripsi dan Dekripsi",
            "File Enkripsi dan Dekripsi",
            "Steganography"
        ]
    )

    # Logout button
    if st.sidebar.button("🚪 Logout"):
        st.session_state.logged_in = False
        st.session_state.username = None
        st.rerun()

    # ======================
    # ChaCha20 Teks
    # ======================
    elif menu == "Teks Enkripsi dan Dekripsi":
        st.title("Enkripsi dan Dekripsi Teks Menggunakan Algoritma ChaCha20")
        st.info("ChaCha20 adalah algoritma stream cipher yang cepat dan aman, sering digunakan dalam protokol keamanan seperti TLS dan SSH.")

    # ========= Generasi (refresh) kunci baru
        if "text_key" not in st.session_state:
            st.session_state.text_key = chacha_text.generate_key()

        col1, col2 = st.columns([3, 1])
        
        with col1:
            st.text_area(
                "Kunci (base64):",
                chacha_text.key_to_str(st.session_state.text_key),
                height=50,
                key=f"display_key_{hash(st.session_state.text_key)}"
            )

        with col2:
            if st.button("🔁 Refresh Kunci"):
                st.session_state.text_key = chacha_text.generate_key()
                st.rerun()

        st.divider()
        st.subheader("🔒 Enkripsi Teks")
        plaintext = st.text_area("Masukkan teks untuk dienkripsi:", "")

        # ========= Encrypt
        if st.button("Enkripsi"):
            if plaintext.strip() == "":
                st.warning("Wajib memasukkan teks untuk dienkripsi!")
            else:
                result = chacha_text.encrypt_text(plaintext, st.session_state.text_key)
                # simpan hasil ke session_state
                st.session_state.last_ciphertext = result["ciphertext"]
                st.session_state.last_nonce = result["nonce"]

                st.success("✅ Teks telah dienkripsi!")
                st.code(st.session_state.last_ciphertext, language="plaintext")
                st.code(st.session_state.last_nonce, language="plaintext")

        # ========= Decrypt
        st.divider()
        st.subheader("🔓 Dekripsi Teks")

        # Manual input agar user bisa menggunakan key sebelumnya
        manual_text_key = st.text_input(
            "Kunci (base64) | Paste jika menyimpan kunci",
            value=st.session_state.get("text_key_b64", ""),
        )

        cipher_in = st.text_area("Ciphertext (base64):", st.session_state.get("last_ciphertext", ""))
        nonce_in = st.text_input("Nonce (base64):", st.session_state.get("last_nonce", ""))

        if st.button("Dekripsi"):
            # error handling kalo ciphertext atau nonce kosong
            if cipher_in.strip() == "" or nonce_in.strip() == "":
                st.warning("Wajib memasukkan ciphertext dan nonce!")
            else:
                # Ambil kunci manual kalo textbox diisi, else ambil kunci yaang digenerate (tp kayak rusak else nya?)
                key_to_use = manual_text_key.strip() if manual_text_key.strip() != "" else chacha_text.key_to_str(st.session_state.text_key)
                try:
                    plain = chacha_text.decrypt_text(cipher_in, nonce_in, chacha_text.str_to_key(key_to_use))
                    st.success("✅ Teks telah didekripsi!")
                    st.code(plain, language="plaintext")
                except Exception as e:
                    st.error(f"❌ Dekripsi gagal: {e}")

    # ======================
    # Teks super
    # ======================
    elif menu == "Teks Super Enkripsi dan Dekripsi":
        st.title("Super Text Menggunakan algoritma (Reverse + Fernet, 2-Step Enkripsi)")
        st.info("Super Text Encryption menggabungkan dua metode enkripsi: pertama, teks dibalik (reversed), kemudian dienkripsi menggunakan algoritma Fernet yang aman.")

        # ========= Setup kunci
        if "super_key" not in st.session_state:
            st.session_state.super_key = Fernet.generate_key().decode()
            st.session_state.super_key_saved = st.session_state.super_key
        else:
            if "super_key_saved" in st.session_state:
                st.session_state.super_key = st.session_state.super_key_saved

        st.text_input("Kunci Fernet (base64):", st.session_state.super_key, disabled=True)

        st.subheader("🔒 Enkripsi Super Text")
        # ========= Encrypt tahap 1: reverse
        st.subheader("Tahap 1: Reverse Text")
        plaintext = st.text_area("Masukkan teks untuk dienkripsi:")

        if st.button("🔁 Reverse Text"):
            if plaintext.strip() == "":
                st.warning("Wajib memasukkan teks untuk enkripsi!")
            else:
                reversed_text = step1_reverse_encrypt(plaintext)
                st.success("✅ Teks telah dienkripsi dengan algoritma Reverse!")
                st.code(reversed_text, language="text")
                st.session_state.last_reversed = reversed_text

        st.divider()

        # ========= Encrypt tahap 2: fernet
        st.subheader("Tahap 2: Fernet Encrypt")
        reversed_input = st.text_area(
            "Masukkan hasil enkripsi dari tahap 1:",
            st.session_state.get("last_reversed", "")
        )

        # Error handling jika tahap 1 belum dilakukan
        if st.button("🔒 Encrypt with Fernet"):
            if reversed_input.strip() == "":
                st.warning("Wajib menjalankan tahap 1 terlebih dahulu!")
            else:
                try:
                    final_cipher = step2_fernet_encrypt(reversed_input, st.session_state.super_key)

                    # simpan hasil ke session agar auto muncul di decrypt section
                    st.session_state.super_cipher = final_cipher

                    st.success("✅ Enkripsi super berhasil!")
                    st.code(st.session_state.super_cipher, language="text")

                except Exception as e:
                    st.error(str(e))

        st.divider()

        # ========= Decrypt Super
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

    # ====================================================
    # File Encryption (XChaCha20-Poly1305)
    # ====================================================
    elif menu == "File Enkripsi dan Dekripsi":
        st.title("File Encryption Menggunakan Algoritma XChaCha20-Poly1305")
        st.info("XChaCha20-Poly1305 adalah algoritma enkripsi yang kuat dan aman, cocok untuk enkripsi file karena kemampuannya menangani nonce yang lebih panjang dan memberikan integritas data melalui autentikasi.")    

        from crypto.xchacha_file import (
            generate_key_b64,
            encrypt_file_bytes,
            decrypt_file_bytes
        )

        # # ========= setup key
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

        # ========= Encrypt
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

        # ========= decrypt
        st.subheader("🔓 Decrypt File")

        manual_file_key = st.text_input(
            "File Key (Base64, 32-byte) — paste here if saved:",
            value=st.session_state.get("file_key", ""),
            help="Key yang dipakai untuk enkripsi file (base64 32 bytes)"
        )

        uploaded_ct = st.file_uploader("Upload ciphertext file (.enc)", type=None, key="upload_dec")

        # auto fill
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
                key_to_use = manual_file_key.strip() if manual_file_key.strip() != "" else st.session_state.file_key

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

    # ====================================================
    # Steganography: LSB Matching (LSB±1)
    # ====================================================
    elif menu == "Steganography":
        st.title("🖼️ Steganography Menggunakan Algoritma LSB-Matching")
        st.info("LSB-Matching adalah teknik steganografi yang menyembunyikan pesan rahasia dalam citra digital dengan memodifikasi bit paling tidak signifikan (LSB) dari piksel gambar. Teknik ini membuat perubahan yang lebih halus pada gambar, sehingga lebih sulit dideteksi dibandingkan metode LSB tradisional.")
         
        encode_tab, decode_tab = st.tabs(["🔒 Encode (Hide Message)", "🔓 Decode (Reveal Message)"])

        # ========= encode
        with encode_tab:
            st.subheader("Hide a Secret Message in an Image")
            
            uploaded_image = st.file_uploader("1. Upload your cover image (PNG, BMP)", type=["png", "bmp"], key="lsbm_uploader")
            message = st.text_area("2. Enter your secret message:", height=150, key="lsbm_message")
            
            if st.button("Hide Message", key="lsbm_hide_btn"):
                if uploaded_image is not None and message:
                    try:
                        # gambar dibuka dalam bentuk PILLOW
                        cover_image = Image.open(uploaded_image)
                        
                        with st.spinner("Hiding message in image..."):
                            secret_image = steg_lsbm.hide(cover_image, message)
                        
                        st.success("Message hidden successfully!")
                        st.image(secret_image, caption="Your new secret image")
                        
                        # Konversi PILLOW ke bytes
                        buf = BytesIO()
                        secret_image.save(buf, format="PNG")
                        byte_im = buf.getvalue()
                        
                        st.download_button(
                            label="3. Download Secret Image (as PNG)",
                            data=byte_im,
                            file_name="secret_image.png",
                            mime="image/png"
                        )
                        
                    # Error handling jika file terlalu besar
                    except ValueError as e:
                        st.error(f"Error: {e}")
                    except Exception as e:
                        st.error(f"An unexpected error occurred: {e}")
                else:
                    st.warning("Please upload an image and enter a message first.")

        # ========= Ddecode
        with decode_tab:
            st.subheader("Reveal a Secret Message from an Image")
            
            secret_file = st.file_uploader("1. Upload your secret image", type=["png", "bmp"], key="lsbm_decoder")
            
            if st.button("Reveal Message", key="lsbm_reveal_btn"):
                if secret_file is not None:
                    try:
                        secret_image = Image.open(secret_file)
                        
                        with st.spinner("Searching for hidden message..."):
                            revealed_message = steg_lsbm.reveal(secret_image)
                        
                        if revealed_message is not None:
                            st.success("Found a hidden message!")
                            st.text_area("Revealed Message:", value=revealed_message, height=150, key="lsbm_revealed_text")
                        else:
                            st.error("Could not find a hidden message. The image may be clean or the data corrupted.")
                            
                    except Exception as e:
                        st.error(f"An error occurred during decoding: {e}")
                else:
                    st.warning("Please upload an image to decode.")

# ======================
# Halaman log
# ======================
def main():
    if not st.session_state.logged_in:
        login_page()
    else:
        main_menu()


if __name__ == "__main__":
    main()
