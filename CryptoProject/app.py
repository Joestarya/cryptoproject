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

    # Pastikan super_key tidak berubah walau rerun
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
            "Super Teks Enkripsi dan Dekripsi",
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
        st.title("📝 Text Enkripsi dengan menggunakan algoritma ChaCha20-Poly1305")
        st.info("ChaCha20-Poly1305 adalah algoritma enkripsi simetris yang menggabungkan kecepatan dan keamanan. ChaCha20 adalah algoritma stream cipher yang dirancang untuk efisiensi tinggi pada perangkat lunak, sementara Poly1305 adalah algoritma autentikasi pesan yang memberikan integritas data. Kombinasi keduanya menghasilkan enkripsi yang kuat dan cepat, sering digunakan dalam protokol keamanan seperti TLS.")   

    # ========= Generasi (refresh) kunci baru
        if "text_key" not in st.session_state:
            st.session_state.text_key = chacha_text.generate_key()

        col1, col2 = st.columns([3, 1])
        
        with col1:
            st.subheader("Kunci (base64)")
            st.code(
                chacha_text.key_to_str(st.session_state.text_key),
                language=None
            )

        with col2:
            if st.button("🔁 Refresh Kunci"):
                st.session_state.text_key = chacha_text.generate_key()
                st.rerun()

        st.divider()
        st.subheader("🔒 Enkripsi Teks")
        plaintext = st.text_area("Masukkan teks untuk dienkripsi", "")

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
                st.text("Hasil enkripsi")
                st.code(st.session_state.last_ciphertext, language="plaintext")
                st.text("Hasil nonce")
                st.code(st.session_state.last_nonce, language="plaintext")

        # ========= Decrypt
        st.divider()
        st.subheader("🔓 Dekripsi Teks")

        # Manual input agar user bisa menggunakan key sebelumnya
        manual_text_key = st.text_input(
            "Kunci (base64)",
            value=chacha_text.key_to_str(st.session_state.text_key),
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

    # ====================================================
    # Super Teks Enkripsi dan Dekripsi
    # ====================================================
    elif menu == "Super Teks Enkripsi dan Dekripsi":
        st.title("🌀 Super Text Encryption menggunakan algoritma (Reverse + Fernet, 2-Step Enkripsi)") 
        st.info("Super Text Encryption adalah metode enkripsi yang menggabungkan dua teknik enkripsi berbeda untuk meningkatkan " \
        "keamanan data. Pertama, teks asli dibalik (reverse) untuk mengacak urutan karakter, menambah lapisan kerumitan. " \
        "Kemudian, teks yang telah dibalik dienkripsi menggunakan algoritma Fernet, yang menyediakan enkripsi simetris dengan " \
        "autentikasi pesan. Kombinasi kedua langkah ini menghasilkan enkripsi yang lebih kuat dan sulit dipecahkan dibandingkan " \
        "menggunakan satu metode saja.")

        # ========= Setup kunci
        if "super_cipher" not in st.session_state:
            st.session_state.super_cipher = ""

        if "super_key" not in st.session_state:
            st.session_state.super_key = Fernet.generate_key().decode()
            st.session_state.super_key_saved = st.session_state.super_key
        else:
            if "super_key_saved" in st.session_state:
                st.session_state.super_key = st.session_state.super_key_saved

        cold1, cold2 = st.columns([3, 1])

        with cold1:
            st.subheader("Kunci (base64)")
            st.code(
                st.session_state.super_key,
                language=None
            )
        with cold2:
            if st.button("🔁 Refresh Kunci"):
                st.session_state.super_key = Fernet.generate_key().decode()
                st.session_state.super_key_saved = st.session_state.super_key
                st.rerun()

        # ========= Encrypt
        st.subheader("🔒 Enkripsi Super")
        plaintext = st.text_area("Masukkan teks untuk dienkripsi")

        if st.button("Enkripsi"):
            if plaintext.strip() == "":
                st.warning("Wajib memasukkan teks untuk dienkripsi!")
            else:
                reversed_text = step1_reverse_encrypt(plaintext)
                fernet_text = step2_fernet_encrypt(reversed_text, st.session_state.super_key)
                
                st.success("✅ Teks berhasil dienkripsi!")
                st.text("Hasil enkripsi tahap 1 (Reverse)")
                st.code(reversed_text, language=None)
                st.text("Hasil akhir enkripsi (Fernet)")
                st.code(st.session_state.super_cipher, language=None)

                st.session_state.last_reversed = reversed_text
                st.session_state.super_cipher = fernet_text

        st.divider()

        # ========= Decrypt Super
        st.subheader("🔓 Dekripsi Super")

        manual_super_key = st.text_input(
            "Kunci Fernet (base64)",
            value=st.session_state.get("super_key", ""),
        )

        # auto-isi ciphertext dari hasil terakhir
        cipher_in = st.text_area(
            "Masukkan ciphertext super (base64):",
            st.session_state.get("super_cipher", "")
        )

        if st.button("Dekripsi"):
            if cipher_in.strip() == "":
                st.warning("Wajib mengisi ciphertext!")
            else:
                key_to_use = manual_super_key.strip() if manual_super_key.strip() != "" else st.session_state.super_key
                try:
                    result = super_decrypt(cipher_in, key_to_use)
                    st.success("✅ Teks berhasil didekripsi")
                    st.text_area("Hasil dekripsi (plaintext)", result, height=100)
                except Exception as e:
                    st.error(f"❌ Dekripsi gagal: {e}")

    # ====================================================
    # File Encryption (XChaCha20-Poly1305)
    # ====================================================
    elif menu == "File Enkripsi dan Dekripsi":
        st.title("🗂️ File Encryption Menggunakan Algoritma XChaCha20-Poly1305")
        st.info("XChaCha20-Poly1305 adalah algoritma enkripsi yang kuat dan aman, cocok untuk enkripsi file karena kemampuannya" \
        "menangani nonce yang lebih panjang dan memberikan integritas data melalui autentikasi.")    

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

        colk1, colk2 = st.columns([3, 1])
        with colk1:
            st.subheader("Kunci (base64)")
            st.code(
                st.session_state.file_key,
                language=None
            )
        with colk2:
            if st.button("🔁 Refresh Kunci"):
                st.session_state.file_key = generate_key_b64()
                st.session_state.file_key_saved = st.session_state.file_key
                st.success("Kunci baru telah dibuat!")
                st.rerun()

        st.divider()

        # ========= Encrypt
        st.subheader("🔒 Enkripsi File")
        uploaded = st.file_uploader("Upload file yang ingin dienkripsi", type=None, key="upload_enc")

        if uploaded is not None:
            file_bytes = uploaded.read()
            st.write(f"Filename: {uploaded.name} — Size: {len(file_bytes)} bytes")

            if st.button("Enkripsi"):
                try:
                    ct_b64, nonce_b64 = encrypt_file_bytes(file_bytes, st.session_state.file_key)
                    st.session_state.file_cipher = ct_b64
                    st.session_state.file_nonce = nonce_b64

                    ct_bytes = base64.b64decode(ct_b64)
                    suggested_name = uploaded.name + ".enc"

                    st.success("✅ File berhasil dienkripsi!")
                    st.code(f"Ciphertext (base64):\n{st.session_state.file_cipher}", language="text")
                    st.code(f"Nonce (base64):\n{st.session_state.file_nonce}", language="text")

                    st.download_button(
                        label="⬇️ Download file yang sudah dienkripsi (.enc)",
                        data=ct_bytes,
                        file_name=suggested_name,
                        mime="application/octet-stream"
                    )

                except Exception as e:
                    st.error(str(e))

        st.divider()

        # ========= decrypt
        st.subheader("🔓 Dekripsi File")

        manual_file_key = st.text_input(
            "Kunci (base64, 32-byte)",
            value=st.session_state.get("file_key", ""),
        )

        uploaded_ct = st.file_uploader("Upload file berupa chipertext (.enc)", type=None, key="upload_dec")

        # auto fill
        ct_b64_input = st.text_area(
            "Atau masukkan ciphertext (base64):",
            value=st.session_state.get("file_cipher", ""),
            height=80
        )
        nonce_input = st.text_input(
            "Nonce (base64):",
            value=st.session_state.get("file_nonce", "")
        )

        target_name = st.text_input("Nama file", value="decrypted_output")

        if st.button("Dekripsi"):
            try:
                key_to_use = manual_file_key.strip() if manual_file_key.strip() != "" else st.session_state.file_key

                if uploaded_ct is not None:
                    raw_ct = uploaded_ct.read()
                    ct_b64 = base64.b64encode(raw_ct).decode()
                else:
                    ct_b64 = ct_b64_input.strip()

                if not ct_b64:
                    st.warning("Masukkan ciphertext (upload .enc or paste Base64)")
                elif not nonce_input.strip():
                    st.warning("Masukkan nonce (Base64)")
                else:
                    plaintext_bytes = decrypt_file_bytes(ct_b64, nonce_input.strip(), key_to_use)
                    st.success("✅ File berhasil didekripsi!")
                    st.download_button(
                        label="⬇️ Download file yang sudah didekripsi",
                        data=plaintext_bytes,
                        file_name=target_name,
                        mime="application/octet-stream"
                    )
            except Exception as e:
                st.error(f"❌ Dekripsi gagal: {e}")

    # ====================================================
    # Steganography: LSB Matching (LSB±1)
    # ====================================================
    elif menu == "Steganography":
        st.title("🖼️ Steganography menggunakan algoritma LSB-Matching")
        st.info("LSB-Matching (Least Significant Bit Matching) adalah teknik steganografi yang menyembunyikan pesan rahasia dalam " \
        "citra digital dengan memodifikasi bit-bit paling tidak signifikan dari piksel-piksel citra tersebut. Teknik ini bertujuan " \
        "untuk menyembunyikan informasi tanpa mengubah kualitas visual citra secara signifikan.")
        encode_tab, decode_tab = st.tabs(["🔒 Encode", "🔓 Decode"])

        # ========= encode
        with encode_tab:
            st.subheader("Sisipkan pesan rahasia dalam gambar")
            
            uploaded_image = st.file_uploader("Upload cover image untuk menyisipkan pesan (PNG, BMP)", type=["png", "bmp"], key="lsbm_uploader")
            message = st.text_area("Masukkan pesan rahasia", height=150, key="lsbm_message")
            
            if st.button("Encode", key="lsbm_hide_btn"):
                if uploaded_image is not None and message:
                    try:
                        # gambar dibuka dalam bentuk PILLOW
                        cover_image = Image.open(uploaded_image)
                        
                        with st.spinner("Menyisipkan pesan dalam gambar"):
                            secret_image = steg_lsbm.hide(cover_image, message)
                        
                        st.success("Pesan telah berhasil disisipkan!")
                        st.image(secret_image, caption="Gambar berisi pesan rahasia")
                        
                        # Konversi PILLOW ke bytes
                        buf = BytesIO()
                        secret_image.save(buf, format="PNG")
                        byte_im = buf.getvalue()
                        
                        st.download_button(
                            label="Download gambar (PNG)",
                            data=byte_im,
                            file_name="secret_image.png",
                            mime="image/png"
                        )
                        
                    # Error handling jika file terlalu besar
                    except ValueError as e:
                        st.error(f"Error: {e}")
                    except Exception as e:
                        st.error(f"Pastikan format dan ukuran memenuhi aturan: {e}")
                else:
                    st.warning("Wajib menyediakan cover image dan pesan untuk disisipkan!")

        # ========= Ddecode
        with decode_tab:
            st.subheader("Pecahkan pesan rahasia dalam gambar")
            
            secret_file = st.file_uploader("Upload gambar yang disisipi pesan", type=["png", "bmp"], key="lsbm_decoder")
            
            if st.button("Decode", key="lsbm_reveal_btn"):
                if secret_file is not None:
                    try:
                        secret_image = Image.open(secret_file)
                        
                        with st.spinner("Memecahkan pesan dalam gambar"):
                            revealed_message = steg_lsbm.reveal(secret_image)
                        
                        if revealed_message is not None:
                            st.success("Pesan rahasia telah dipecahkan!")
                            st.text_area("Pesan:", value=revealed_message, height=150, key="lsbm_revealed_text")
                        else:
                            st.error("Tidak ditemukan pesan rahasia")
                            
                    except Exception as e:
                        st.error(f"Error pada saat proses decode, silakan coba lagi: {e}")
                else:
                    st.warning("Wajib menyediakan gambar untuk memecahkan pesan rahasia!")

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
