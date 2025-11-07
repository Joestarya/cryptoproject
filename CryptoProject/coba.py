import streamlit as st
import base64

st.title("🔐 Aplikasi Enkripsi Sederhana")

# Input teks
teks = st.text_area("Masukkan teks yang ingin dienkripsi:")

if st.button("Enkripsi"):
    if teks:
        # Contoh proses enkripsi sederhana (base64)
        encoded = base64.b64encode(teks.encode()).decode()
        key = base64.b64encode(b"key123").decode()

        st.success("✅ Teks telah dienkripsi!")

        # Tampilkan hasil dan key dengan tombol copy otomatis
        st.subheader("Hasil Enkripsi:")
        st.code(encoded, language=None)

        st.subheader("Kunci:")
        st.code(key, language=None)

    else:
        st.warning("Masukkan teks terlebih dahulu!")