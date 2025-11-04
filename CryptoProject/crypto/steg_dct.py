# steg_dct.py
from PIL import Image
import numpy as np
from scipy.fftpack import dct, idct
import io

def embed_dct(image_bytes, message):
    """
    Menyisipkan pesan teks ke dalam gambar menggunakan algoritma DCT.
    """
    try:
        img = Image.open(io.BytesIO(image_bytes)).convert('L')
        img_array = np.array(img, dtype=np.int16)
        h, w = img_array.shape

        if h % 8 != 0 or w % 8 != 0:
            return "Error: Dimensi gambar harus habis dibagi 8."

        message += "####"
        binary_message = ''.join(format(ord(i), '08b') for i in message)
        
        required_bits = len(binary_message)
        total_pixels = h * w
        if required_bits > total_pixels:
            return "Error: Pesan terlalu panjang untuk disisipkan ke dalam gambar."

        data_index = 0
        for i in range(0, h, 8):
            for j in range(0, w, 8):
                if data_index >= required_bits:
                    break
                
                block = img_array[i:i+8, j:j+8]
                dct_block = dct(dct(block.T, norm='ortho').T, norm='ortho')
                
                for x in range(8):
                    for y in range(8):
                        if data_index < required_bits:
                            coeff_value = int(dct_block[x, y])
                            new_coeff_value = (coeff_value & 0b11111110) | int(binary_message[data_index])
                            dct_block[x, y] = new_coeff_value
                            data_index += 1
                        else:
                            break
                
                idct_block = idct(idct(dct_block.T, norm='ortho').T, norm='ortho')
                img_array[i:i+8, j:j+8] = idct_block.astype(np.int16)

            if data_index >= required_bits:
                break
        
        stego_img = Image.fromarray(img_array.astype(np.uint8))
        stego_bytes = io.BytesIO()
        stego_img.save(stego_bytes, format='PNG')
        return stego_bytes.getvalue()
    
    except Exception as e:
        return f"Error: {e}"


def extract_dct(stego_image_bytes):
    """
    Mengekstrak pesan dari gambar steganografi menggunakan algoritma DCT.
    """
    try:
        img = Image.open(io.BytesIO(stego_image_bytes)).convert('L')
        img_array = np.array(img, dtype=np.int16)
        h, w = img_array.shape

        if h % 8 != 0 or w % 8 != 0:
            return "Error: Dimensi gambar tidak valid untuk ekstraksi DCT."

        binary_message = ""
        stop_marker = "####"

        for i in range(0, h, 8):
            for j in range(0, w, 8):
                block = img_array[i:i+8, j:j+8]
                dct_block = dct(dct(block.T, norm='ortho').T, norm='ortho')

                for x in range(8):
                    for y in range(8):
                        coeff_value = int(dct_block[x, y])
                        binary_message += str(coeff_value & 1)
                        
                        # Cek setiap 8 bit apakah sudah ada penanda akhir pesan
                        if len(binary_message) % 8 == 0:
                            all_bytes = [binary_message[k:k+8] for k in range(0, len(binary_message), 8)]
                            extracted_char = chr(int(all_bytes[-1], 2))
                            
                            if extracted_char == stop_marker[len(stop_marker)-1] and stop_marker in ''.join([chr(int(b, 2)) for b in all_bytes]):
                                full_message = ''.join([chr(int(b, 2)) for b in all_bytes]).split(stop_marker)[0]
                                return full_message

        return "Error: Penanda akhir pesan tidak ditemukan. Pesan tidak valid."

    except Exception as e:
        return f"Error: {e}"
