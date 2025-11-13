from PIL import Image
import random

# batas akhir pesan
DELIMITER = "1111111111110000"

# konversi tiap karakter ASCII ke biner (8 bit), tambahin delimiter di akhir pesan
def _message_to_binary(message):
    binary_message = ''.join(format(ord(char), '08b') for char in message)
    return binary_message + DELIMITER

# kebalikannya di atas
def _binary_to_message(binary_string):
    chars = []
    for i in range(0, len(binary_string), 8):
        byte = binary_string[i:i+8]
        if len(byte) == 8:
            chars.append(chr(int(byte, 2)))
    return "".join(chars)

# gambar diproses dengan pillow, kemudian disisipi pesan
def hide(image, message):
    # cek mode warna gambar (harus RGB)
    if image.mode != 'RGB':
        image = image.convert('RGB')

    binary_message = _message_to_binary(message)
    width, height = image.size
    
    # jumlah bit yang bisa disisipkan = panjang x lebar x 3 (3 warna R,G,B)
    max_capacity = width * height * 3
    
    # cek ukuran pesan
    if len(binary_message) > max_capacity:
        raise ValueError(f"Pesan melebihi kapasitas maksimum: {max_capacity} bit, ukuran pesan: {len(binary_message)} bit!")

    # buat salinan gambar untuk menyimpan piksel yang dimodifikasi
    new_image = image.copy()
    pixels = new_image.load()
    
    bit_index = 0

    # ulangi sebanyak jumlah piksel dan salin nilai RGB yang sudah dimodifikasi
    for y in range(height):
        for x in range(width):
            if bit_index < len(binary_message):
                r, g, b = pixels[x, y]
                
                channels = [r, g, b]
                new_channels = []
                
                # sisipkan pesan ke tiap channel warna (rgb)
                for i in range(3):
                    if bit_index < len(binary_message):
                        channel_val = channels[i]
                        current_lsb = channel_val % 2
                        target_bit = int(binary_message[bit_index])
                        
                        # LSB matching, kalau nilai 0 maka ditambah 1, kalau 255 dikurang 1
                        if current_lsb != target_bit:
                            if channel_val == 0:
                                channel_val = 1
                            elif channel_val == 255:
                                channel_val = 254
                            else:
                                # selain 0 dan 255, nilai diubah secara acak (tambah atau kurang 1)
                                channel_val += random.choice([-1, 1])
                        
                        new_channels.append(channel_val)
                        bit_index += 1
                    else:
                        new_channels.append(channels[i])
                
                # isi sisa channel kalo bit habis di tengah pixel
                while len(new_channels) < 3:
                    new_channels.append(channels[len(new_channels)])
                    
                pixels[x, y] = tuple(new_channels)
            else:
                return new_image
                
    return new_image

def reveal(image):
    if image.mode != 'RGB':
        image = image.convert('RGB')
        
    pixels = image.load()
    width, height = image.size
    
    binary_string = ""
    
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            
            for channel_val in [r, g, b]:
                # ambil LSB dari tiap channel warna
                binary_string += str(channel_val % 2)
                
                # cek delimiter untuk mendapatkan batas akhir pesan
                if binary_string.endswith(DELIMITER):
                    message_part = binary_string[:-len(DELIMITER)]
                    return _binary_to_message(message_part)
    return None
