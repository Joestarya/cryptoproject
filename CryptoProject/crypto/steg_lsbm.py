"""
Core logic for LSB Matching (LSB±1) Steganography.

This module provides functions to hide a message in an image and
reveal a message from an image. It uses LSB Matching for
encoding, which is more resistant to statistical analysis than
simple LSB.
"""

from PIL import Image
import random

# A 16-bit delimiter (e.g., 16 '1's) to mark the end of the message.
# We'll use a sequence that is unlikely to appear in normal text.
DELIMITER = "1111111111110000"

def _message_to_binary(message):
    """Converts a string message into a binary string, appending a delimiter."""
    # Convert each character to its 8-bit ASCII binary representation
    binary_message = ''.join(format(ord(char), '08b') for char in message)
    # Add the delimiter to signal the end of the message
    return binary_message + DELIMITER

def _binary_to_message(binary_string):
    """Converts a binary string back into an ASCII string."""
    chars = []
    for i in range(0, len(binary_string), 8):
        byte = binary_string[i:i+8]
        if len(byte) == 8:
            chars.append(chr(int(byte, 2)))
    return "".join(chars)

def hide(image, message):
    """
    Hides a secret message within an image using LSB Matching (LSB±1).
    
    Args:
        image (PIL.Image.Image): The cover image (opened with Pillow).
        message (str): The secret message to hide.

    Returns:
        PIL.Image.Image: A new image object with the message hidden.
    
    Raises:
        ValueError: If the message is too large to be hidden in the image.
    """
    
    # Ensure the image is in RGB mode
    if image.mode != 'RGB':
        image = image.convert('RGB')

    binary_message = _message_to_binary(message)
    width, height = image.size
    
    # Total available bits = width * height * 3 color channels
    max_capacity = width * height * 3
    
    if len(binary_message) > max_capacity:
        raise ValueError(f"Message is too large. Max capacity: {max_capacity} bits. Message size: {len(binary_message)} bits.")

    # Create a new image to store the modified pixels
    new_image = image.copy()
    pixels = new_image.load()
    
    bit_index = 0
    
    for y in range(height):
        for x in range(width):
            if bit_index < len(binary_message):
                r, g, b = pixels[x, y]
                
                # List of channels to embed in: R, G, B
                channels = [r, g, b]
                new_channels = []
                
                for i in range(3): # Iterate over R, G, B channels
                    if bit_index < len(binary_message):
                        channel_val = channels[i]
                        current_lsb = channel_val % 2
                        target_bit = int(binary_message[bit_index])
                        
                        if current_lsb != target_bit:
                            # --- This is the LSB Matching (LSB±1) logic ---
                            if channel_val == 0:
                                # Can't subtract, must add
                                channel_val = 1
                            elif channel_val == 255:
                                # Can't add, must subtract
                                channel_val = 254
                            else:
                                # Randomly add or subtract 1
                                channel_val += random.choice([-1, 1])
                        
                        new_channels.append(channel_val)
                        bit_index += 1
                    else:
                        new_channels.append(channels[i]) # No more bits, append original value
                
                # Fill in remaining channels if we ran out of bits mid-pixel
                while len(new_channels) < 3:
                    new_channels.append(channels[len(new_channels)])
                    
                pixels[x, y] = tuple(new_channels)
            else:
                # No more bits to hide, we can stop processing
                return new_image
                
    return new_image

def reveal(image):
    """
    Reveals a secret message from an image hidden with LSB.
    
    Args:
        image (PIL.Image.Image): The image containing the hidden message.

    Returns:
        str: The hidden message, or None if no message/delimiter is found.
    """
    
    # Ensure the image is in RGB mode
    if image.mode != 'RGB':
        image = image.convert('RGB')
        
    pixels = image.load()
    width, height = image.size
    
    binary_string = ""
    
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            
            for channel_val in [r, g, b]:
                # Extract the LSB (this is the same for LSB and LSBM)
                binary_string += str(channel_val % 2)
                
                # Check if the end of the string matches our delimiter
                if binary_string.endswith(DELIMITER):
                    # Delimiter found! Get the message part.
                    message_part = binary_string[:-len(DELIMITER)]
                    return _binary_to_message(message_part)
    
    # If we get through the whole image and no delimiter was found
    return None
