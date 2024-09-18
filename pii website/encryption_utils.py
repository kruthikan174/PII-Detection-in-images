from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

# Function to generate a key and IV
def generate_key_iv():
    key = os.urandom(32)  # 256-bit key
    iv = os.urandom(16)   # 128-bit IV
    return key, iv

# Function to encrypt text
def encrypt_text(text, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Pad text to be multiple of block size
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_text = padder.update(text.encode()) + padder.finalize()
    
    encrypted_text = encryptor.update(padded_text) + encryptor.finalize()
    return encrypted_text

# Function to decrypt text
def decrypt_text(encrypted_text, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    decrypted_padded_text = decryptor.update(encrypted_text) + decryptor.finalize()
    
    # Unpad text
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_text = unpadder.update(decrypted_padded_text) + unpadder.finalize()
    
    return decrypted_text.decode()
