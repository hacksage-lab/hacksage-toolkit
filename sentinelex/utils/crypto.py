from cryptography.fernet import Fernet
import base64
import os

def generate_key():
    return base64.urlsafe_b64encode(os.urandom(32))

def encrypt_config(data, key):
    f = Fernet(key)
    return f.encrypt(data)
    
def decrypt_config(encrypted_data, key):
    f = Fernet(key)
    return f.decrypt(encrypted_data)