import getpass
import hashlib
import bcrypt
from utils.validator import validate_credentials

class Authentication:
    def __init__(self, config_manager):
        self.config = config_manager
        self.max_attempts = 3
        
    def authenticate(self):
        attempts = 0
        while attempts < self.max_attempts:
            user = input("Username: ").strip()
            passwd = getpass.getpass("Password: ")
            
            if validate_credentials(user, passwd):
                stored_hash = self.config.get('auth').get(user)
                if stored_hash and bcrypt.checkpw(passwd.encode(), stored_hash.encode()):
                    return True
            attempts += 1
            print(f"Authentication failed. Attempts remaining: {self.max_attempts - attempts}")
        return False