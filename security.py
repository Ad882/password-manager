from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import bcrypt
import os 

class Security:
    def __init__(self, master_password_file="master_password.txt", db=None):
        self.master_password_file = master_password_file
        self.db = db
        
    def initialize_master_password(self, master_password: str) -> None:
        try:
            hashed_password = bcrypt.hashpw(master_password.encode(), bcrypt.gensalt())
            if self.db:
                self.db.store_master_password(hashed_password)

            with open(self.master_password_file, "wb") as file:
                file.write(hashed_password)

            print("Master password initialized successfully.")
        except Exception as e:
            print(f"Error initializing master password: {e}")

    def create_cipher(self, master_password: str) -> None:
        salt = os.urandom(16)
        self.salt = salt
        key = self._derive_key(master_password, salt)
        self.cipher = Fernet(key)

    def _derive_key(self, master_password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))

    def encrypt(self, data: str, master_password: str) -> str:
        self.create_cipher(master_password)
        combined_data = (master_password + data).encode()
        encrypted_data = self.cipher.encrypt(combined_data).decode()
        return base64.urlsafe_b64encode(self.salt).decode() + ":" + encrypted_data

    def decrypt(self, enc_data: str, master_password: str) -> str:
        salt_base64, encrypted_data = enc_data.split(":", 1)
        salt = base64.urlsafe_b64decode(salt_base64)

        key = self._derive_key(master_password, salt)
        self.cipher = Fernet(key)

        decrypted = self.cipher.decrypt(encrypted_data.encode()).decode()
        return decrypted.replace(master_password, "")

    def verify_master_password(self, master_password: str) -> bool:
        try:
            with open(self.master_password_file, "rb") as file:
                stored_hashed_password = file.read()
            return bcrypt.checkpw(master_password.encode(), stored_hashed_password)
        except FileNotFoundError:
            print("Error: Master password file not found.")
            return False
        except Exception as e:
            print(f"Error verifying master password: {e}")
            return False

    def check_consistency(self) -> bool:
        with open(self.master_password_file, "r") as file:
            file_password_hash = file.readline().strip()
        
        if self.db:
            db_password_hash = self.db.get_stored_master_password()
        else: 
            None
        return file_password_hash == db_password_hash.decode()
