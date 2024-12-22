from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64

class Security:
    def __init__(self, master_password_file="master_password.txt"):
        self.master_password_file = master_password_file
        self.cipher = None

    def initialize_master_password(self, master_password: str) -> None:
        try:
            with open(self.master_password_file, "w") as file:
                file.write(master_password + "\n")
            print("Master password initialized successfully.")
            self.create_cipher(master_password)
        except Exception as e:
            print(f"Error initializing master password: {e}")

    def create_cipher(self, master_password: str) -> None:
        salt = b"static_salt_for_key_derivation"  
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
        return self.cipher.encrypt(combined_data).decode()

    def decrypt(self, enc_data: str, master_password: str) -> str:
        self.create_cipher(master_password) 
        decrypted = self.cipher.decrypt(enc_data.encode()).decode()
        return decrypted.replace(master_password, "")

    def verify_master_password(self, master_password: str) -> bool:
        try:
            with open(self.master_password_file, "r") as file:
                stored_password = file.readline().strip()
            return master_password == stored_password
        except FileNotFoundError:
            print("Error: Master password file not found.")
            return False
