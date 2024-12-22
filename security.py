from cryptography.fernet import Fernet

class Security:
    def __init__(self, master_password_file="master_password.txt"):
        self.master_password_file = master_password_file

    def initialize_master_password(self, master_password: str) -> None:
        try:
            with open(self.master_password_file, "w") as file:
                file.write(master_password + "\n")
            print("Master password initialized successfully.")
        except Exception as e:
            print(f"Error initializing master password: {e}")

    def encrypt(self, data, master_password):
        combined_data = (master_password + data).encode()
        return self.cipher.encrypt(combined_data).decode()

    def decrypt(self, enc_data, master_password):
        decrypted = self.cipher.decrypt(enc_data.encode()).decode()
        return decrypted.replace(master_password, "")

    def verify_master_password(self, master_password):
        try:
            with open(self.master_password_file, "r") as file:
                stored_password = file.readline().strip()
            return master_password == stored_password
        except FileNotFoundError:
            print("Error: Master password file not found.")
            return False