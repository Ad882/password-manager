import os
import getpass
import tkinter as tk
from ui.main_window import PasswordManagerApp
from security import Security
from database.database import Database

def main():
    master_password_file = "master_password.txt"
    db_path = "database/passwords.db"

    if not os.path.exists(master_password_file):
        if os.path.exists(db_path):
            os.remove(db_path)
        db = Database(db_path)
        security = Security(db=db)
        master_password = getpass.getpass("Entrez un nouveau mot de passe maître: ")
        security.initialize_master_password(master_password)
    
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()