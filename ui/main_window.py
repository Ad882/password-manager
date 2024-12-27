import tkinter as tk
from tkinter import messagebox, scrolledtext
from database.database import Database
from security import Security
import base64
from utils import generate_password

class PasswordManagerApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Password Manager")
        self.master.geometry("400x400")
        self.security = Security(master_password_file="master_password.txt", db=Database("database/passwords.db"))

        # Master Password Section
        self.lbl_master = tk.Label(master, text="Enter Master Password:")
        self.lbl_master.pack(pady=10)
        self.entry_master = tk.Entry(master, show="*")
        self.entry_master.pack(pady=5)
        self.btn_login = tk.Button(master, text="Login", command=self.verify_master_password)
        self.btn_login.pack(pady=10)

        # Password Manager Section (Hidden initially)
        self.frame_manager = tk.Frame(master)
        self.lbl_site = tk.Label(self.frame_manager, text="Site:")
        self.lbl_site.grid(row=0, column=0, pady=5)
        self.entry_site = tk.Entry(self.frame_manager)
        self.entry_site.grid(row=0, column=1, pady=5)

        self.lbl_password = tk.Label(self.frame_manager, text="Password:")
        self.lbl_password.grid(row=1, column=0, pady=5)
        self.entry_password = tk.Entry(self.frame_manager, show="*")
        self.entry_password.grid(row=1, column=1, pady=5)

        self.lbl_username = tk.Label(self.frame_manager, text="Username:")
        self.lbl_username.grid(row=2, column=0, pady=5)
        self.entry_username = tk.Entry(self.frame_manager)
        self.entry_username.grid(row=2, column=1, pady=5)

        self.btn_save = tk.Button(self.frame_manager, text="Save Password", command=self.save_password)
        self.btn_save.grid(row=3, columnspan=2, pady=10)

        self.btn_save = tk.Button(self.frame_manager, text="Generate Password", command=self.generate_password)
        self.btn_save.grid(row=4, columnspan=2, pady=10)

        self.btn_show = tk.Button(self.frame_manager, text="Show Password", command=self.show_password)
        self.btn_show.grid(row=5, columnspan=2, pady=10)

        self.btn_show_all = tk.Button(self.frame_manager, text="Show All", command=self.show_all)
        self.btn_show_all.grid(row=6, columnspan=2, pady=10)

        self.btn_show_all = tk.Button(self.frame_manager, text="Delete Password", command=self.delete_password)
        self.btn_show_all.grid(row=7, columnspan=2, pady=10)

    def verify_master_password(self):
        master_password = self.entry_master.get()
        if self.security.verify_master_password(master_password):
            messagebox.showinfo("Success", "Master password verified!")
            self.show_manager_ui()
        else:
            messagebox.showerror("Error", "Incorrect master password.")

    def show_manager_ui(self):
        self.lbl_master.pack_forget()
        self.entry_master.pack_forget()
        self.btn_login.pack_forget()
        self.frame_manager.pack(pady=20)

    def save_password(self):
        site = self.entry_site.get()
        username = self.entry_username.get()
        password = self.entry_password.get()
        master_password = self.entry_master.get()
        enc_data = self.security.encrypt(password, master_password)
        salt_base64, encrypted_password = enc_data.split(":", 1)
        salt = base64.urlsafe_b64decode(salt_base64)

        self.security.db.add_password(site, username, encrypted_password, salt)
        messagebox.showinfo("Success", f"Password for {site} saved!")
        self.entry_site.delete(0, tk.END)
        self.entry_username.delete(0, tk.END)
        self.entry_password.delete(0, tk.END)

    def show_password(self):
        site = self.entry_site.get()
        master_password = self.entry_master.get()
        results = self.security.db.get_password(site)
        if results:
            for index, record in enumerate(results, start=1):
                username = record['username']
                enc_password = record['password']
                salt = record['salt']
                decoded_salt = base64.urlsafe_b64encode(salt).decode()
                data_with_salt = decoded_salt + ":" + enc_password
                password = self.security.decrypt(data_with_salt, master_password)
                messagebox.showinfo("Password", f"Site: {site}\nUsername: {username}\nPassword: {password}")
        else:
            messagebox.showerror("Error", "No password found for this site.")

    def generate_password(self):
        site = self.entry_site.get()
        username = self.entry_username.get()
        password = generate_password()
        master_password = self.entry_master.get()
        enc_data = self.security.encrypt(password, master_password)
        salt_base64, encrypted_password = enc_data.split(":", 1)
        salt = base64.urlsafe_b64decode(salt_base64)

        self.security.db.add_password(site, username, encrypted_password, salt)
        messagebox.showinfo("Success", f"Password for {site} saved!")
        self.entry_site.delete(0, tk.END)
        self.entry_username.delete(0, tk.END)
        self.entry_password.delete(0, tk.END)

    def show_all(self):
        master_password = self.entry_master.get()
        passwords = self.security.db.list_all_passwords()
        if passwords:
            all_passwords = []
            for site, username, enc_password, salt in passwords:
                decoded_salt = base64.urlsafe_b64encode(salt).decode()
                data_with_salt = decoded_salt + ":" + enc_password
                try:
                    password = self.security.decrypt(data_with_salt, master_password)
                    all_passwords.append(f"Site: {site}\nUsername: {username}\nPassword: {password}\n")
                except Exception as e:
                    all_passwords.append(f"Site: {site}\nError decrypting password: {e}\n")
            
            # Display passwords in a scrolled text widget
            all_passwords_text = "\n".join(all_passwords)
            popup = tk.Toplevel(self.master)
            popup.title("All Passwords")
            popup.geometry("500x400")
            text_area = scrolledtext.ScrolledText(popup, wrap=tk.WORD, width=60, height=20)
            text_area.insert(tk.END, all_passwords_text)
            text_area.config(state=tk.DISABLED)
            text_area.pack(pady=10)
        else:
            messagebox.showinfo("Info", "No passwords stored.")


    def delete_password(self):
        site = self.entry_site.get()
        username = self.entry_username.get()
        self.security.db.delete_password(site, username)

        messagebox.showinfo("Success", f"Password deleted!")
        self.entry_site.delete(0, tk.END)
        self.entry_username.delete(0, tk.END)
        self.entry_password.delete(0, tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()
