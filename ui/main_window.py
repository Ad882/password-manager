import tkinter as tk
from tkinter import messagebox, scrolledtext
from database.database import Database
from security import Security
import base64
from utils import generate_password
from PIL import Image, ImageTk
from tkinter.font import Font

class PasswordManagerApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Password Manager")
        self.master.geometry("600x400")
        self.master.resizable(False, False)

        self.background_image = Image.open("resources/background.webp")
        self.background_image = self.background_image.resize((600, 400), Image.Resampling.LANCZOS)
        self.bg_photo = ImageTk.PhotoImage(self.background_image)
        self.bg_label = tk.Label(master, image=self.bg_photo)
        self.bg_label.place(x=0, y=0, relwidth=1, relheight=1)

        self.icon_add = ImageTk.PhotoImage(Image.open("resources/icons/add.png").resize((40, 40), Image.Resampling.LANCZOS))
        self.icon_generate = ImageTk.PhotoImage(Image.open("resources/icons/generate.png").resize((40, 40), Image.Resampling.LANCZOS))
        self.icon_delete = ImageTk.PhotoImage(Image.open("resources/icons/delete.png").resize((40, 40), Image.Resampling.LANCZOS))
        self.icon_show = ImageTk.PhotoImage(Image.open("resources/icons/show.png").resize((40, 40), Image.Resampling.LANCZOS))
        self.icon_show_all = ImageTk.PhotoImage(Image.open("resources/icons/show_all.png").resize((40, 40), Image.Resampling.LANCZOS))


        self.security = Security(master_password_file="master_password.txt", db=Database("database/passwords.db"))

        # Master Password Section
        self.entry_master = tk.Entry(master, show="*")
        self.entry_master.pack(pady=38)
        self.entry_master.focus_set()
        self.btn_login = tk.Button(master, text="Login", command=self.verify_master_password)
        self.btn_login.pack(pady=10)
        self.master.bind("<Return>", lambda event: self.verify_master_password())

        # Main Menu Section
        self.frame_menu = tk.Frame(master)
        self.btn_add = tk.Button(self.frame_menu, text="Add Password", image=self.icon_add, compound="left", command=lambda: self.show_action_ui("add"))
        self.btn_add.grid(row=0, column=0, padx=10, pady=10)
        self.btn_generate = tk.Button(self.frame_menu, text="Generate Password", image=self.icon_generate, compound="left", command=lambda: self.show_action_ui("generate"))
        self.btn_generate.grid(row=0, column=1, padx=10, pady=10)
        self.btn_delete = tk.Button(self.frame_menu, text="Delete Password", image=self.icon_delete, compound="left", command=lambda: self.show_action_ui("delete"))
        self.btn_delete.grid(row=1, column=0, padx=10, pady=10)
        self.btn_show = tk.Button(self.frame_menu, text="Show Password", image=self.icon_show, compound="left", command=lambda: self.show_action_ui("show"))
        self.btn_show.grid(row=1, column=1, padx=10, pady=10)
        self.btn_show_all = tk.Button(self.frame_menu, text="Show All", image=self.icon_show_all, compound="left", command=self.show_all)
        self.btn_show_all.grid(row=2, columnspan=2, pady=10)

        self.frame_action = tk.Frame(master)
        self.lbl_site = tk.Label(self.frame_action, text="Site:")
        self.lbl_site.grid(row=0, column=0, pady=5)
        self.entry_site = tk.Entry(self.frame_action)
        self.entry_site.grid(row=0, column=1, pady=5)

        self.lbl_username = tk.Label(self.frame_action, text="Username:")
        self.lbl_username.grid(row=1, column=0, pady=5)
        self.entry_username = tk.Entry(self.frame_action)
        self.entry_username.grid(row=1, column=1, pady=5)

        self.lbl_password = tk.Label(self.frame_action, text="Password:")
        self.entry_password = tk.Entry(self.frame_action, show="*")

        self.btn_confirm_action = tk.Button(self.frame_action, text="Confirm", command=self.handle_action)
        self.btn_confirm_action.grid(row=3, columnspan=2, pady=10)
        self.btn_exit_action = tk.Button(self.frame_action, text="Exit", command=self.show_main_menu)
        self.btn_exit_action.grid(row=4, columnspan=2, pady=10)

    def verify_master_password(self):
        master_password = self.entry_master.get()
        if self.security.verify_master_password(master_password):
            messagebox.showinfo("Success", "Master password verified!")
            self.show_main_menu()
        else:
            messagebox.showerror("Error", "Incorrect master password.")

    def show_main_menu(self):
        self.frame_action.pack_forget()
        self.entry_master.pack_forget()
        self.btn_login.pack_forget()
        self.frame_menu.pack(pady=20)
        self.current_action = None

    def show_action_ui(self, action):
        self.frame_menu.pack_forget()
        self.frame_action.pack(pady=20)
        self.current_action = action

        if action == "add":
            self.lbl_password.grid(row=2, column=0, pady=5)
            self.entry_password.grid(row=2, column=1, pady=5)
        else:
            self.lbl_password.grid_forget()
            self.entry_password.grid_forget()

    def handle_action(self):
        site = self.entry_site.get()
        username = self.entry_username.get()
        master_password = self.entry_master.get()

        if self.current_action == "add":
            password = self.entry_password.get()
            if not password:
                messagebox.showerror("Error", "Please enter a password.")
                return

            enc_data = self.security.encrypt(password, master_password)
            salt_base64, encrypted_password = enc_data.split(":", 1)
            salt = base64.urlsafe_b64decode(salt_base64)
            self.security.db.add_password(site, username, encrypted_password, salt)
            messagebox.showinfo("Success", f"Password for {site} added!")

        elif self.current_action == "generate":
            password = generate_password()
            enc_data = self.security.encrypt(password, master_password)
            salt_base64, encrypted_password = enc_data.split(":", 1)
            salt = base64.urlsafe_b64decode(salt_base64)
            self.security.db.add_password(site, username, encrypted_password, salt)
            messagebox.showinfo("Success", f"Password for {site} generated and saved!")

        elif self.current_action == "delete":
            self.security.db.delete_password(site, username)
            messagebox.showinfo("Success", f"Password for {site} deleted!")

        elif self.current_action == "show":
            results = self.security.db.get_password(site)
            if results:
                for record in results:
                    enc_password = record['password']
                    salt = record['salt']
                    decoded_salt = base64.urlsafe_b64encode(salt).decode()
                    data_with_salt = decoded_salt + ":" + enc_password
                    password = self.security.decrypt(data_with_salt, master_password)
                    messagebox.showinfo("Password", f"Site: {site}\nUsername: {username}\nPassword: {password}")
            else:
                messagebox.showerror("Error", "No password found for this site.")

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

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()