import tkinter as tk
from tkinter import messagebox, scrolledtext
from database.database import Database
from security import Security
import base64
from utils import generate_password
from PIL import Image, ImageTk
from tkinter.font import Font
import webbrowser

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
        self.master.bind("<Escape>", lambda event: self.master.destroy())

        # Main Menu Section
        self.btn_add = tk.Button(master, text="Add Password", image=self.icon_add, compound="left", 
                                 command=lambda: self.show_action_ui("add"), bd=0, bg="white", activebackground="white")
        self.btn_add.place(x=80, y=100)

        self.btn_generate = tk.Button(master, text="Generate Password", image=self.icon_generate, compound="left", 
                                      command=lambda: self.show_action_ui("generate"), bd=0, bg="white", activebackground="white")
        self.btn_generate.place(x=350, y=100)

        self.btn_delete = tk.Button(master, text="Delete Password", image=self.icon_delete, compound="left", 
                                    command=lambda: self.show_action_ui("delete"), bd=0, bg="white", activebackground="white")
        self.btn_delete.place(x=75, y=200)

        self.btn_show = tk.Button(master, text="Show Password", image=self.icon_show, compound="left", 
                                  command=lambda: self.show_action_ui("show"), bd=0, bg="white", activebackground="white")
        self.btn_show.place(x=360, y=200)

        self.btn_show_all = tk.Button(master, text="Show All", image=self.icon_show_all, compound="left", 
                                      command=self.show_all, bd=0, bg="white", activebackground="white")
        self.btn_show_all.place(x=245, y=340)


        self.hide_menu_buttons()

        self.frame_action = tk.Frame(master)
        self.lbl_site = tk.Label(self.frame_action, text="Site:")
        self.lbl_site.grid(row=0, column=0, pady=10)
        self.entry_site = tk.Entry(self.frame_action)
        self.entry_site.grid(row=0, column=3, pady=10)

        self.lbl_username = tk.Label(self.frame_action, text="Username:")
        self.lbl_username.grid(row=1, column=0, pady=10)
        self.entry_username = tk.Entry(self.frame_action)
        self.entry_username.grid(row=1, column=3, pady=10)

        self.lbl_password = tk.Label(self.frame_action, text="Password:")
        self.entry_password = tk.Entry(self.frame_action, show="*")

        self.btn_confirm_action = tk.Button(self.frame_action, text="Confirm", command=self.handle_action)
        self.btn_confirm_action.grid(row=5, columnspan=4, pady=5)
        self.btn_exit_action = tk.Button(self.frame_action, text="Exit", command=self.show_main_menu)
        self.btn_exit_action.grid(row=6, columnspan=4, pady=5)


    def hide_menu_buttons(self):
        self.btn_add.place_forget()
        self.btn_generate.place_forget()
        self.btn_delete.place_forget()
        self.btn_show.place_forget()
        self.btn_show_all.place_forget()

    def show_menu_buttons(self):
        self.btn_add.place(x=80, y=100)
        self.btn_generate.place(x=350, y=100)
        self.btn_delete.place(x=75, y=200)
        self.btn_show.place(x=360, y=200)

        self.btn_show_all.place(x=245, y=300)

    def verify_master_password(self):
        master_password = self.entry_master.get()
        if self.security.verify_master_password(master_password):
            messagebox.showinfo("Success", "Master password verified!")
            self.show_menu_buttons()
            self.show_main_menu()
        else:
            messagebox.showerror("Error", "Incorrect master password.")

    def show_main_menu(self):
        self.frame_action.pack_forget()
        self.entry_master.pack_forget()
        self.btn_login.pack_forget()
        self.current_action = None
        self.show_menu_buttons()

    def show_action_ui(self, action):
        self.hide_menu_buttons()
        self.frame_action.pack(pady=100)
        self.current_action = action

        if action == "add":
            self.lbl_password.grid(row=2, column=0, pady=10)
            self.entry_password.grid(row=2, column=3, pady=10)
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
                    self.master.clipboard_clear()
                    self.master.clipboard_append(password)
                    self.master.update()
                    messagebox.showinfo("Password", "Password copied to clipboard!")
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
                    all_passwords.append([site, username, password])
                except Exception as e:
                    print(f"Error decrypting password: {e}\n")

            popup = tk.Toplevel(self.master)
            popup.title("All Passwords")
            popup.geometry("500x400")
            listbox = tk.Listbox(popup, width=60, height=20)
            for sup in all_passwords:
                site = sup[0]
                username = sup[1]
                password = sup[2]
                listbox.insert(tk.END, f"Site: {site}")
                listbox.insert(tk.END, f"Username: {username}")
                listbox.insert(tk.END, f"Password: {password}")
                listbox.insert(tk.END, f"")
            listbox.pack(pady=10)

            listbox.bind("<Double-1>", self.handle_double_click)
        else:
            messagebox.showinfo("Info", "No passwords stored.")

    def handle_double_click(self, event):
        listbox = event.widget
        selected_index = listbox.curselection()
        if selected_index:
            selected_item = listbox.get(selected_index).split(": ")[1]
            if (selected_item.endswith(".com") or selected_item.endswith(".fr")) and not ("@" in selected_item):
                webbrowser.open(selected_item)
            else:
                self.master.clipboard_clear()
                self.master.clipboard_append(selected_item)
                self.master.update()


if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()