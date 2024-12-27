from ui.main_window import PasswordManagerApp
import tkinter as tk

def main():
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()