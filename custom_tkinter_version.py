# file_encrypt_decrypt_gui.py
import customtkinter as ctk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
import os

# Encryption & Decryption Functions
def generate_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

def load_key():
    if not os.path.exists("secret.key"):
        messagebox.showwarning("Key Missing", "No secret.key found! Generating a new one.")
        generate_key()
    return open("secret.key", "rb").read()

def encrypt_file(filepath):
    try:
        key = load_key()
        fernet = Fernet(key)

        with open(filepath, "rb") as file:
            data = file.read()

        encrypted = fernet.encrypt(data)
        new_filename = filepath + ".enc"

        with open(new_filename, "wb") as file:
            file.write(encrypted)

        messagebox.showinfo("Success", f"✅ Encrypted file saved as:\n{new_filename}")
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed:\n{e}")

def decrypt_file(filepath):
    try:
        key = load_key()
        fernet = Fernet(key)

        with open(filepath, "rb") as file:
            encrypted_data = file.read()

        decrypted = fernet.decrypt(encrypted_data)
        new_filename = filepath.replace(".enc", "_decrypted.txt")

        with open(new_filename, "wb") as file:
            file.write(decrypted)

        messagebox.showinfo("Success", f"✅ Decrypted file saved as:\n{new_filename}")
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed:\n{e}")

# GUI Setup
class FileEncryptDecryptApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("File Encryptor/Decryptor")
        self.geometry("600x400")
        self.resizable(False, False)
        ctk.set_appearance_mode("dark")  
        ctk.set_default_color_theme("blue")

        self.file_path = ctk.StringVar()

        # UI Layout
        self.create_widgets()

    def create_widgets(self):
        title_label = ctk.CTkLabel(self, text="🔐 File Encryption & Decryption", font=("Segoe UI", 22, "bold"))
        title_label.pack(pady=20)

        # File Selection
        file_frame = ctk.CTkFrame(self, corner_radius=15)
        file_frame.pack(pady=20, padx=30, fill="x")

        file_entry = ctk.CTkEntry(file_frame, textvariable=self.file_path, placeholder_text="Select a file...", width=400)
        file_entry.pack(side="left", padx=10, pady=10, fill="x", expand=True)

        browse_button = ctk.CTkButton(file_frame, text="Browse", width=80, command=self.browse_file)
        browse_button.pack(side="right", padx=10)

        # Buttons
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(pady=30)

        encrypt_btn = ctk.CTkButton(btn_frame, text="Encrypt File", width=200, height=40, command=self.encrypt_action)
        encrypt_btn.grid(row=0, column=0, padx=20)

        decrypt_btn = ctk.CTkButton(btn_frame, text="Decrypt File", width=200, height=40, fg_color="teal", command=self.decrypt_action)
        decrypt_btn.grid(row=0, column=1, padx=20)

        # Info / Footer
        footer_label = ctk.CTkLabel(self, text="Built with Python 🐍 & Fernet encryption", font=("Segoe UI", 12))
        footer_label.pack(side="bottom", pady=10)

    def browse_file(self):
        filepath = filedialog.askopenfilename(title="Select File")
        if filepath:
            self.file_path.set(filepath)

    def encrypt_action(self):
        filepath = self.file_path.get()
        if not filepath:
            messagebox.showwarning("No File", "Please select a file first.")
            return
        generate_key()
        encrypt_file(filepath)

    def decrypt_action(self):
        filepath = self.file_path.get()
        if not filepath:
            messagebox.showwarning("No File", "Please select a file first.")
            return
        decrypt_file(filepath)

# Run App 
if __name__ == "__main__":
    app = FileEncryptDecryptApp()
    app.mainloop()
