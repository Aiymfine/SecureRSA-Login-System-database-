import tkinter as tk
from tkinter import messagebox
import sqlite3
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

DB_FILE = "users.db"
PUBLIC_KEY_FILE = "public.pem"
PRIVATE_KEY_FILE = "private.pem"

def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    with open(PRIVATE_KEY_FILE, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    with open(PUBLIC_KEY_FILE, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
    print("RSA keys generated.")

def load_public_key():
    with open(PUBLIC_KEY_FILE, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def load_private_key():
    with open(PRIVATE_KEY_FILE, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def encrypt_with_public_key(data: str, public_key) -> str:
    encrypted = public_key.encrypt(
        data.encode(),
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return encrypted.hex()

def decrypt_with_private_key(enc_hex: str, private_key) -> str:
    encrypted_bytes = bytes.fromhex(enc_hex)
    decrypted = private_key.decrypt(
        encrypted_bytes,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return decrypted.decode()

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def save_user_enc(username_enc, password_enc):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username_enc, password_enc))
    conn.commit()
    conn.close()

def get_all_users():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT username, password FROM users")
    rows = c.fetchall()
    conn.close()
    return rows

class RSACryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("RSA Login/Register with Encrypted DB")
        self.root.geometry("400x300")
        self.root.config(bg="#14375e")

        self.username_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.is_logged_in = False

        if not os.path.exists(PUBLIC_KEY_FILE) or not os.path.exists(PRIVATE_KEY_FILE):
            generate_rsa_keys()

        self.public_key = load_public_key()
        self.private_key = load_private_key()

        init_db()

        self.build_ui()

    def build_ui(self):
        tk.Label(self.root, text="Secure RSA Login/Register", font=("Arial", 16), fg="white", bg="#14375e").pack(pady=10)

        tk.Label(self.root, text="Username:", fg="white", bg="#14375e").pack(anchor="w", padx=20)
        tk.Entry(self.root, textvariable=self.username_var, width=30).pack(padx=20)

        tk.Label(self.root, text="Password:", fg="white", bg="#14375e").pack(anchor="w", padx=20, pady=(10,0))
        tk.Entry(self.root, textvariable=self.password_var, show="*", width=30).pack(padx=20)

        btn_frame = tk.Frame(self.root, bg="#14375e")
        btn_frame.pack(pady=10)

        tk.Button(btn_frame, text="Register", bg="#5b52e6", fg="white", width=10, command=self.register).pack(side="left", padx=5)
        tk.Button(btn_frame, text="Login", bg="#26d13f", fg="white", width=10, command=self.login).pack(side="left", padx=5)

        self.enc_dec_btn = tk.Button(self.root, text="Encrypt/Decrypt Message", bg="#f0732c", fg="white",
                                     state="disabled", command=self.open_encrypt_decrypt_window)
        self.enc_dec_btn.pack(pady=10)

        self.status_label = tk.Label(self.root, text="", fg="red", bg="#14375e")
        self.status_label.pack()

    def register(self):
        username = self.username_var.get().strip()
        password = self.password_var.get().strip()
        if not username or not password:
            self.status_label.config(text="Enter username and password!")
            return

        # Encrypt username and password before saving
        username_enc = encrypt_with_public_key(username, self.public_key)
        password_enc = encrypt_with_public_key(password, self.public_key)

        # Save encrypted to DB
        save_user_enc(username_enc, password_enc)
        self.status_label.config(text="Registration successful!", fg="green")

    def login(self):
        username = self.username_var.get().strip()
        password = self.password_var.get().strip()
        if not username or not password:
            self.status_label.config(text="Enter username and password!")
            return

        users = get_all_users()
        for user_enc, pass_enc in users:
            try:
                user_dec = decrypt_with_private_key(user_enc, self.private_key)
                pass_dec = decrypt_with_private_key(pass_enc, self.private_key)
            except Exception as e:
                continue
            if user_dec == username and pass_dec == password:
                self.status_label.config(text="Login successful!", fg="green")
                self.is_logged_in = True
                self.enc_dec_btn.config(state="normal")
                return

        self.status_label.config(text="User not found or wrong password.", fg="red")
        self.is_logged_in = False
        self.enc_dec_btn.config(state="disabled")

    def open_encrypt_decrypt_window(self):
        if not self.is_logged_in:
            messagebox.showerror("Error", "Please log in first!")
            return

        self.enc_win = tk.Toplevel(self.root)
        self.enc_win.title("Encrypt/Decrypt Message")
        self.enc_win.geometry("500x400")
        self.enc_win.config(bg="#14375e")

        tk.Label(self.enc_win, text="Enter message:", fg="white", bg="#14375e").pack(anchor="w", padx=10, pady=(10,0))
        self.message_entry = tk.Entry(self.enc_win, width=60)
        self.message_entry.pack(padx=10, pady=(0,10))

        self.encrypt_btn = tk.Button(self.enc_win, text="Encrypt & Decrypt", bg="#f0732c", fg="white",
                                     command=self.encrypt_decrypt_message)
        self.encrypt_btn.pack(pady=5)

        tk.Label(self.enc_win, text="Encrypted message:", fg="white", bg="#14375e").pack(anchor="w", padx=10, pady=(10,0))
        self.encrypted_text = tk.Text(self.enc_win, height=5, width=60)
        self.encrypted_text.pack(padx=10)

        tk.Label(self.enc_win, text="Decrypted message:", fg="white", bg="#14375e").pack(anchor="w", padx=10, pady=(10,0))
        self.decrypted_text = tk.Text(self.enc_win, height=5, width=60)
        self.decrypted_text.pack(padx=10)

    def encrypt_decrypt_message(self):
        message = self.message_entry.get()
        if not message:
            messagebox.showwarning("Warning", "Enter a message to encrypt!")
            return

        # Encrypt message with public key
        encrypted = self.public_key.encrypt(
            message.encode(),
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        self.encrypted_text.delete(1.0, tk.END)
        self.encrypted_text.insert(tk.END, encrypted.hex())

        # Decrypt with private key
        decrypted = self.private_key.decrypt(
            encrypted,
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        self.decrypted_text.delete(1.0, tk.END)
        self.decrypted_text.insert(tk.END, decrypted.decode())


if __name__ == "__main__":
    root = tk.Tk()
    app = RSACryptoApp(root)
    root.mainloop()
