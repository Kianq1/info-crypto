import tkinter as tk
from tkinter import ttk, messagebox
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

# Generate a random key (16 bytes for AES-128)
key = get_random_bytes(16)

def pad(text):
    while len(text) % 16 != 0:
        text += ' '
    return text

def encrypt_info():
    info = entry.get()
    if not info:
        messagebox.showerror("Error", "Please enter some information")
        return
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted = cipher.encrypt(pad(info).encode())
    encoded = base64.b64encode(encrypted).decode()
    result_label.config(text=f"🔒 Encrypted:\n{encoded}")
    with open("secret.txt", "w") as f:
        f.write(encoded)
    with open("key.txt", "wb") as f:
        f.write(key)

def decrypt_info():
    try:
        with open("secret.txt", "r") as f:
            encoded = f.read()
        with open("key.txt", "rb") as f:
            saved_key = f.read()
        cipher = AES.new(saved_key, AES.MODE_ECB)
        encrypted = base64.b64decode(encoded)
        decrypted = cipher.decrypt(encrypted).decode().strip()
        result_label.config(text=f"🔓 Decrypted:\n{decrypted}")
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {e}")

def copy_to_clipboard():
    text = result_label.cget("text")
    if text:
        root.clipboard_clear()
        root.clipboard_append(text)
        messagebox.showinfo("Clipboard", "Copied to clipboard!")
    else:
        messagebox.showerror("Error", "No text to copy.")

# -----------------------------
# Modern GUI Setup
# -----------------------------
root = tk.Tk()
root.title("Info Encryptor")
root.geometry("420x400")
root.configure(bg="#2C3E50")  # dark background

style = ttk.Style(root)
style.theme_use("clam")

style.configure("TButton",
                font=("Arial", 12, "bold"),
                padding=10,
                background="#3498DB",
                foreground="white")
style.map("TButton",
          background=[("active", "#2980B9")])

style.configure("TLabel",
                background="#2C3E50",
                foreground="white",
                font=("Arial", 12))

# Title
title_label = tk.Label(root, text="Info Encryptor", font=("Arial", 16, "bold"), bg="#2C3E50", fg="#F1C40F")
title_label.pack(pady=15)

# Entry field
tk.Label(root, text="Enter information:", bg="#2C3E50", fg="white", font=("Arial", 12)).pack(pady=5)
entry = tk.Entry(root, width=40, font=("Arial", 12))
entry.pack(pady=10)

# Buttons
encrypt_btn = ttk.Button(root, text="Encrypt", command=encrypt_info)
encrypt_btn.pack(pady=10)

decrypt_btn = ttk.Button(root, text="Decrypt", command=decrypt_info)
decrypt_btn.pack(pady=10)

clipboard_btn = ttk.Button(root, text="Copy to Clipboard", command=copy_to_clipboard)
clipboard_btn.pack(pady=10)
credit_label = tk.Label(root, text="Created by MasterK", bg="#2C3E50", fg="white", font=("Arial", 10))
credit_label.pack(side="bottom", pady=5)
# Result label
result_label = tk.Label(root, text="", wraplength=380, justify="left", bg="#34495E", fg="white", font=("Arial", 12), relief="groove", padx=10, pady=10)
result_label.pack(pady=20, fill="x")

root.mainloop()