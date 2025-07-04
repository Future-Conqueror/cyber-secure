import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
import os, hashlib

def select_file():
    path = filedialog.askopenfilename()
    entry_file.delete(0, tk.END)
    entry_file.insert(0, path)

def encrypt_file():
    filepath = entry_file.get()
    pwd = entry_pwd.get().encode()
    key = hashlib.sha256(pwd).digest()
    cipher = AES.new(key, AES.MODE_EAX)
    with open(filepath, 'rb') as f:
        data = f.read()
    ciphertext, tag = cipher.encrypt_and_digest(data)
    with open(filepath + ".enc", 'wb') as f:
        f.write(cipher.nonce + tag + ciphertext)
    messagebox.showinfo("Success", "File encrypted!")

def decrypt_file():
    filepath = entry_file.get()
    pwd = entry_pwd.get().encode()
    key = hashlib.sha256(pwd).digest()
    with open(filepath, 'rb') as f:
        nonce, tag, ciphertext = f.read(16), f.read(16), f.read()
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    try:
        data = cipher.decrypt_and_verify(ciphertext, tag)
        out = filepath.replace(".enc", ".dec")
        with open(out, 'wb') as f:
            f.write(data)
        messagebox.showinfo("Success", f"Decrypted file saved as {out}")
    except ValueError:
        messagebox.showerror("Error", "Incorrect password or corrupted file")

app = tk.Tk()
app.title("AES Encryption Tool")

tk.Button(app, text="Select File", command=select_file).pack(pady=5)
entry_file = tk.Entry(app, width=50); entry_file.pack()
tk.Label(app, text="Password:").pack(pady=5)
entry_pwd = tk.Entry(app, show="*", width=50); entry_pwd.pack()

tk.Button(app, text="Encrypt", command=encrypt_file).pack(padx=20, pady=5, side=tk.LEFT)
tk.Button(app, text="Decrypt", command=decrypt_file).pack(padx=20, pady=5, side=tk.RIGHT)

app.mainloop()
