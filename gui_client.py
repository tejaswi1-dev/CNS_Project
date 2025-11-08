import tkinter as tk
from tkinter import simpledialog, messagebox, ttk
import json, os, asyncio, ssl
import websockets
from crypto_utils import *

DB_FILE = "db.json"
SERVER = "wss://localhost:8765"

# Load / init DB
def load_db():
    if os.path.exists(DB_FILE):
        with open(DB_FILE, "r") as f:
            return json.load(f)
    return {}

def save_db(db):
    with open(DB_FILE, "w") as f:
        json.dump(db, f)

# Async Sync to server
async def sync_to_server(db):
    sslctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    sslctx.check_hostname = False
    sslctx.verify_mode = ssl.CERT_NONE
    async with websockets.connect(SERVER, ssl=sslctx) as ws:
        await ws.send(json.dumps(db))
        await ws.recv()

# Main GUI Application
class PasswordManagerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Advanced Secure Password Manager")
        self.geometry("600x400")
        self.db = load_db()
        self.aes_key = None
        self.priv = None
        self.pub = None

        self.create_login_frame()

    def create_login_frame(self):
        self.login_frame = tk.Frame(self)
        self.login_frame.pack(pady=50)

        tk.Label(self.login_frame, text="Master Password:").pack(pady=5)
        self.master_entry = tk.Entry(self.login_frame, show="*")
        self.master_entry.pack(pady=5)
        tk.Button(self.login_frame, text="Login", command=self.login).pack(pady=10)

    def login(self):
        master = self.master_entry.get()
        if not master:
            messagebox.showerror("Error", "Enter master password")
            return

        # Load or create salt
        salt_file = "salt.bin"
        if os.path.exists(salt_file):
            with open(salt_file, "rb") as f:
                salt = f.read()
        else:
            salt = os.urandom(16)
            with open(salt_file, "wb") as f:
                f.write(salt)
        self.aes_key = derive_aes_key(master, salt)

        # Load or create Ed25519 keys
        priv_file = "ed25519_priv.pem"
        pub_file = "ed25519_pub.pem"
        if os.path.exists(priv_file):
            with open(priv_file, "rb") as f:
                self.priv = Ed25519PrivateKey.from_private_bytes(f.read())
            with open(pub_file, "rb") as f:
                self.pub = deserialize_public_key(base64.b64encode(f.read()).decode())
        else:
            self.priv, self.pub = generate_ed25519_keypair()
            with open(priv_file, "wb") as f:
                f.write(self.priv.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            with open(pub_file, "wb") as f:
                f.write(self.pub.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                ))

        self.login_frame.destroy()
        self.create_main_frame()

    def create_main_frame(self):
        self.main_frame = tk.Frame(self)
        self.main_frame.pack(pady=10)

        # Treeview to display entries
        self.tree = ttk.Treeview(self.main_frame, columns=("Username",), show="headings")
        self.tree.heading("Username", text="Username")
        self.tree.pack(fill=tk.BOTH, expand=True)

        self.update_tree()

        # Buttons
        btn_frame = tk.Frame(self.main_frame)
        btn_frame.pack(pady=10)

        tk.Button(btn_frame, text="Add Entry", command=self.add_entry).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="View Entry", command=self.view_entry).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Sync to Server", command=self.sync_db).pack(side=tk.LEFT, padx=5)

    def update_tree(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        for site, data in self.db.items():
            self.tree.insert("", tk.END, iid=site, values=(data["username"],))

    def add_entry(self):
        site = simpledialog.askstring("Website", "Enter website name:")
        if not site: return
        username = simpledialog.askstring("Username", "Enter username:")
        if not username: return
        password = simpledialog.askstring("Password", "Enter password:", show="*")
        if not password: return
        encrypted = encrypt_aes(self.aes_key, password)
        signature = sign_message(self.priv, encrypted.encode())
        self.db[site] = {"username": username, "password": encrypted, "signature": signature}
        save_db(self.db)
        self.update_tree()
        messagebox.showinfo("Success", f"Entry added for {site}")

    def view_entry(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showerror("Error", "Select an entry")
            return
        site = selected[0]
        entry = self.db[site]
        if verify_signature(self.pub, entry["password"].encode(), entry["signature"]):
            password = decrypt_aes(self.aes_key, entry["password"])
            messagebox.showinfo(site, f"Username: {entry['username']}\nPassword: {password}")
        else:
            messagebox.showerror("Error", "Signature verification failed")

    def sync_db(self):
        asyncio.run(sync_to_server(self.db))
        messagebox.showinfo("Sync", "Database synced to server")

if __name__ == "__main__":
    app = PasswordManagerApp()
    app.mainloop()
