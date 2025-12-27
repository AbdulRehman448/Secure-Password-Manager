import os
import json
import base64
import time
import hashlib
import tkinter as tk
import sys  # Added for clean exit
from tkinter import ttk, simpledialog, messagebox, filedialog
from cryptography.fernet import Fernet, InvalidToken
import random
import csv

# ================= CONFIGURATION =================
DATA_FILE = "vault.dat"
SALT_FILE = "salt.key"
SESSION_TIMEOUT = 30  # 30 seconds
DEVELOPER_NAME = "Abdul Rehman Ali"

# ================= SECURITY LAYER =================
class Security:
    @staticmethod
    def get_salt():
        if not os.path.exists(SALT_FILE):
            with open(SALT_FILE, "wb") as f:
                f.write(os.urandom(16))
        with open(SALT_FILE, "rb") as f:
            return f.read()

    @staticmethod
    def derive_key(password, salt):
        kdf = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
        return base64.urlsafe_b64encode(kdf)

    @staticmethod
    def get_cipher(password):
        salt = Security.get_salt()
        key = Security.derive_key(password, salt)
        return Fernet(key)

# ================= UTILS =================
class Utils:
    @staticmethod
    def check_strength(p):
        length = len(p)
        has_upper = any(c.isupper() for c in p)
        has_lower = any(c.islower() for c in p)
        has_digit = any(c.isdigit() for c in p)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in p)
        
        variety_count = sum([has_upper, has_lower, has_digit, has_special])

        # Colors
        c_very_weak = "#ff4d4d"
        c_weak      = "#ff9999"
        c_medium    = "#ffff99"
        c_strong    = "#90ee90"
        c_very_strong="#32cd32"

        # 1. IMMEDIATE FAIL: Too short OR No variety
        if length < 8 or variety_count < 2:
            return "Very Weak", c_very_weak

        # 2. WEAK: Meets min length, but low variety
        if variety_count == 2:
            return "Weak", c_weak

        # 3. MEDIUM: Good variety (3 types), standard length
        if variety_count == 3 and length < 12:
            return "Medium", c_medium

        # 4. STRONG: Good variety + Long OR Excellent variety + Std Length
        if (variety_count == 3 and length >= 12) or (variety_count == 4 and length < 12):
            return "Strong", c_strong

        # 5. VERY STRONG
        if variety_count == 4 and length >= 12:
            return "Very Strong", c_very_strong

        return "Weak", c_weak

    @staticmethod
    def generate_password(length=16):
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+"
        return "".join(random.choice(chars) for _ in range(length))

# ================= APP ENGINE =================
class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title(f"🔐 Secure Password Manager")
        self.root.geometry("1300x650")
        
        # State
        self.dark_mode = False
        self.vault = {}
        self.cipher = None
        self.show_passwords = tk.BooleanVar(value=False)
        self.search_var = tk.StringVar()
        
        # Initialize
        self.setup_styles()
        self.root.lift()
        self.root.attributes('-topmost',True)
        self.root.after_idle(self.root.attributes,'-topmost',False)
        
        # Authentication
        self.master_password = self.authenticate() 
        self.cipher = Security.get_cipher(self.master_password)
        self.load_vault()
        
        # UI & Events
        self.create_ui()
        self.apply_theme()
        self.bind_events()
        self.update_table()
        
        # --- FIX: Start timer ONLY after everything is ready ---
        self.last_activity = time.time()
        self.check_timeout()

    def setup_styles(self):
        self.style = ttk.Style()
        self.style.theme_use("clam")
        
        self.colors = {
            "light": {
                "bg": "#f0f2f5", "fg": "#333333", "entry_bg": "#ffffff", 
                "tree_bg": "#ffffff", "select": "#0078d7", "status": "#e1e4e8"
            },
            "dark": {
                "bg": "#2b2b2b", "fg": "#ffffff", "entry_bg": "#3d3d3d", 
                "tree_bg": "#333333", "select": "#555555", "status": "#1f1f1f"
            }
        }

    def apply_theme(self):
        theme = self.colors["dark" if self.dark_mode else "light"]
        
        self.root.configure(bg=theme["bg"])
        self.main_frame.configure(bg=theme["bg"])
        self.control_frame.configure(bg=theme["bg"])
        self.status_label.configure(bg=theme["status"], fg=theme["fg"])
        self.lbl_search.configure(bg=theme["bg"], fg=theme["fg"])
        self.lbl_dev.configure(bg=theme["bg"], fg="#888888")
        
        self.chk_show.configure(background=theme["bg"], foreground=theme["fg"], 
                                activebackground=theme["bg"], activeforeground=theme["fg"])

        self.style.configure("Treeview", 
                             background=theme["tree_bg"], 
                             foreground=theme["fg"], 
                             fieldbackground=theme["tree_bg"],
                             rowheight=30,
                             font=('Segoe UI', 10))
        
        self.style.configure("Treeview.Heading", 
                             background=theme["status"], 
                             foreground=theme["fg"],
                             relief="flat",
                             font=('Segoe UI', 10, 'bold'))
        
        self.style.map("Treeview", background=[("selected", theme["select"])])
        
        btn_bg = "#444" if self.dark_mode else "#e1e1e1"
        self.style.configure("TButton", background=btn_bg, foreground=theme["fg"], font=('Segoe UI', 9))
        
        self.btn_theme.config(text="☀ Light Mode" if self.dark_mode else "🌙 Dark Mode")
        self.update_table()

    def toggle_theme(self):
        self.dark_mode = not self.dark_mode
        self.apply_theme()

    def authenticate(self):
        # Case 1: First time setup
        if not os.path.exists(DATA_FILE):
            while True:
                p1 = simpledialog.askstring("Setup", "Create Master Password (min 6 chars):", show="*", parent=self.root)
                if not p1: sys.exit() 
                
                p2 = simpledialog.askstring("Confirm", "Confirm Master Password:", show="*", parent=self.root)
                if not p2: sys.exit()
                
                if p1 == p2 and len(p1) >= 6:
                    cipher = Security.get_cipher(p1)
                    with open(DATA_FILE, "wb") as f:
                        f.write(cipher.encrypt(json.dumps({}).encode()))
                    return p1
                messagebox.showerror("Error", "Passwords do not match or are too short.", parent=self.root)
        
        # Case 2: Login
        else:
            attempts = 3
            while attempts > 0:
                prompt_text = f"Enter Master Password:\n({attempts} attempts remaining)"
                pwd = simpledialog.askstring("Login", prompt_text, show="*", parent=self.root)
                
                if not pwd: 
                    sys.exit() 
                
                try:
                    cipher = Security.get_cipher(pwd)
                    with open(DATA_FILE, "rb") as f:
                        cipher.decrypt(f.read())
                    return pwd 
                except InvalidToken:
                    attempts -= 1
                    if attempts > 0:
                        messagebox.showerror("Failed", f"Incorrect Password.\nYou have {attempts} attempts left.", parent=self.root)
                    else:
                        messagebox.showerror("Locked", "Too many incorrect attempts.", parent=self.root)
                        sys.exit()
                except Exception as e:
                    messagebox.showerror("Critical", f"Data file corrupted: {e}", parent=self.root)
                    sys.exit()

    def load_vault(self):
        try:
            if not os.path.exists(DATA_FILE): return
            with open(DATA_FILE, "rb") as f:
                data = self.cipher.decrypt(f.read()).decode()
                self.vault = json.loads(data)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load vault: {e}", parent=self.root)
            self.vault = {}

    def save_vault(self):
        try:
            encrypted = self.cipher.encrypt(json.dumps(self.vault).encode())
            with open(DATA_FILE, "wb") as f:
                f.write(encrypted)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save vault: {e}", parent=self.root)

    def create_ui(self):
        self.main_frame = tk.Frame(self.root)
        self.main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        self.control_frame = tk.Frame(self.main_frame)
        self.control_frame.pack(fill="x", pady=(0, 15))

        self.lbl_search = tk.Label(self.control_frame, text="🔍 Search:", font=('Segoe UI', 10, 'bold'))
        self.lbl_search.pack(side="left")
        
        self.ent_search = ttk.Entry(self.control_frame, textvariable=self.search_var, width=25, font=('Segoe UI', 10))
        self.ent_search.pack(side="left", padx=10)
        self.search_var.trace("w", lambda *_: self.update_table())

        actions = [
            ("➕ Add", self.add_entry),
            ("✏ Edit", self.edit_entry),
            ("🗑 Delete", self.delete_entry),
            ("🎲 Gen Pass", self.generate_tool),
            ("📋 User", lambda: self.copy_to_clipboard("username")),
            ("📋 Pass", lambda: self.copy_to_clipboard("password")),
            ("💾 Export", self.export_csv)
        ]
        
        for text, cmd in actions:
            ttk.Button(self.control_frame, text=text, command=cmd).pack(side="left", padx=4)

        self.btn_theme = ttk.Button(self.control_frame, text="Dark Mode", command=self.toggle_theme)
        self.btn_theme.pack(side="right", padx=5)

        self.chk_show = tk.Checkbutton(self.control_frame, text="Show Passwords", 
                                       variable=self.show_passwords, command=self.update_table, font=('Segoe UI', 9))
        self.chk_show.pack(side="right", padx=10)

        cols = ("Website/App", "Username", "Password", "Strength")
        self.tree = ttk.Treeview(self.main_frame, columns=cols, show="headings", height=15)
        
        self.tree.column("Website/App", width=250, anchor="w")
        self.tree.column("Username", width=200, anchor="w")
        self.tree.column("Password", width=200, anchor="w")
        self.tree.column("Strength", width=120, anchor="center")
        
        for c in cols:
            self.tree.heading(c, text=c)
        
        self.tree.pack(fill="both", expand=True)

        self.status_label = tk.Label(self.root, text="Ready", anchor="w", padx=10, pady=8, font=('Segoe UI', 9))
        self.status_label.pack(side="bottom", fill="x")
        
        self.lbl_dev = tk.Label(self.root, text=f"Developed by {DEVELOPER_NAME}", font=("Segoe UI", 8), fg="#888")
        self.lbl_dev.pack(side="bottom", pady=2)

    def bind_events(self):
        for ev in ("<Any-KeyPress>", "<Any-Button>", "<Motion>"):
            self.root.bind_all(ev, self.reset_timer)
        self.tree.bind("<Button-1>", self.on_tree_click)

    def update_table(self):
        self.tree.delete(*self.tree.get_children())
        query = self.search_var.get().lower()
        
        for site, data in self.vault.items():
            if query and query not in site.lower() and query not in data['username'].lower():
                continue
                
            display_pass = data['password'] if self.show_passwords.get() else "•" * 12
            str_text, str_color = Utils.check_strength(data['password'])
            
            item_id = self.tree.insert("", "end", values=(site, data['username'], display_pass, str_text))
            self.tree.item(item_id, tags=(str_text,))
        
        levels = [
            ("Very Weak",   "#ff4d4d"), 
            ("Weak",        "#ff9999"), 
            ("Medium",      "#ffff99"), 
            ("Strong",      "#90ee90"), 
            ("Very Strong", "#32cd32")
        ]
        
        for name, color in levels:
            self.tree.tag_configure(name, background=color, foreground="#000000")

    def add_entry(self):
        site = simpledialog.askstring("Add Entry", "Website/App Name:", parent=self.root)
        if not site: return
        if site in self.vault:
            if not messagebox.askyesno("Exists", "This entry exists. Overwrite?", parent=self.root):
                return
                
        user = simpledialog.askstring("Add Entry", "Username:", parent=self.root)
        pwd = simpledialog.askstring("Add Entry", "Password:", show="*", parent=self.root)
        
        if site and user and pwd:
            self.vault[site] = {"username": user, "password": pwd}
            self.save_vault()
            self.update_table()
            self.status_msg(f"Successfully added: {site}")

    def edit_entry(self):
        sel = self.tree.selection()
        if not sel: return
        
        old_site = self.tree.item(sel[0])['values'][0]
        data = self.vault[old_site]
        
        new_site = simpledialog.askstring("Edit", "Website:", initialvalue=old_site, parent=self.root)
        if not new_site: return
        
        new_user = simpledialog.askstring("Edit", "Username:", initialvalue=data['username'], parent=self.root)
        new_pass = simpledialog.askstring("Edit", "Password:", initialvalue=data['password'], parent=self.root)
        
        if new_site != old_site:
            del self.vault[old_site]
            
        self.vault[new_site] = {"username": new_user, "password": new_pass}
        self.save_vault()
        self.update_table()
        self.status_msg("Entry updated")

    def delete_entry(self):
        sel = self.tree.selection()
        if not sel: return
        site = self.tree.item(sel[0])['values'][0]
        
        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete the password for:\n\n{site}?", parent=self.root):
            del self.vault[site]
            self.save_vault()
            self.update_table()
            self.status_msg("Entry deleted")

    def generate_tool(self):
        pwd = Utils.generate_password()
        self.root.clipboard_clear()
        self.root.clipboard_append(pwd)
        self.root.update()
        messagebox.showinfo("Generated", f"Password: {pwd}\n\n(Copied to clipboard)", parent=self.root)

    def copy_to_clipboard(self, key):
        sel = self.tree.selection()
        if not sel: 
            messagebox.showwarning("Selection Required", "Please select a row first to copy data.", parent=self.root)
            return
        
        site = self.tree.item(sel[0])['values'][0]
        val = self.vault[site][key]
        
        self.root.clipboard_clear()
        self.root.clipboard_append(val)
        self.root.update() 
        
        target_name = "Username" if key == "username" else "Password"
        messagebox.showinfo("Copied", f"{target_name} for '{site}' copied to clipboard!", parent=self.root)
        self.status_msg(f"{target_name} copied!")

    def export_csv(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")], parent=self.root)
        if not path: return
        try:
            with open(path, "w", newline="") as f:
                w = csv.writer(f)
                w.writerow(["Website/App", "Username", "Password"])
                for s, d in self.vault.items():
                    w.writerow([s, d['username'], d['password']])
            messagebox.showinfo("Success", "Vault exported successfully.", parent=self.root)
        except Exception as e:
            messagebox.showerror("Error", str(e), parent=self.root)

    def status_msg(self, msg):
        self.status_label.config(text=f"ℹ {msg}")
        self.root.after(3000, lambda: self.status_label.config(text="Ready"))

    def reset_timer(self, _):
        self.last_activity = time.time()

    def check_timeout(self):
        # --- FIX: Uses sys.exit() to completely kill the process ---
        if time.time() - self.last_activity > SESSION_TIMEOUT:
            messagebox.showwarning("Timeout", "Session locked due to inactivity.", parent=self.root)
            self.root.destroy()
            sys.exit(0) # Ensures complete closure
        else:
            self.root.after(1000, self.check_timeout)
            
    def on_tree_click(self, event):
        if not self.tree.identify_row(event.y):
            self.tree.selection_remove(self.tree.selection())

# ================= MAIN =================
if __name__ == "__main__":
    root = tk.Tk()
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except: pass
    
    app = PasswordManagerApp(root)
    root.mainloop()