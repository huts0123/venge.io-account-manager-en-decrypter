import tkinter as tk
from tkinter import messagebox, Listbox, END
import pyperclip
import os
from cryptography.fernet import Fernet

class AccountManager:
    def __init__(self, master):
        self.master = master
        master.title("Venge.io Account Manager")

        # Load or generate a key for encryption and decryption
        self.key = self.load_key()  # Load existing key from file
        self.cipher = Fernet(self.key)

        # Frame for account management
        self.frame = tk.Frame(master)
        self.frame.pack(pady=20)

        # Username label and entry
        self.username_label = tk.Label(self.frame, text="Username:")
        self.username_label.grid(row=0, column=0, padx=5)
        self.username_entry = tk.Entry(self.frame)
        self.username_entry.grid(row=0, column=1, padx=5)

        # Password label and entry
        self.password_label = tk.Label(self.frame, text="Password:")
        self.password_label.grid(row=1, column=0, padx=5)
        self.password_entry = tk.Entry(self.frame, show="*")
        self.password_entry.grid(row=1, column=1, padx=5)

        # Info label and entry
        self.info_label = tk.Label(self.frame, text="Info:")
        self.info_label.grid(row=2, column=0, padx=5)
        self.info_entry = tk.Entry(self.frame)
        self.info_entry.grid(row=2, column=1, padx=5)

        # Add Account Button
        self.add_button = tk.Button(self.frame, text="Add Account", command=self.add_account)
        self.add_button.grid(row=3, columnspan=2, pady=5)

        # Delete Account Button
        self.delete_button = tk.Button(self.frame, text="Delete Account", command=self.delete_account)
        self.delete_button.grid(row=4, columnspan=2, pady=5)

        # Edit Info Button
        self.edit_info_button = tk.Button(self.frame, text="Edit Info", command=self.edit_info)
        self.edit_info_button.grid(row=5, columnspan=2, pady=5)

        # Copy Username:Password Button
        self.copy_button = tk.Button(self.frame, text="Copy Username:Password", command=self.copy_credentials)
        self.copy_button.grid(row=6, columnspan=2, pady=5)

        # Accounts Listbox
        self.accounts_listbox = Listbox(master, width=50, height=10)
        self.accounts_listbox.pack(pady=20)
        self.accounts_listbox.bind("<<ListboxSelect>>", self.populate_fields)

        # Store accounts
        self.accounts = []

        # Specify the path to the accounts file
        self.accounts_file = "accounts.enc"  

        # Load accounts from file at startup
        self.load_accounts()

    def load_key(self):
        """Load the encryption key from a file or generate a new one if it doesn't exist."""
        key_file = "encryption_key.key"
        if os.path.exists(key_file):
            with open(key_file, "rb") as key_file:
                return key_file.read()
        else:
            # Generate a new key if none exists
            key = Fernet.generate_key()
            with open(key_file, "wb") as key_file:
                key_file.write(key)
            return key

    def add_account(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        info = self.info_entry.get()

        if username and password:
            account = (username, password, info)
            self.accounts.append(account)
            self.update_accounts_listbox()
            self.clear_entries()
            self.save_accounts()  
        else:
            messagebox.showwarning("Input Error", "Please enter both username and password.")

    def delete_account(self):
        selected_account_index = self.accounts_listbox.curselection()
        if selected_account_index:
            del self.accounts[selected_account_index[0]]
            self.update_accounts_listbox()
            self.clear_entries()
            self.save_accounts()  
        else:
            messagebox.showwarning("Selection Error", "Please select an account to delete.")

    def edit_info(self):
        selected_account_index = self.accounts_listbox.curselection()
        if selected_account_index:
            new_info = self.info_entry.get()
            if new_info:
                self.accounts[selected_account_index[0]] = (
                    self.accounts[selected_account_index[0]][0],  
                    self.accounts[selected_account_index[0]][1],  
                    new_info  
                )
                self.update_accounts_listbox()
                self.save_accounts()  
            else:
                messagebox.showwarning("Input Error", "Please enter new info to update.")
        else:
            messagebox.showwarning("Selection Error", "Please select an account to edit.")

    def populate_fields(self, event):
        selected_account_index = self.accounts_listbox.curselection()
        if selected_account_index:
            username, password, info = self.accounts[selected_account_index[0]]
            self.username_entry.delete(0, END)
            self.username_entry.insert(0, username)
            self.password_entry.delete(0, END)
            self.password_entry.insert(0, password)
            self.info_entry.delete(0, END)
            self.info_entry.insert(0, info)

    def clear_entries(self):
        self.username_entry.delete(0, END)
        self.password_entry.delete(0, END)
        self.info_entry.delete(0, END)

    def update_accounts_listbox(self):
        self.accounts_listbox.delete(0, END)
        for account in self.accounts:
            display_text = f"{account[0]} ({account[2]})"  
            self.accounts_listbox.insert(END, display_text)

    def copy_credentials(self):
        selected_account_index = self.accounts_listbox.curselection()
        if selected_account_index:
            username, password = self.accounts[selected_account_index[0]][:2]
            credentials = f"{username}:{password}"
            pyperclip.copy(credentials)
            messagebox.showinfo("Copied", "Credentials copied to clipboard!")
        else:
            messagebox.showwarning("Selection Error", "Please select an account to copy credentials.")

    def save_accounts(self):
        with open(self.accounts_file, 'wb') as f:
            for account in self.accounts:
                account_data = f"{account[0]}:{account[1]}:{account[2]}".encode()
                encrypted_data = self.cipher.encrypt(account_data)
                f.write(encrypted_data + b'\n')  

    def load_accounts(self):
        if os.path.exists(self.accounts_file):
            with open(self.accounts_file, 'rb') as f:
                for line in f:
                    try:
                        decrypted_data = self.cipher.decrypt(line.strip())
                        username, password, info = decrypted_data.decode().split(':')
                        self.accounts.append((username, password, info))
                    except Exception as e:
                        print(f"Failed to decrypt line: {line}. Error: {str(e)}")  
            self.update_accounts_listbox()

if __name__ == "__main__":
    root = tk.Tk()
    account_manager = AccountManager(root)
    root.mainloop()
