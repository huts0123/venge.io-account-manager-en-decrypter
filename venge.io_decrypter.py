import os
from cryptography.fernet import Fernet
import pyperclip

def decrypt_accounts(key):
    cipher = Fernet(key)
    accounts_file = "accounts.enc"

    if not os.path.exists(accounts_file):
        print("No accounts file found.")
        return

    # Store decrypted accounts in a list for display
    decrypted_accounts = []

    with open(accounts_file, 'rb') as f:
        for line in f:
            try:
                decrypted_data = cipher.decrypt(line.strip())
                username, password, info = decrypted_data.decode().split(':')
                decrypted_accounts.append((username, password, info))
            except Exception as e:
                print(f"Failed to decrypt line: {line}. Error: {str(e)}")

    return decrypted_accounts

def display_accounts(accounts):
    for index, (username, password, info) in enumerate(accounts):
        print(f"{index + 1}. Username: {username}, Password: {password}, Info: {info}")

def copy_password(password):
    pyperclip.copy(password)
    print("Password copied to clipboard!")

if __name__ == "__main__":
    key_input = input("Enter your encryption key: ")
    decrypted_accounts = decrypt_accounts(key_input.encode())
    
    if decrypted_accounts:
        display_accounts(decrypted_accounts)
        
        # Copy password example
        while True:
            try:
                account_index = int(input("\nEnter the account number to copy the password (or 0 to exit): ")) - 1
                if account_index == -1:
                    break
                if 0 <= account_index < len(decrypted_accounts):
                    copy_password(decrypted_accounts[account_index][1])  # Copy the password of the selected account
                else:
                    print("Invalid account number.")
            except ValueError:
                print("Please enter a valid number.")
