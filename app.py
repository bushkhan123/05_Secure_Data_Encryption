import streamlit as st
import json
import os
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

# Constants
DATA_FILE = "data.json"
SALT = b"somesalt"
MASTER_PASSWORD = "admin123"
LOCKOUT_DURATION = 60  # in seconds

# Initialize session state
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0
if "authorized" not in st.session_state:
    st.session_state.authorized = False

# Load stored data
if os.path.exists(DATA_FILE):
    with open(DATA_FILE, "r") as f:
        stored_data = json.load(f)
else:
    stored_data = {}

# Save stored data
def save_data():
    with open(DATA_FILE, "w") as f:
        json.dump(stored_data, f)

# PBKDF2 hashing for passkey
def hash_passkey(passkey):
    return pbkdf2_hmac("sha256", passkey.encode(), SALT, 100000).hex()

# Generate Fernet key from passkey
def get_cipher(passkey):
    key = pbkdf2_hmac("sha256", passkey.encode(), SALT, 100000, dklen=32)
    return Fernet(urlsafe_b64encode(key))

# Encrypt data
def encrypt_data(text, passkey):
    cipher = get_cipher(passkey)
    return cipher.encrypt(text.encode()).decode()

# Decrypt data
def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)
    for username, value in stored_data.items():
        if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed_passkey:
            try:
                cipher = get_cipher(passkey)
                return cipher.decrypt(encrypted_text.encode()).decode()
            except:
                return None
    return None

# Streamlit UI
st.title("🔐 Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

# Lockout check
if time.time() < st.session_state.lockout_time:
    st.warning("⏱️ Locked out due to too many failed attempts. Try again later.")
    st.stop()

if choice == "Home":
    st.subheader("🏠 Welcome")
    st.write("Securely store and retrieve your data using passkeys.")

elif choice == "Store Data":
    st.subheader("📂 Store Data")
    username = st.text_input("Enter Username")
    user_data = st.text_area("Enter Data")
    passkey = st.text_input("Enter Passkey", type="password")

    if st.button("Encrypt & Save"):
        if username and user_data and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data, passkey)
            stored_data[username] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey
            }
            save_data()
            st.success("✅ Data stored securely!")
        else:
            st.error("⚠️ All fields are required!")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Data")
    username = st.text_input("Enter Username")
    passkey = st.text_input("Enter Passkey", type="password")

    if st.button("Decrypt"):
        if username and passkey:
            user_info = stored_data.get(username)
            if user_info:
                decrypted_text = decrypt_data(user_info["encrypted_text"], passkey)
                if decrypted_text:
                    st.session_state.failed_attempts = 0
                    st.success(f"✅ Decrypted Data: {decrypted_text}")
                else:
                    st.session_state.failed_attempts += 1
                    remaining = 3 - st.session_state.failed_attempts
                    st.error(f"❌ Incorrect passkey! Attempts remaining: {remaining}")
                    if st.session_state.failed_attempts >= 3:
                        st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                        st.warning("🔒 Too many failed attempts. Locked out!")
                        st.experimental_rerun()
            else:
                st.error("⚠️ Username not found!")
        else:
            st.error("⚠️ All fields are required!")

elif choice == "Login":
    st.subheader("🔑 Admin Reauthorization")
    login_pass = st.text_input("Enter Master Password", type="password")

    if st.button("Login"):
        if login_pass == MASTER_PASSWORD:
            st.session_state.failed_attempts = 0
            st.session_state.lockout_time = 0
            st.session_state.authorized = True
            st.success("✅ Reauthorized successfully!")
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect password!")
