import streamlit as st
from cryptography.fernet import Fernet
import hashlib

# Session state setup for persistent storage
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = {}

if "fernet_key" not in st.session_state:
    st.session_state.fernet_key = Fernet.generate_key()

fernet = Fernet(st.session_state.fernet_key)

# Utility: Hash passkey for secure storage
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Insert new data (encrypt and store)
def insert_data(user_id, text, passkey):
    encrypted_text = fernet.encrypt(text.encode()).decode()
    hashed_passkey = hash_passkey(passkey)
    st.session_state.stored_data[user_id] = {
        "encrypted_text": encrypted_text,
        "passkey": hashed_passkey
    }
    st.success(f"Data stored securely for user: {user_id}")

# Retrieve data (decrypt with passkey)
def retrieve_data(user_id, passkey):
    if user_id not in st.session_state.stored_data:
        st.error("No data found for this user.")
        return

    # Check failed attempts and block after 3 failed attempts
    if st.session_state.failed_attempts.get(user_id, 0) >= 3:
        st.warning("Too many failed attempts. Please login again.")
        return

    hashed_input = hash_passkey(passkey)
    if hashed_input == st.session_state.stored_data[user_id]["passkey"]:
        decrypted = fernet.decrypt(
            st.session_state.stored_data[user_id]["encrypted_text"].encode()
        ).decode()
        st.success(f"Decrypted Data: {decrypted}")
        st.session_state.failed_attempts[user_id] = 0  # Reset on success
    else:
        st.session_state.failed_attempts[user_id] = (
            st.session_state.failed_attempts.get(user_id, 0) + 1
        )
        attempts_left = 3 - st.session_state.failed_attempts[user_id]
        st.error(f"Incorrect passkey. Attempts left: {attempts_left}")

# Login Page for Admin
def login_page():
    st.title("🔐 Reauthorization Required")
    username = st.text_input("Enter Admin Username")
    password = st.text_input("Enter Admin Password", type="password")

    if st.button("Login"):
        if username == "admin" and password == "admin123":
            st.session_state["authorized"] = True
            st.success("Login successful!")
            st.session_state.failed_attempts.clear()
        else:
            st.error("Invalid credentials.")

# Main App Logic
def main():
    if not st.session_state.get("authorized", False):
        login_page()
        return

    st.sidebar.title("🔐 Secure Data Storage")
    menu = st.sidebar.radio("Navigate", ["Home", "Insert Data", "Retrieve Data", "Logout"])

    if menu == "Home":
        st.title("Welcome to Secure Data Encryption System")
        st.write("Use the sidebar to insert or retrieve encrypted data.")

    elif menu == "Insert Data":
        st.title("📥 Store Your Secure Data")
        user_id = st.text_input("Enter User ID")
        data = st.text_area("Enter Data to Encrypt")
        passkey = st.text_input("Set a Passkey", type="password")

        if st.button("Store Data"):
            if user_id and data and passkey:
                insert_data(user_id, data, passkey)
            else:
                st.warning("All fields are required.")

    elif menu == "Retrieve Data":
        st.title("🔓 Retrieve Your Encrypted Data")
        user_id = st.text_input("Enter Your User ID")
        passkey = st.text_input("Enter Your Passkey", type="password")

        if st.button("Decrypt Data"):
            if user_id and passkey:
                retrieve_data(user_id, passkey)
            else:
                st.warning("Both User ID and Passkey are required.")

        # Optional: show stored users (for debug)
        if st.checkbox("Show stored users (for debugging)"):
            st.write("Users in memory:", list(st.session_state.stored_data.keys()))

    elif menu == "Logout":
        st.session_state["authorized"] = False
        st.success("Logged out successfully. Please refresh or go back to Home.")

if __name__ == "__main__":
    main()
