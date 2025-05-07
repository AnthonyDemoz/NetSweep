import sqlite3
import bcrypt
import os

DB_PATH = "netsweep_users.db"

# Ensure DB exists
if not os.path.exists(DB_PATH):
    raise FileNotFoundError("User database not found. Please run setup_users.py first.")

def verify_user(username, password):
    if not username or not password:
        return False

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        conn.close()

        if result and bcrypt.checkpw(password.encode('utf-8'), result[0]):
            return True
        else:
            return False
    except Exception as e:
        print(f"Error verifying user: {e}")
        return False
