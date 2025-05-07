import sqlite3
import bcrypt

# Connect to or create the database
conn = sqlite3.connect("netsweep_users.db")
cursor = conn.cursor()

# Create the users table if it doesn't exist
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password BLOB NOT NULL
)
''')

def is_valid(username, password):
    if not username or not password:
        print("Username and password cannot be empty.")
        return False
    if ' ' in username or ' ' in password:
        print("Username and password cannot contain spaces.")
        return False
    if len(password) < 4:
        print("Password should be at least 4 characters long.")
        return False
    return True

def create_user():
    while True:
        username = input("Enter new username: ").strip()
        password = input("Enter new password: ").strip()

        if not is_valid(username, password):
            continue

        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            print(f"User '{username}' already exists. Try a different username.\n")
            continue

        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed))
        conn.commit()
        print(f"User '{username}' created successfully.\n")
        break

def list_users():
    cursor.execute("SELECT username FROM users")
    users = cursor.fetchall()
    if users:
        print("\nRegistered Users:")
        for user in users:
            print(f" - {user[0]}")
    else:
        print("No users found.")

def delete_user():
    username = input("Enter the username to delete: ").strip()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    if cursor.fetchone():
        confirm = input(f"Are you sure you want to delete '{username}'? (y/n): ").lower()
        if confirm == 'y':
            cursor.execute("DELETE FROM users WHERE username = ?", (username,))
            conn.commit()
            print(f"User '{username}' has been deleted.\n")
    else:
        print(f"User '{username}' does not exist.\n")

# Main menu
while True:
    print("\n=== NetSweep User Setup ===")
    print("1. Create new user")
    print("2. List users")
    print("3. Delete user")
    print("4. Exit")

    choice = input("Select an option: ").strip()

    if choice == '1':
        create_user()
    elif choice == '2':
        list_users()
    elif choice == '3':
        delete_user()
    elif choice == '4':
        print("Thank you. Goodbye!")
        break
    else:
        print("Invalid option. Try again.")

conn.close()
