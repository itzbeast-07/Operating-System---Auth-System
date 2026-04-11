import sqlite3
import hashlib
import random
from datetime import datetime


def generate_otp():
    return str(random.randint(100000, 999999))

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def initialize_database():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password TEXT NOT NULL,
        role TEXT NOT NULL,
        failed_attempts INTEGER DEFAULT 0
    )
    """)
    conn.commit()
    conn.close()


def log_activity(message):
    with open("logs.txt", "a") as file:
        time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        file.write(f"[{time}] [{level}] {message}\n")


def create_admin():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    admin_username = "admin"
    admin_password = hash_password("Admin@123")

    cursor.execute("SELECT * FROM users WHERE username = ?", (admin_username,))
    if cursor.fetchone() is None:
        cursor.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            (admin_username, admin_password, "admin")
        )
        conn.commit()
        print("Default admin created (username: admin, password: Admin@123)")

    conn.close()


initialize_database()
create_admin()
print("Database Initialized Successfully.")

def register():
    username = input("Enter username: ")
    password = input("Enter password: ")
    if len(username) > 20:
        print("Username too long!")
        return
    if len(password) < 8:
        print("Password must be at least 8 characters.")
        return
    hashed_password = hash_password(password)
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            (username, hashed_password, "user")
        )
        conn.commit()
        print("User registered successfully!")
        log_activity("INFO", f"New user registered: {username}")
    except sqlite3.IntegrityError:
        print("Username already exists!")
        log_activity("WARNING", f"Duplicate registration attempt: {username}")
    conn.close()



def user_menu(username):
    while True:
        print(f"\nWelcome {username} (User)")
        print("1. Change Password")
        print("2. Logout")

        choice = input("Choose option: ")

        if choice == "1":
            change_password(username)
        elif choice == "2":
            break
        else:
            print("Invalid option.")



def admin_menu():
    while True:
        print("\nWelcome Admin")
        print("1. View All Users")
        print("2. Logout")

        choice = input("Choose option: ")

        if choice == "1":
            view_users()
        elif choice == "2":
            break
        else:
            print("Invalid option.")



def view_users():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute("SELECT username, role FROM users")
    users = cursor.fetchall()

    print("\n--- Registered Users ---")
    for user in users:
        print(f"Username: {user[0]}, Role: {user[1]}")

    conn.close()



def change_password(username):
    new_password = input("Enter new password: ")

    if len(new_password) < 8:
        print("Password must be at least 8 characters.")
        return

    hashed_password = hash_password(new_password)

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute(
        "UPDATE users SET password = ? WHERE username = ?",
        (hashed_password, username)
    )
    conn.commit()
    conn.close()

    print("Password updated successfully!")



def login():
    username = input("Enter username: ")
    password = input("Enter password: ")

    hashed_password = hash_password(password)

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute("SELECT password, role, failed_attempts FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()

    if result is None:
        print("User not found!")
        log_activity("WARNING", f"Login failed - user not found: {username}")
        conn.close()
        return

    stored_password, role, failed_attempts = result

    if failed_attempts >= 3:
        print("Account locked due to multiple failed attempts.")
        log_activity("ALERT", f"Login attempt on locked account: {username}")
        conn.close()
        return

    if stored_password == hashed_password:
        otp = generate_otp()
        print("Your OTP is:", otp)

        entered_otp = input("Enter OTP: ")

        if entered_otp == otp:
            print(f"Login successful! Logged in as {role}")
            log_activity("INFO", f"Login successful: {username} ({role})")
            cursor.execute("UPDATE users SET failed_attempts = 0 WHERE username = ?", (username,))
            conn.commit()

            if role == "admin":
                admin_menu()
            else:
                user_menu(username)

        else:
            print("Incorrect OTP!")
            log_activity("WARNING", f"OTP failed for user: {username}")

    else:
        failed_attempts += 1
        if failed_attempts >= 3:
            log_activity("ALERT", f"Account locked due to multiple failures: {username}")
        cursor.execute("UPDATE users SET failed_attempts = ? WHERE username = ?", (failed_attempts, username))
        conn.commit()
        print("Incorrect password!")
        log_activity("WARNING", f"Incorrect password attempt for user: {username}")



while True:
    print("\n1. Register")
    print("2. Login")
    print("3. Exit")

    choice = input("Choose option: ")

    if choice == "1":
        register()
    elif choice == "2":
        login()
    elif choice == "3":
        break
    else:
        print("Invalid option.")