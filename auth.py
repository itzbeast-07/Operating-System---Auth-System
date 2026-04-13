from db import get_connection
from security import hash_password, generate_otp, is_strong_password
from logger import log_activity
from admin import *
import time
import sqlite3

def register():
    username = input("Enter username: ")
    password = input("Enter password: ")
    if len(username) > 20:
        print("Username too long!")
        return
    if not is_strong_password(password):
        print("Weak password! Must include uppercase, number, special character.")
        return
    hashed_password = hash_password(password)
    conn = get_connection()
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

def login():
    username = input("Enter username: ")
    password = input("Enter password: ")

    hashed_password = hash_password(password)

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT password, role, failed_attempts, lock_time FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()

    if result is None:
        print("User not found!")
        log_activity("WARNING", f"Login failed - user not found: {username}")
        conn.close()
        return

    stored_password, role, failed_attempts, lock_time = result

    if failed_attempts >= 3:
        if time.time() - lock_time < 120:
            print("Account temporarily locked. Try again later.")
            log_activity("ALERT", f"Login attempt on locked account: {username}")
            conn.close()
            return
        else:
            cursor.execute("UPDATE users SET failed_attempts = 0 WHERE username = ?", (username,))
            conn.commit()
            failed_attempts = 0

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
            lock_time = time.time()
            cursor.execute(
                "UPDATE users SET failed_attempts = ?, lock_time = ? WHERE username = ?",
                (failed_attempts, lock_time, username)
            )
            print("Account locked due to multiple failed attempts.")
            log_activity("ALERT", f"Account locked: {username}")
        else:
            cursor.execute(
                "UPDATE users SET failed_attempts = ? WHERE username = ?",
                (failed_attempts, username)
            )
            print("Incorrect password!")
            log_activity("WARNING", f"Incorrect password attempt for user: {username}")
        conn.commit()
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
        print("1. View All Users")
        print("2. Delete User")
        print("3. Unlock User Account")
        print("4. Promote User to Admin")
        print("5. View Logs")
        print("6. Logout")
        choice = input("Choose option: ")

        if choice == "1":
            view_users()
        elif choice == "2":
            delete_user()
        elif choice == "3":
            unlock_user()
        elif choice == "4":
            promote_user()
        elif choice == "5":
            view_logs()
        elif choice == "6":
            break
        else:
            print("Invalid option.")


def change_password(username):
    new_password = input("Enter new password: ")

    if len(new_password) < 8:
        print("Password must be at least 8 characters.")
        return
    
    hashed_password = hash_password(new_password)

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        "UPDATE users SET password = ? WHERE username = ?",
        (hashed_password, username)
    )
    conn.commit()
    conn.close()

    print("Password updated successfully!")
    log_activity("INFO", f"Password changed for user: {username}")


def create_admin():
    conn = get_connection()
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

def login_gui(username, password):
    conn = get_connection()
    cursor = conn.cursor()
    hashed_password = hash_password(password)
    cursor.execute("SELECT password, role FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    if result is None:
        return "User not found"
    stored_password, role = result
    if stored_password != hashed_password:
        return "Incorrect password"
    return f"Success:{role}"