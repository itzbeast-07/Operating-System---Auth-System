from db import get_connection
from security import hash_password, generate_otp, is_strong_password
from logger import log_activity
from admin import *
import time
import sqlite3
from email_service import send_otp_email

otp_store = {}

# ── GUI-facing login (OTP flow) ────────────────────────────────────────────────
def start_login(username, password):
    conn = get_connection()
    cursor = conn.cursor()
    hashed_password = hash_password(password)
    cursor.execute(
        "SELECT password, role, email, failed_attempts, lock_time FROM users WHERE username = ?",
        (username,)
    )
    result = cursor.fetchone()
    conn.close()
    if result is None:
        return "User not found"
    stored_password, role, email, failed_attempts, lock_time = result

    # Lockout check
    if failed_attempts >= 3:
        if time.time() - lock_time < 120:
            return "Account locked. Try again in 2 minutes."
        else:
            # Auto-unlock after timeout
            conn2 = get_connection()
            conn2.cursor().execute(
                "UPDATE users SET failed_attempts = 0 WHERE username = ?", (username,))
            conn2.commit()
            conn2.close()
            failed_attempts = 0

    if stored_password != hashed_password:
        # Track failed attempt
        failed_attempts += 1
        conn3 = get_connection()
        cur3 = conn3.cursor()
        if failed_attempts >= 3:
            cur3.execute(
                "UPDATE users SET failed_attempts = ?, lock_time = ? WHERE username = ?",
                (failed_attempts, time.time(), username)
            )
            log_activity("ALERT", f"Account locked after failed attempts: {username}")
            conn3.commit()
            conn3.close()
            return "Account locked due to too many failed attempts."
        cur3.execute(
            "UPDATE users SET failed_attempts = ? WHERE username = ?",
            (failed_attempts, username)
        )
        conn3.commit()
        conn3.close()
        log_activity("WARNING", f"Incorrect password for: {username}")
        return "Incorrect password"

    # Reset failed attempts on correct password
    conn4 = get_connection()
    conn4.cursor().execute(
        "UPDATE users SET failed_attempts = 0 WHERE username = ?", (username,))
    conn4.commit()
    conn4.close()

    otp = generate_otp()
    expiry = time.time() + 60
    otp_store[username] = (otp, expiry, role)
    send_otp_email(email, otp)
    log_activity("INFO", f"OTP dispatched for: {username}")
    return "OTP_SENT"


def verify_otp(username, entered_otp):
    if username not in otp_store:
        return "No OTP found. Please login again."
    otp, expiry, role = otp_store[username]
    if time.time() > expiry:
        del otp_store[username]
        return "OTP expired. Please login again."
    if entered_otp == otp:
        del otp_store[username]
        log_activity("INFO", f"Login successful: {username} ({role})")
        return f"Success:{role}"
    log_activity("WARNING", f"Incorrect OTP attempt for: {username}")
    return "Incorrect OTP"


# ── GUI register ───────────────────────────────────────────────────────────────
def register_gui(username, password, email):
    if len(username) > 20:
        return "Username too long (max 20 chars)"
    if not username.strip():
        return "Username cannot be empty"
    if not is_strong_password(password):
        return "Weak password: need 8+ chars, uppercase, number, special char"
    if "@" not in email or "." not in email:
        return "Invalid email address"
    hashed_password = hash_password(password)
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, password, role, email) VALUES (?, ?, ?, ?)",
            (username, hashed_password, "user", email)
        )
        conn.commit()
        log_activity("INFO", f"New user registered: {username}")
        return "Success"
    except sqlite3.IntegrityError:
        log_activity("WARNING", f"Duplicate registration attempt: {username}")
        return "Username already exists"
    finally:
        conn.close()


# ── GUI change password (takes username + new password) ────────────────────────
def change_password(username, new_password):
    """Called from the GUI change-password screen."""
    hashed = hash_password(new_password)
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE users SET password = ? WHERE username = ?",
        (hashed, username)
    )
    conn.commit()
    conn.close()
    log_activity("INFO", f"Password changed for user: {username}")


# ── Admin helpers (GUI) ────────────────────────────────────────────────────────
def view_users():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT username, role FROM users")
    data = cursor.fetchall()
    conn.close()
    return data


def view_logs():
    try:
        with open("logs.txt", "r") as f:
            return f.read()
    except FileNotFoundError:
        return "No logs found."


def delete_user(username):
    if username == "admin":
        return "Cannot delete the root admin account."
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
    if cursor.fetchone() is None:
        conn.close()
        return f"User '{username}' not found."
    cursor.execute("DELETE FROM users WHERE username = ?", (username,))
    conn.commit()
    conn.close()
    log_activity("ALERT", f"Admin deleted user: {username}")
    return f"User '{username}' deleted successfully."


def unlock_user(username):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
    if cursor.fetchone() is None:
        conn.close()
        return f"User '{username}' not found."
    cursor.execute(
        "UPDATE users SET failed_attempts = 0, lock_time = 0 WHERE username = ?",
        (username,)
    )
    conn.commit()
    conn.close()
    log_activity("INFO", f"Admin unlocked account: {username}")   # FIXED: was missing level arg
    return f"User '{username}' unlocked successfully."


def promote_user(username):
    if username == "admin":
        return "User is already the root admin."
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT role FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    if result is None:
        conn.close()
        return f"User '{username}' not found."
    if result[0] == "admin":
        conn.close()
        return f"User '{username}' is already an admin."
    cursor.execute(
        "UPDATE users SET role = 'admin' WHERE username = ?", (username,)
    )
    conn.commit()
    conn.close()
    log_activity("ALERT", f"User promoted to admin: {username}")   # FIXED: was missing level arg
    return f"User '{username}' promoted to admin."


# ── CLI helpers (unchanged, kept for main.py compatibility) ───────────────────
def create_admin():
    conn = get_connection()
    cursor = conn.cursor()
    admin_password = hash_password("Admin@123")
    cursor.execute("SELECT * FROM users WHERE username = ?", ("admin",))
    if cursor.fetchone() is None:
        cursor.execute(
            "INSERT INTO users (username, password, role, email) VALUES (?, ?, ?, ?)",
            ("admin", admin_password, "admin", "example@gmail.com")
        )
        conn.commit()
        print("Default admin created  (username: admin  password: Admin@123)")
    conn.close()


def login_gui(username, password):
    conn = get_connection()
    cursor = conn.cursor()
    hashed_password = hash_password(password)
    cursor.execute("SELECT password, role FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()
    if result is None:
        return "User not found"
    stored_password, role = result
    if stored_password != hashed_password:
        return "Incorrect password"
    return f"Success:{role}"


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
            "INSERT INTO users (username, password, role, email) VALUES (?, ?, ?, ?)",
            (username, hashed_password, "user", "")
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
    cursor.execute(
        "SELECT password, role, failed_attempts, lock_time FROM users WHERE username = ?",
        (username,))
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
            print(f"Login successful! Role: {role}")
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
            cursor.execute(
                "UPDATE users SET failed_attempts = ?, lock_time = ? WHERE username = ?",
                (failed_attempts, time.time(), username)
            )
            print("Account locked.")
            log_activity("ALERT", f"Account locked: {username}")
        else:
            cursor.execute(
                "UPDATE users SET failed_attempts = ? WHERE username = ?",
                (failed_attempts, username)
            )
            print("Incorrect password!")
            log_activity("WARNING", f"Incorrect password for: {username}")
        conn.commit()
    conn.close()


def user_menu(username):
    while True:
        print(f"\nWelcome {username} (User)")
        print("1. Change Password")
        print("2. Logout")
        choice = input("Choose option: ")
        if choice == "1":
            new_pw = input("Enter new password: ")
            if is_strong_password(new_pw):
                change_password(username, new_pw)
                print("Password updated.")
            else:
                print("Weak password.")
        elif choice == "2":
            break
        else:
            print("Invalid option.")


def admin_menu():
    while True:
        print("\n1. View All Users\n2. Delete User\n3. Unlock User"
              "\n4. Promote User to Admin\n5. View Logs\n6. Logout")
        choice = input("Choose option: ")
        if   choice == "1": view_users_cli()
        elif choice == "2": delete_user_cli()
        elif choice == "3": unlock_user_cli()
        elif choice == "4": promote_user_cli()
        elif choice == "5": view_logs_cli()
        elif choice == "6": break
        else: print("Invalid option.")


def view_users_cli():
    for u in view_users():
        print(f"Username: {u[0]}, Role: {u[1]}")

def delete_user_cli():
    u = input("Username to delete: ")
    print(delete_user(u))

def unlock_user_cli():
    u = input("Username to unlock: ")
    print(unlock_user(u))

def promote_user_cli():
    u = input("Username to promote: ")
    print(promote_user(u))

def view_logs_cli():
    print(view_logs())


# ── Forgot password flow ───────────────────────────────────────────────────────
reset_otp_store = {}

def start_forgot_password(email):
    """Look up user by email, send a reset OTP. Returns (username, 'OTP_SENT') or (None, error)."""
    if "@" not in email or "." not in email:
        return None, "Please enter a valid email address."
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT username, role FROM users WHERE email = ?", (email,))
    result = cursor.fetchone()
    conn.close()
    if result is None:
        return None, "No account found with that email address."
    username, role = result
    if role == "admin":
        return None, "Password reset is not available for admin accounts."
    otp = generate_otp()
    expiry = time.time() + 60
    reset_otp_store[username] = (otp, expiry)
    send_otp_email(email, otp)
    log_activity("INFO", f"Password reset OTP sent for: {username}")
    return username, "OTP_SENT"


def verify_reset_otp(username, entered_otp):
    """Returns 'OK' or an error string."""
    if username not in reset_otp_store:
        return "No reset code found. Please start over."
    otp, expiry = reset_otp_store[username]
    if time.time() > expiry:
        del reset_otp_store[username]
        return "Code expired. Please start over."
    if entered_otp == otp:
        del reset_otp_store[username]
        return "OK"
    return "Incorrect code. Please try again."


def reset_password(username, new_password):
    """Set a new password — call only after verify_reset_otp returns 'OK'."""
    hashed = hash_password(new_password)
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET password = ? WHERE username = ?", (hashed, username))
    conn.commit()
    conn.close()
    log_activity("INFO", f"Password reset completed for: {username}")
otp_store = {}

# ── GUI-facing login (OTP flow) ────────────────────────────────────────────────
def start_login(username, password):
    conn = get_connection()
    cursor = conn.cursor()
    hashed_password = hash_password(password)
    cursor.execute(
        "SELECT password, role, email, failed_attempts, lock_time FROM users WHERE username = ?",
        (username,)
    )
    result = cursor.fetchone()
    conn.close()
    if result is None:
        return "User not found"
    stored_password, role, email, failed_attempts, lock_time = result

    # Lockout check
    if failed_attempts >= 3:
        if time.time() - lock_time < 120:
            return "Account locked. Try again in 2 minutes."
        else:
            # Auto-unlock after timeout
            conn2 = get_connection()
            conn2.cursor().execute(
                "UPDATE users SET failed_attempts = 0 WHERE username = ?", (username,))
            conn2.commit()
            conn2.close()
            failed_attempts = 0

    if stored_password != hashed_password:
        # Track failed attempt
        failed_attempts += 1
        conn3 = get_connection()
        cur3 = conn3.cursor()
        if failed_attempts >= 3:
            cur3.execute(
                "UPDATE users SET failed_attempts = ?, lock_time = ? WHERE username = ?",
                (failed_attempts, time.time(), username)
            )
            log_activity("ALERT", f"Account locked after failed attempts: {username}")
            conn3.commit()
            conn3.close()
            return "Account locked due to too many failed attempts."
        cur3.execute(
            "UPDATE users SET failed_attempts = ? WHERE username = ?",
            (failed_attempts, username)
        )
        conn3.commit()
        conn3.close()
        log_activity("WARNING", f"Incorrect password for: {username}")
        return "Incorrect password"

    # Reset failed attempts on correct password
    conn4 = get_connection()
    conn4.cursor().execute(
        "UPDATE users SET failed_attempts = 0 WHERE username = ?", (username,))
    conn4.commit()
    conn4.close()

    otp = generate_otp()
    expiry = time.time() + 60
    otp_store[username] = (otp, expiry, role)
    send_otp_email(email, otp)
    log_activity("INFO", f"OTP dispatched for: {username}")
    return "OTP_SENT"


def verify_otp(username, entered_otp):
    if username not in otp_store:
        return "No OTP found. Please login again."
    otp, expiry, role = otp_store[username]
    if time.time() > expiry:
        del otp_store[username]
        return "OTP expired. Please login again."
    if entered_otp == otp:
        del otp_store[username]
        log_activity("INFO", f"Login successful: {username} ({role})")
        return f"Success:{role}"
    log_activity("WARNING", f"Incorrect OTP attempt for: {username}")
    return "Incorrect OTP"


# ── GUI register ───────────────────────────────────────────────────────────────
def register_gui(username, password, email):
    if len(username) > 20:
        return "Username too long (max 20 chars)"
    if not username.strip():
        return "Username cannot be empty"
    if not is_strong_password(password):
        return "Weak password: need 8+ chars, uppercase, number, special char"
    if "@" not in email or "." not in email:
        return "Invalid email address"
    hashed_password = hash_password(password)
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, password, role, email) VALUES (?, ?, ?, ?)",
            (username, hashed_password, "user", email)
        )
        conn.commit()
        log_activity("INFO", f"New user registered: {username}")
        return "Success"
    except sqlite3.IntegrityError:
        log_activity("WARNING", f"Duplicate registration attempt: {username}")
        return "Username already exists"
    finally:
        conn.close()


# ── GUI change password (takes username + new password) ────────────────────────
def change_password(username, new_password):
    """Called from the GUI change-password screen."""
    hashed = hash_password(new_password)
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE users SET password = ? WHERE username = ?",
        (hashed, username)
    )
    conn.commit()
    conn.close()
    log_activity("INFO", f"Password changed for user: {username}")


# ── Admin helpers (GUI) ────────────────────────────────────────────────────────
def view_users():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT username, role FROM users")
    data = cursor.fetchall()
    conn.close()
    return data


def view_logs():
    try:
        with open("logs.txt", "r") as f:
            return f.read()
    except FileNotFoundError:
        return "No logs found."


def delete_user(username):
    if username == "admin":
        return "Cannot delete the root admin account."
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
    if cursor.fetchone() is None:
        conn.close()
        return f"User '{username}' not found."
    cursor.execute("DELETE FROM users WHERE username = ?", (username,))
    conn.commit()
    conn.close()
    log_activity("ALERT", f"Admin deleted user: {username}")
    return f"User '{username}' deleted successfully."


def unlock_user(username):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
    if cursor.fetchone() is None:
        conn.close()
        return f"User '{username}' not found."
    cursor.execute(
        "UPDATE users SET failed_attempts = 0, lock_time = 0 WHERE username = ?",
        (username,)
    )
    conn.commit()
    conn.close()
    log_activity("INFO", f"Admin unlocked account: {username}")   # FIXED: was missing level arg
    return f"User '{username}' unlocked successfully."


def promote_user(username):
    if username == "admin":
        return "User is already the root admin."
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT role FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    if result is None:
        conn.close()
        return f"User '{username}' not found."
    if result[0] == "admin":
        conn.close()
        return f"User '{username}' is already an admin."
    cursor.execute(
        "UPDATE users SET role = 'admin' WHERE username = ?", (username,)
    )
    conn.commit()
    conn.close()
    log_activity("ALERT", f"User promoted to admin: {username}")   # FIXED: was missing level arg
    return f"User '{username}' promoted to admin."


# ── CLI helpers (unchanged, kept for main.py compatibility) ───────────────────
def create_admin():
    conn = get_connection()
    cursor = conn.cursor()
    admin_password = hash_password("Admin@123")
    cursor.execute("SELECT * FROM users WHERE username = ?", ("admin",))
    if cursor.fetchone() is None:
        cursor.execute(
            "INSERT INTO users (username, password, role, email) VALUES (?, ?, ?, ?)",
            ("admin", admin_password, "admin", "example@gmail.com")
        )
        conn.commit()
        print("Default admin created  (username: admin  password: Admin@123)")
    conn.close()


def login_gui(username, password):
    conn = get_connection()
    cursor = conn.cursor()
    hashed_password = hash_password(password)
    cursor.execute("SELECT password, role FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()
    if result is None:
        return "User not found"
    stored_password, role = result
    if stored_password != hashed_password:
        return "Incorrect password"
    return f"Success:{role}"


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
            "INSERT INTO users (username, password, role, email) VALUES (?, ?, ?, ?)",
            (username, hashed_password, "user", "")
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
    cursor.execute(
        "SELECT password, role, failed_attempts, lock_time FROM users WHERE username = ?",
        (username,))
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
            print(f"Login successful! Role: {role}")
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
            cursor.execute(
                "UPDATE users SET failed_attempts = ?, lock_time = ? WHERE username = ?",
                (failed_attempts, time.time(), username)
            )
            print("Account locked.")
            log_activity("ALERT", f"Account locked: {username}")
        else:
            cursor.execute(
                "UPDATE users SET failed_attempts = ? WHERE username = ?",
                (failed_attempts, username)
            )
            print("Incorrect password!")
            log_activity("WARNING", f"Incorrect password for: {username}")
        conn.commit()
    conn.close()


def user_menu(username):
    while True:
        print(f"\nWelcome {username} (User)")
        print("1. Change Password")
        print("2. Logout")
        choice = input("Choose option: ")
        if choice == "1":
            new_pw = input("Enter new password: ")
            if is_strong_password(new_pw):
                change_password(username, new_pw)
                print("Password updated.")
            else:
                print("Weak password.")
        elif choice == "2":
            break
        else:
            print("Invalid option.")


def admin_menu():
    while True:
        print("\n1. View All Users\n2. Delete User\n3. Unlock User"
              "\n4. Promote User to Admin\n5. View Logs\n6. Logout")
        choice = input("Choose option: ")
        if   choice == "1": view_users_cli()
        elif choice == "2": delete_user_cli()
        elif choice == "3": unlock_user_cli()
        elif choice == "4": promote_user_cli()
        elif choice == "5": view_logs_cli()
        elif choice == "6": break
        else: print("Invalid option.")


def view_users_cli():
    for u in view_users():
        print(f"Username: {u[0]}, Role: {u[1]}")

def delete_user_cli():
    u = input("Username to delete: ")
    print(delete_user(u))

def unlock_user_cli():
    u = input("Username to unlock: ")
    print(unlock_user(u))

def promote_user_cli():
    u = input("Username to promote: ")
    print(promote_user(u))

def view_logs_cli():
    print(view_logs())
