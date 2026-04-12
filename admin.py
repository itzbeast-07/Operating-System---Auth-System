from db import get_connection
from logger import log_activity

def view_users():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT username, role FROM users")
    users = cursor.fetchall()

    print("\n--- Registered Users ---")
    log_activity("INFO", "Admin viewed all users")
    for user in users:
        print(f"Username: {user[0]}, Role: {user[1]}")

    conn.close()


    
def view_logs():
    print("\n--- System Logs ---")
    try:
        with open("logs.txt", "r") as file:
            print(file.read())
    except FileNotFoundError:
        print("No logs found.")  



def delete_user():
    username = input("Enter username to delete: ")

    if username == "admin":
        print("Cannot delete admin account!")
        return

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    if cursor.fetchone() is None:
        print("User not found!")
        return

    cursor.execute("DELETE FROM users WHERE username = ?", (username,))
    conn.commit()
    conn.close()

    print("User deleted successfully!")
    log_activity("ALERT", f"Admin deleted user: {username}")


def unlock_user():
    username = input("Enter username to unlock: ")

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    if cursor.fetchone() is None:
        print("User not found!")
        return

    cursor.execute(
        "UPDATE users SET failed_attempts = 0 WHERE username = ?",
        (username,)
    )
    conn.commit()
    conn.close()

    print("User account unlocked!")
    log_activity("INFO", f"Admin unlocked account: {username}")



def promote_user():
    username = input("Enter username to promote: ")

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT role FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()

    if result is None:
        print("User not found!")
        return

    if result[0] == "admin":
        print("User is already an admin!")
        return

    cursor.execute(
        "UPDATE users SET role = 'admin' WHERE username = ?",
        (username,)
    )
    conn.commit()
    conn.close()

    print("User promoted to admin!")
    log_activity("ALERT", f"User promoted to admin: {username}")

