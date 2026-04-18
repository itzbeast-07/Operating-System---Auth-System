import tkinter as tk
from tkinter import messagebox
from auth import login
from auth import login_gui
from auth import register
from auth import register_gui
from auth import start_login, verify_otp, register_gui
from tkinter import simpledialog
from auth import view_users, view_logs, delete_user



def clear_screen():
    for widget in root.winfo_children():
        widget.destroy()



def show_login():
    clear_screen()

    tk.Label(root, text="Login", font=("Arial", 16)).pack(pady=10)

    tk.Label(root, text="Username").pack()
    username_entry = tk.Entry(root)
    username_entry.pack()

    tk.Label(root, text="Password").pack()
    password_entry = tk.Entry(root, show="*")
    password_entry.pack()

    def login_action():
        username = username_entry.get()
        password = password_entry.get()

        result = start_login(username, password)

        if result == "OTP_SENT":
            messagebox.showinfo("OTP", "OTP sent to your email.")
            show_otp_screen(username)
        else:
            messagebox.showerror("Error", result)

    tk.Button(root, text="Login", command=login_action).pack(pady=10)

    tk.Button(root, text="Go to Register", command=show_register).pack()



def show_register():
    clear_screen()

    tk.Label(root, text="Register", font=("Arial", 16)).pack(pady=10)

    tk.Label(root, text="Username").pack()
    username_entry = tk.Entry(root)
    username_entry.pack()

    tk.Label(root, text="Password").pack()
    password_entry = tk.Entry(root, show="*")
    password_entry.pack()

    tk.Label(root, text="Email").pack()
    email_entry = tk.Entry(root)
    email_entry.pack()

    def register_action():
        username = username_entry.get()
        password = password_entry.get()
        email = email_entry.get()

        result = register_gui(username, password, email)

        if result == "Success":
            messagebox.showinfo("Success", "User registered!")
            show_login()
        else:
            messagebox.showerror("Error", result)

    tk.Button(root, text="Register", command=register_action).pack(pady=10)

    tk.Button(root, text="Back to Login", command=show_login).pack()




def show_otp_screen(username):
    clear_screen()

    tk.Label(root, text="OTP Verification", font=("Arial", 16)).pack(pady=10)
    tk.Label(root, text="Enter OTP sent to your email").pack()

    otp_entry = tk.Entry(root)
    otp_entry.pack(pady=5)

    def verify_action():
        otp = otp_entry.get()

        result = verify_otp(username, otp)

        if result.startswith("Success"):
            role = result.split(":")[1]
            if role == "admin":
                show_admin_dashboard(username)
            else:
                show_user_dashboard(username)
            messagebox.showinfo("Success", f"Welcome {role}")
        else:
            messagebox.showerror("Error", result)

    tk.Button(root, text="Verify OTP", command=verify_action).pack(pady=10)
    tk.Button(root, text="Back to Login", command=show_login).pack()


def show_admin_dashboard(username):
    clear_screen()

    tk.Label(root, text="Admin Dashboard", font=("Arial", 16)).pack(pady=10)
    tk.Label(root, text=f"Welcome {username}").pack(pady=5)

    tk.Button(root, text="View Users", width=20, command=view_users_gui).pack(pady=5)
    tk.Button(root, text="View Logs", width=20, command=view_logs_gui).pack(pady=5)
    tk.Button(root, text="Delete User", width=20, command=delete_user_gui).pack(pady=5)
    tk.Button(root, text="Logout", width=20, command=show_login).pack(pady=10)


def show_user_dashboard(username):
    clear_screen()

    tk.Label(root, text="User Dashboard", font=("Arial", 16)).pack(pady=10)
    tk.Label(root, text=f"Welcome {username}").pack(pady=5)

    tk.Button(root, text="Change Password", width=20,
            command=lambda: messagebox.showinfo("Info", "Coming next")).pack(pady=5)

    tk.Button(root, text="Logout", width=20, command=show_login).pack(pady=10)


def view_users_gui():
    users = view_users()

    text = ""
    for user in users:
        text += f"Username: {user[0]} | Role: {user[1]}\n"

    messagebox.showinfo("Users", text)


def view_logs_gui():
    logs = view_logs()
    messagebox.showinfo("System Logs", logs)

def delete_user_gui():
    username = simpledialog.askstring("Delete User", "Enter username:")

    if username:
        result = delete_user(username)
        messagebox.showinfo("Result", result)





root = tk.Tk()
root.title("Secure Auth System")
root.geometry("400x350")

show_login()

root.mainloop()
