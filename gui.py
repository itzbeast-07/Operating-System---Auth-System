import tkinter as tk
from tkinter import messagebox
from auth import login
from auth import login_gui
from auth import register
from auth import register_gui

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

        result = login_gui(username, password)

        if result.startswith("Success"):
            role = result.split(":")[1]
            messagebox.showinfo("Login", f"Welcome {role}")
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

root = tk.Tk()
root.title("Secure Auth System")
root.geometry("400x350")

show_login()

root.mainloop()
