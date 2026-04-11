from db import initialize_database
from auth import register, login, create_admin

initialize_database()
create_admin()

print("Database Initialized Successfully.")

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