import sqlite3

def get_connection():
    return sqlite3.connect("users.db") 


def initialize_database():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password TEXT NOT NULL,
        role TEXT NOT NULL,
        email TEXT NOT NULL,
        failed_attempts INTEGER DEFAULT 0,
        lock_time REAL DEFAULT 0
    )
    """)

    conn.commit()
    conn.close()