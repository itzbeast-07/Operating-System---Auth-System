from datetime import datetime

def log_activity(level, message):
    with open("logs.txt", "a") as file:
        time_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        file.write(f"[{time_now}] [{level}] {message}\n")