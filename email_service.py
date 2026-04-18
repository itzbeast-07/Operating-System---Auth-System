import smtplib
from email.mime.text import MIMEText

EMAIL = "example@gmail.com"
APP_PASSWORD = "example"

def send_otp_email(receiver_email, otp):
    subject = "Secure Auth OTP"
    body = f"Your OTP is {otp}. It expires in 60 seconds."

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = EMAIL
    msg["To"] = receiver_email

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(EMAIL, APP_PASSWORD)
            server.send_message(msg)
        return True
    except Exception as e:
        print("Email error:", e)
        return False