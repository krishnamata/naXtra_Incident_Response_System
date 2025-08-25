import smtplib
from email.mime.text import MIMEText
from flask import current_app

def send_email(to, subject, body):
    sender = 'naxtra@yourdomain.com'
    smtp_server = 'smtp.yourdomain.com'
    smtp_port = 587
    smtp_user = 'naxtra@yourdomain.com'
    smtp_password = 'your_password'

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = to

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.send_message(msg)
            print(f"✅ Email sent to {to}")
    except Exception as e:
        print(f"❌ Email failed: {e}")
