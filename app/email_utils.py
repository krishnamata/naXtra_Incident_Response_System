from flask_mail import Message
from flask import current_app
from app.extensions import mail

def send_email(to, subject, body):
    try:
        msg = Message(subject=subject, recipients=[to])
        msg.body = body
        mail.send(msg)
        current_app.logger.info(f"✅ Email sent to {to}")
    except Exception as e:
        current_app.logger.error(f"❌ Failed to send email to {to}: {str(e)}")

