import os
from flask import Flask
from flask_mail import Mail, Message
from dotenv import load_dotenv

load_dotenv()  # Load .env variables if using .env file

app = Flask(__name__)

app.config['MAIL_SERVER'] = 'mail.mataservice.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'krishna@mataservice.com'
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')  # ✅ safer
app.config['MAIL_DEFAULT_SENDER'] = 'krishna@mataservice.com'

mail = Mail(app)

@app.route("/test-mail")
def test_mail():
    try:
        msg = Message("Test from Flask", recipients=['krishna.sewa2017@gmail.com'])
        msg.body = "Mail test using env variable for password."
        mail.send(msg)
        return "✅ Email sent successfully!"
    except Exception as e:
        return f"❌ Failed to send email: {str(e)}"

if __name__ == "__main__":
    app.run(debug=True)
