from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer  # if needed
import pyotp
from app.extensions import db  # Already initialized globally
from datetime import datetime

# --- User Model ---
# --- User Model ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), default='user')  
    status = db.Column(db.String(20), default='pending')
    full_name = db.Column(db.String(120))
    photo_path = db.Column(db.String(255))
    date_of_birth = db.Column(db.Date)    
    contact_number = db.Column(db.String(20))
    family_contact_number = db.Column(db.String(20))
    personal_email = db.Column(db.String(120))
    office_email = db.Column(db.String(120)) 
    academic_certificate_path = db.Column(db.String(255))
    international_certificate_path = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    is_approved = db.Column(db.Boolean, default=False)
    is_rejected = db.Column(db.Boolean, default=False)
    mfa_enabled = db.Column(db.Boolean, default=False)
    otp_secret = db.Column(db.String(32), default=pyotp.random_base32)


    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def is_admin(self):
        return self.role == 'admin'


# --- Log Entry Model ---
class LogEntry(db.Model):
    __tablename__ = 'logs'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    source = db.Column(db.String(50))
    log_type = db.Column(db.String(50))
    message = db.Column(db.Text)
    raw_log = db.Column(db.JSON)
    md5_hash = db.Column(db.String(32), index=True, unique=True, nullable=True)  



# --- Alert Model ---
class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Required fields used in dashboard/alerts
    detected_time = db.Column(db.DateTime, default=datetime.utcnow)
    rule_id = db.Column(db.String(50))
    rule_title = db.Column(db.String(255))
    description = db.Column(db.Text)
    severity = db.Column(db.Integer)
    tactic = db.Column(db.String(255))
    technique_id = db.Column(db.String(50))
    technique_name = db.Column(db.String(255))
    tags = db.Column(db.String(255))
    playbook = db.Column(db.String(255))
    agent_name = db.Column(db.String(255))  # Critical for grouping by agent

    matched_log_id = db.Column(db.Integer, db.ForeignKey('logs.id'))
    matched_log = db.relationship('LogEntry', backref=db.backref('alerts', lazy=True))
