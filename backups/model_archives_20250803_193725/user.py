from datetime import datetime
from sqlalchemy import Enum as SQLEnum
from app.models.enums import UserStatus
from app import db
from werkzeug.security import check_password_hash, generate_password_hash
import pyotp
from flask_login import UserMixin

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
 # Flask-Login required properties

    @property
    def is_active(self):
        # Only active users can log in
        return self.status == 'active'

    @property
    def is_authenticated(self):
        return True  # Return True if user is authenticated (after login)

    @property
    def is_anonymous(self):
        return False  # Anonymous users are not actual users

    def get_id(self):
        return str(self.id)
