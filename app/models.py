from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from sqlalchemy import Boolean
from sqlalchemy.dialects.postgresql import JSON
from sqlalchemy import Enum as SQLEnum
import pyotp

from app.extensions import db
from app.utils.enums import AlertStatus
from app.utils.playbook import Playbook

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
    md5_hash = db.Column(db.String(32), index=True, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)  


# --- Alert Model (Unified) ---
class Alert(db.Model):
    __tablename__ = 'alerts'

    id = db.Column(db.Integer, primary_key=True)

    # Rule Info
    rule_id = db.Column(db.String(64))
    rule_title = db.Column(db.String(255))
    description = db.Column(db.Text)
    severity = db.Column(db.Integer)
    tactic = db.Column(db.String(100))
    technique_id = db.Column(db.String(50))
    technique_name = db.Column(db.String(255))
    tags = db.Column(db.Text)
    is_malware = db.Column(db.Boolean, default=False)
    is_escalated = db.Column(db.Boolean, default=False)
    remedy_steps = db.Column(JSON, nullable=True)

    # Agent & Detection
    agent_name = db.Column(db.String(100))
    detected_time = db.Column(db.DateTime, default=datetime.utcnow)

    # Log Matching
    matched_log_id = db.Column(db.Integer, db.ForeignKey('logs.id'))
    matched_log = db.relationship('LogEntry', backref=db.backref('alerts', lazy=True))

    # Playbook Relation
    playbook_id = db.Column(db.Integer, db.ForeignKey('playbooks.id'), nullable=True)
    playbook = db.relationship('Playbook', backref='alerts')

    # Status & Enrichment
    is_new = db.Column(Boolean, nullable=False, default=True)
    status = db.Column(SQLEnum(AlertStatus), nullable=False, default=AlertStatus.NEW)
    enrichment_data = db.Column(JSON, nullable=True)
    enrichment_status = db.Column(db.String(50), nullable=True)
    enrichment_source = db.Column(db.String(100), nullable=True)
    enrichment_timestamp = db.Column(db.DateTime, nullable=True)
    ai_suggestions = db.Column(JSON, nullable=True)

    # IOC Info
    md5_hash = db.Column(db.String(64), nullable=True)
    sha256_hash = db.Column(db.String(128), nullable=True)
    ioc_type = db.Column(db.String(50), nullable=True)
    ioc_value = db.Column(db.Text, nullable=True)
    cvss_score = db.Column(db.Float, nullable=True)
    assigned_to_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    assigned_to_user = db.relationship('User', backref='alerts_assigned')

# Add below your existing models
class MitreTactic(db.Model):
    __tablename__ = 'mitre_tactics'
    id = db.Column(db.Integer, primary_key=True)
    tactic_id = db.Column(db.String(20), unique=True, nullable=False)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    url = db.Column(db.String(255))
    deprecated = db.Column(db.Boolean, default=False) 
    platforms = db.Column(db.Text)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)
    source = db.Column(db.String(50), default='local')
    mitre_version = db.Column(db.String(10))
    techniques = db.relationship('MitreTechnique', backref='tactic', lazy=True)


class MitreTechnique(db.Model):
    __tablename__ = 'mitre_techniques'
    id = db.Column(db.Integer, primary_key=True)
    technique_id = db.Column(db.String(20), unique=True, nullable=False)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    tactic_id = db.Column(db.String(20), db.ForeignKey('mitre_tactics.tactic_id'), nullable=False)
    tactic_name = db.Column(db.String(255))
    platforms = db.Column(db.Text)
    mitigations = db.Column(JSON)
    url = db.Column(db.String(255))
    deprecated = db.Column(db.Boolean, default=False)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)
    source = db.Column(db.String(50), default='local')
    mitre_version = db.Column(db.String(10))


class MitreMetadata(db.Model):
    __tablename__ = 'mitre_metadata'
    id = db.Column(db.Integer, primary_key=True)
    current_version = db.Column(db.String(10))
    last_sync_timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    next_scheduled_sync = db.Column(db.DateTime)


    def get_playbook(self):
        return self.playbook


class Tasks(db.Model):
    __tablename__ = 'tasks'

    task_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    type = db.Column(db.String(10), nullable=False)  # 'log', 'alert', 'risk'
    content_id = db.Column(db.Integer, nullable=False)
    assigned_to = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'), nullable=True)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'), nullable=False)
    status = db.Column(db.String(20), nullable=False, default='pending')  # 'pending', 'in-progress', 'completed', 'canceled'
    priority = db.Column(db.String(20), nullable=False, default='medium')  # 'low', 'medium', 'high', 'critical'
    notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Optional: convenience relationship to User
    assigned_user = db.relationship('User', foreign_keys=[assigned_to], backref='tasks_assigned')
    created_user = db.relationship('User', foreign_keys=[created_by], backref='tasks_created')


class TaskStep(db.Model):
    __tablename__ = 'task_steps'
    step_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    task_id = db.Column(db.Integer, db.ForeignKey('tasks.task_id', ondelete='CASCADE'))
    step_name = db.Column(db.String(255), nullable=False)
    completed = db.Column(db.Boolean, default=False)
    evidence_text = db.Column(db.Text, nullable=True)
    evidence_file = db.Column(db.String(255), nullable=True)
    assigned_user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    task = db.relationship('Tasks', backref='steps')
    assigned_user = db.relationship('User')

class AlertStepWork(db.Model):
    __tablename__ = "alert_step_work"

    id = db.Column(db.Integer, primary_key=True)
    alert_id = db.Column(db.Integer, db.ForeignKey('alerts.id'), nullable=False)
    nist_phase = db.Column(db.String(50), nullable=False)
    sub_step = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(50), default="pending")   # pending, in_progress, completed, false_positive
    notes = db.Column(db.Text)
    updated_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)
    reviewed_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    reviewed_at = db.Column(db.DateTime, nullable=True)
    review_status = db.Column(db.String(20), nullable=True)  # 'approved' / 'rejected'
    
    alert = db.relationship('Alert', backref='steps')
    updater = db.relationship('User', foreign_keys=[updated_by])
    reviewer = db.relationship('User', foreign_keys=[reviewed_by])

    # New reviewer fields
    
class AlertEvidence(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    step_id = db.Column(db.Integer, db.ForeignKey('alert_step_work.id', ondelete='CASCADE'))
    evidence_type = db.Column(db.String(20), default="note")  # 'note', 'image', 'log', etc.
    evidence_text = db.Column(db.Text)
    file_path = db.Column(db.String(255))   # path to uploaded file
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

    step = db.relationship("AlertStepWork", backref="evidences")
    user = db.relationship("User")
    file_hash = db.Column(db.String(64), nullable=True)

class AlertHistory(db.Model):
    __tablename__ = "alert_history"

    id = db.Column(db.Integer, primary_key=True)
    alert_id = db.Column(db.Integer, db.ForeignKey('alerts.id'), nullable=False)
    action = db.Column(db.String(100))   # 'step_completed', 'marked_false_positive', 'restored', etc.
    details = db.Column(db.Text)
    performed_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    performed_at = db.Column(db.DateTime, default=datetime.utcnow)

    alert = db.relationship("Alert", backref="history")
    user = db.relationship("User")
