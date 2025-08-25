from app.extensions import db
from datetime import datetime
from app.models.enums import AlertStatus
from sqlalchemy.dialects.postgresql import JSON 
from sqlalchemy import Enum as SQLEnum

class Alert(db.Model):
    __tablename__ = 'alerts'

    id = db.Column(db.Integer, primary_key=True)
    log_id = db.Column(db.Integer)
    rule_id = db.Column(db.String(64))
    rule_title = db.Column(db.String(255))
    description = db.Column(db.Text)
    severity = db.Column(db.String(50))
    tactic = db.Column(db.String(100))
    technique_id = db.Column(db.String(50))
    technique_name = db.Column(db.String(255))
    tags = db.Column(db.Text)
    playbook_id = db.Column(db.Integer, db.ForeignKey('playbooks.id'), nullable=True)
    playbook = db.relationship('Playbook', backref='alerts')
    agent_name = db.Column(db.String(100))
    detected_time = db.Column(db.DateTime, default=datetime.utcnow)
    matched_log_id = db.Column(db.Integer, db.ForeignKey('logs.id'))
    status = db.Column(SQLEnum(AlertStatus), nullable=False, default=AlertStatus.NEW)
    enrichment_data = db.Column(db.JSON, nullable=True)
    enrichment_status = db.Column(db.String(50), nullable=True)
    enrichment_source = db.Column(db.String(100), nullable=True)
    enrichment_timestamp = db.Column(db.DateTime, nullable=True)
    md5_hash = db.Column(db.String(64), nullable=True)
    sha256_hash = db.Column(db.String(128), nullable=True)
    ioc_type = db.Column(db.String(50), nullable=True)    
    ioc_value = db.Column(db.Text, nullable=True)     


    def get_playbook(self):
        return self.playbook  # Adjust if your column is named differently
