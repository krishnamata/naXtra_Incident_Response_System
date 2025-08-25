from app import db
from datetime import datetime

class DetectionRule(db.Model):
    __tablename__ = 'detection_rules'

    id = db.Column(db.Integer, primary_key=True)
    rule_id = db.Column(db.String(100), nullable=True)
    title = db.Column(db.String(255), nullable=False)
    tactic = db.Column(db.String(100), nullable=True)
    description = db.Column(db.Text, nullable=True)
    filename = db.Column(db.String(100), nullable=False)
    source = db.Column(db.String(50), default="github")
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<DetectionRule {self.title}>"
