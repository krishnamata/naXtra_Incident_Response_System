from app.extensions import db
from datetime import datetime

class LogEntry(db.Model):
    __tablename__ = 'logs'

    id = db.Column(db.Integer, primary_key=True)
    source = db.Column(db.String(64))
    message = db.Column(db.Text)
    processed = db.Column(db.Boolean, default=False)
    log_type = db.Column(db.String(64))
    raw_log = db.Column(db.JSON)
    agent_name = db.Column(db.String(100))
    md5_hash = db.Column(db.String(64))  # New field
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'source': self.source,
            'message': self.message,
            'log_type': self.log_type,
            'raw_log': self.raw_log,
            'agent_name': self.agent_name,
            'md5_hash': self.md5_hash,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        }
