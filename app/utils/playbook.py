from app import db
from sqlalchemy import Text
from sqlalchemy.dialects.postgresql import JSON  # if using Postgres; else use PickleType or Text

class Playbook(db.Model):
    __tablename__ = "playbooks"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)   # e.g. "Malware Incident"
    keyword = db.Column(db.String(50), nullable=False)               # e.g. "Malware"
    min_severity = db.Column(db.Integer, nullable=False)
    max_severity = db.Column(db.Integer, nullable=False)
    steps = db.Column(JSON, nullable=False)                          # list of strings (playbook steps)

    # New fields
    emerging_threats = db.Column(db.Text, nullable=True)             # Plain text or markdown
    mitre_tactics = db.Column(JSON, nullable=True)                   # List of tactics (strings)
    mitre_techniques = db.Column(JSON, nullable=True)                # List of dicts [{id, name}]
 

    def __repr__(self):
        return f"<Playbook {self.name} ({self.keyword})>"
