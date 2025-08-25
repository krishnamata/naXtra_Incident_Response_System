# app/models/agent_heartbeat.py
from app.extensions import db
from datetime import datetime

class AgentHeartbeat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    agent_name = db.Column(db.String(50), nullable=False)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
