# app/playbooks/dispatcher.py

from sqlalchemy import func
from app.utils.playbook import Playbook

def dispatch_playbook(alert):
    severity = int(alert.severity)
    keyword = alert.playbook.name if alert.playbook else ""

    # Query playbook where keyword matches (case-insensitive) and severity is in range
    playbook = Playbook.query.filter(
        Playbook.keyword.ilike(f"%{keyword}%"),
        Playbook.min_severity <= severity,
        Playbook.max_severity >= severity
    ).first()

    if playbook:
        return playbook.steps
    return ["No specific playbook found for this alert. Please escalate to Security Officer."]


def assign_playbook_to_alert(alert):
    severity = int(alert.severity or 0)
    desc = (alert.description or "").lower()

    playbook_obj = None

    # Assign based on keywords in description
    if "buffer overflow" in desc or "heap overflow" in desc:
        playbook_obj = Playbook.query.filter(func.lower(Playbook.name) == "malware").first()
    elif severity >= 15:
        playbook_obj = Playbook.query.filter(func.lower(Playbook.name) == "critical").first()
    elif 13 <= severity <= 14:
        playbook_obj = Playbook.query.filter(func.lower(Playbook.name) == "insider").first()
    elif 11 <= severity <= 12:
        playbook_obj = Playbook.query.filter(func.lower(Playbook.name) == "malware").first()
    elif 9 <= severity <= 10:
        playbook_obj = Playbook.query.filter(func.lower(Playbook.name) == "privilege").first()
    elif 7 <= severity <= 8:
        playbook_obj = Playbook.query.filter(func.lower(Playbook.name) == "suspicious").first()

    alert.playbook = playbook_obj
