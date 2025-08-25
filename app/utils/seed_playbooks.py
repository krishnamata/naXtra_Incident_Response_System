from app import create_app, db
from app.utils.playbook import Playbook

app = create_app()
app.app_context().push()

def seed_playbooks():
    playbooks = [
        Playbook(
            name="Suspicious Activity",
            keyword="Suspicious",
            min_severity=7,
            max_severity=8,
            steps=[
                "Review user login times and sources.",
                "Check recent file access history.",
                "Verify any anomalous behavior."
            ],
        ),
        Playbook(
            name="Privilege Escalation",
            keyword="Privilege",
            min_severity=9,
            max_severity=10,
            steps=[
                "Identify accounts with recent privilege changes.",
                "Check audit logs for suspicious escalations.",
                "Disable or isolate suspicious accounts temporarily.",
                "Run memory dump analysis if necessary."
            ],
        ),
        Playbook(
            name="Malware Incident",
            keyword="Malware",
            min_severity=11,
            max_severity=12,
            steps=[
                "Isolate affected endpoint from network.",
                "Scan files with antivirus and YARA rules.",
                "Collect malware sample and hash for analysis.",
                "Check for persistence mechanisms (registry, services, etc.)."
            ],
        ),
        Playbook(
            name="Insider Threat",
            keyword="Insider",
            min_severity=13,
            max_severity=14,
            steps=[
                "Review file transfer activity (USB, cloud).",
                "Investigate long-term login patterns.",
                "Check data exfiltration through proxy logs.",
                "Engage HR for insider behavior evaluation."
            ],
        ),
        Playbook(
            name="Critical Incident",
            keyword="Critical",
            min_severity=15,
            max_severity=15,
            steps=[
                "Immediately isolate affected systems.",
                "Notify senior incident response team.",
                "Initiate full forensic acquisition.",
                "Begin breach notification protocol if necessary."
            ],
        ),
    ]

    for pb in playbooks:
        existing = Playbook.query.filter_by(name=pb.name).first()
        if not existing:
            db.session.add(pb)
    db.session.commit()
    print("Playbooks seeded successfully.")

if __name__ == "__main__":
    seed_playbooks()
