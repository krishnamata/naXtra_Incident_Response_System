from app import create_app
from app.dlp import fetch_logs_by_type, match_logs_to_rules, RULES

app = create_app()

with app.app_context():
    logs = fetch_logs_by_type("journal", limit=10)
    print(f"Fetched {len(logs)} logs")

    alerts = match_logs_to_rules(logs, RULES)
    print(f"Total alerts matched: {len(alerts)}")

    for alert in alerts:
        print(f"- Rule {alert.rule_id}: {alert.rule_title} (Severity {alert.severity})")
