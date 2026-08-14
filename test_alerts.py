from app import create_app
from app.extensions import db
from app.models import LogEntry
from app.dlp import detect_logs_and_generate_alerts_for_selected_logs, SERVICE_RULES_CACHE
import json, re

app = create_app()

with app.app_context():
    logs = LogEntry.query.filter_by(processed=False).order_by(LogEntry.timestamp.asc()).limit(10).all()
    if not logs:
        print("No unprocessed logs found.")
    else:
        logs_dicts = []
        for log in logs:
            parsed_raw = log.raw_log if isinstance(log.raw_log, dict) else json.loads(log.raw_log or "{}")
            message = log.message or parsed_raw.get("event") or parsed_raw.get("log") or ""
            logs_dicts.append({
                "id": log.id,
                "log_type": log.log_type,
                "agent_name": log.source or parsed_raw.get("agent_name") or "Unknown",
                "message": message,
                "raw_log": log.raw_log,
                "parsed_raw": parsed_raw,
                "timestamp": log.timestamp
            })

        # Print matched rules for each log
        for log in logs_dicts:
            matched_rule_ids = []
            for r in SERVICE_RULES_CACHE.get(log["log_type"], []):
                detection = r.get("detection")
                if detection:
                    for cond in detection.get("conditions", []):
                        pattern = cond.get("pattern")
                        if pattern and re.search(pattern, log["message"]):
                            matched_rule_ids.append(r["id"])
                            break
            print(f"Log ID {log['id']} | Type: {log['log_type']} | Matched Rules: {matched_rule_ids}")

        # Generate alerts
        alerts = detect_logs_and_generate_alerts_for_selected_logs(logs_dicts)
        print(f"\nTotal alerts generated: {len(alerts)}")
        for a in alerts:
            print(f"Alert ID: {a.id}, Log ID: {a.matched_log_id}, Rule ID: {a.rule_id}, "
                  f"Severity: {a.severity}, Description: {a.description[:100]}")

        # Mark logs as processed
        for log in logs:
            log.processed = True
        db.session.commit()
        print("\nAll processed logs marked as processed.")
