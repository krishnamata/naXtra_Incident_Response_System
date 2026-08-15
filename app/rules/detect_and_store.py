from app.utils.description_generator import generate_alert_description
from datetime import datetime
from app import db
from app.models import Alert, LogEntry
from app.rules.rules_loader import load_rules 
from app.rules.rules_engine import RuleEngine
import os
import sys

def run_detection():
    RULES_DIR = os.path.join(os.path.dirname(__file__), "wazuh-ruleset", "rules")
    print("[*] Starting DB-based detection...")
    print("[DEBUG] detect_and_store() called")
    rules = load_rules(RULES_DIR)
    print(f"[DEBUG] Loaded {len(rules)} rules")
    engine = RuleEngine(rules)

    unprocessed_logs = LogEntry.query.all()
    print(f"[INFO] Loadedddd {len(unprocessed_logs)} unprocessed logs")

    for log in unprocessed_logs:
        log_data = log.to_dict()
        #print("[DEBUG das1] detect_and_store() called")
        matched_rules = engine.match_log(log_data)
        #print(f"[DEBUG das2] Matched rules: {matched_rules}")

        matched_rules = engine.match_log(log_data)
        #print(f"[DEBUG] Matched rules for log {log.id}: {matched_rules}")
   

        for rule in matched_rules:
           
            print(f"[DEBUG] About to generate description for rule id {rule['id']} with severity {rule['severity']}")
            desc = generate_alert_description(
                severity=rule["severity"],
                mitre={
                    "id": rule["mitre"].get("id", ""),
                    "name": rule["mitre"].get("name", ""),
                    "tactic": rule["mitre"].get("tactic", ""),
                    "impact": rule["mitre"].get("impact", "No impact data."),
                },
                matched_keywords=rule.get("matched_keywords", [])
            )
            print("[DEBUG] Generated description: {desc!r}")
            #print("[DEBUG detectandstore.py] MITRE:", rule.get("mitre"))
            alert = Alert(
                log_id=log.id,
                rule_id=rule["id"],
                rule_title=rule["title"],
                description=description_text,
                severity=rule["severity"],
                playbook=rule.get("playbook", ""),
                tactic=rule["mitre"].get("tactic", ""),
                technique_id=rule["mitre"].get("id", ""),
                technique_name=rule["mitre"].get("name", ""),
                tags=",".join(rule.get("tags",[])),
                detected_time=datetime.now(),
                agent_name=log_data.get("log_type") 
            )
            db.session.add(alert)
            print(f"[ALERT] {log.id} matched {rule['title']}")

        log.processed = True

    db.session.commit()
    print("[✓] Detection complete and alerts saved.")

if __name__ == "__main__":
    from app.main import app
    with app.app_context():
        run_detection()
