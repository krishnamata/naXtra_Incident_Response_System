# File: dlp_test.py
from app.rules.rules_engine import RuleEngine
from app.rules.rules_loader import load_rules
from app.models import LogEntry, Alert
from app.extensions import db
from app import create_app
from dateutil.parser import parse as parse_date
from datetime import datetime
import json

def safe_json_load(data):
    if not data:
        return {}
    try:
        return data  # If SQLAlchemy already decodes JSON, just return it
    except Exception:
        return {}


def fetch_and_parse_logs():
    """
    Fetch recent logs from database and normalize/parse them.
    """
    logs = LogEntry.query.order_by(LogEntry.timestamp.desc()).all()
    #print(f"[from fetch and parse logs] fetch_and_parse_logs fetched {len(logs)} logs from DB")

    parsed_logs = []

    for log in logs:
        message = ''
        agent_name = log.source or 'unknown'
        raw_log_data = {}

        try:
            if isinstance(log.raw_log, str):
                raw_log_data = json.loads(log.raw_log)
            elif isinstance(log.raw_log, dict):
                raw_log_data = log.raw_log
            else:
                raw_log_data = {}
        except Exception as e:
            print(f"[Warning] Failed to parse raw_log JSON for log ID={log.id}: {e}")
            continue

        # Try to extract message from known keys
        message = raw_log_data.get("log") or \
                  raw_log_data.get("event") or \
                  raw_log_data.get("raw") or ""

        # Try to extract agent name from known structures
        agent_name = (
            raw_log_data.get("agent_name") or
            raw_log_data.get("agent", {}).get("name") or
            raw_log_data.get("agent_hostname") or
            log.source or
            "unknown"
        )

        parsed_logs.append({
            'id': log.id,
            'agent_name': agent_name,
            'log_type': log.log_type or 'unknown',
            'message': str(message).lower(),
            'raw_log': raw_log_data,
            'timestamp': log.timestamp.isoformat() if isinstance(log.timestamp, datetime) else str(log.timestamp),
        })

    #print(f"[Test from fetch and parse logs] Total logs fetched and parsed: {len(parsed_logs)}")
    return parsed_logs


def match_log(log, rules):
    engine = RuleEngine(rules)
    return engine.match_log(log)


def generate_alerts_from_matches(matches):
    """
    Given matched rules, create Alert objects.
    """
    alerts = []
    for match in matches:
        log = match.get('log', {})
        log_id = log.get('id')
        rule_id = match.get('rule_id')
        title = match.get('title', 'NA')
        description = match.get('description', 'NA')
        severity = match.get('severity', 0)
        detected_time = parse_date(log.get('timestamp')) if log.get('timestamp') else datetime.utcnow()

        exists = Alert.query.filter_by(log_id=log_id, rule_id=rule_id).first()
        if exists:
            continue  # Skip duplicates

        alert = Alert(
            agent_name=log.get('agent_name'),
            log_id=log_id,
            rule_id=rule_id,
            rule_title=title,
            description=description,
            severity=severity,
            detected_time=detected_time,
            tactic=match.get('tactic', 'Test'),
            technique_id=match.get('technique_id', 'Txxxx'),
            technique_name=match.get('technique_name', 'Test Technique'),
            tags="test"
        )
        alerts.append(alert)
    return alerts

def main():
    app = create_app()
    with app.app_context():
        # Load detection rules
        rules = load_rules("app/rules/wazuh-ruleset/rules/")
        #print(f"[Test] Total rules loaded: {len(rules)}")
        #print("Checking if test rule is loaded:")
        for rule in rules:
            if 'unique_test_keyword' in rule.get('match', ''):
                print(f"Found test rule: ID={rule.get('rule_id')}, match={rule.get('match')}")

        # Fetch and parse logs
        logs = fetch_and_parse_logs()
        # After fetching logs
        #agent_logs = [log for log in logs if log.get('agent_name') and log.get('agent_name').lower() != 'unknown']
 
        #print(f"[Test] Total logs from agents: {len(agent_logs)}")
        #print("[Test] Printing first 20 agent logs:")

        #for i, log in enumerate(agent_logs[:20]):
            #print(f"Log #{i+1} ID={log['id']}, agent={log['agent_name']}, message: {log['message'][:100]}")



        # Match logs against rules
        matched_alerts = []
        for log in logs:
            print(f"[Test] Testing log message: {log['message']}")
            matched_rules = match_log(log, rules)
            for rule in matched_rules:
                # Attach log info to rule for alert creation
                rule['log'] = log
                matched_alerts.append(rule)

        print(f"[Test] Total matched alerts: {len(matched_alerts)}")

        # Generate Alert objects from matches
        new_alerts = generate_alerts_from_matches(matched_alerts)

        if new_alerts:
            db.session.add_all(new_alerts)
            db.session.commit()
            print(f"[Test] Inserted {len(new_alerts)} new alerts")
        else:
            print("[Test] No new alerts inserted")

if __name__ == "__main__":
    main()

