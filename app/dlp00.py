Can you share updated full code with this integration? ─$ cat app/dlp.py              
import json
from flask import current_app
from app.models import LogEntry, Alert
from app.extensions import db
from app.rules.rules_loader import load_rules
from app.rules.rules_engine import RuleEngine
import re
import logging
from flask import current_app


#logger = current_app.logger if current_app else None

# Load rules once globally
RULES = load_rules("app/rules/wazuh-ruleset/rules")
RULE_ENGINE = RuleEngine(RULES)

print("[DEBUG] Imported dlp00.py") # in dlp00.py
def get_logger():
    try:
        return current_app.logger
    except RuntimeError:
        # Happens if no Flask app context
        return logging.getLogger(__name__)

logger = get_logger()

def fetch_logs_by_type(log_type: str, limit=None):
    """
    Fetch logs from the database filtered by log_type.
    Normalizes unknown log_type to 'generic'.
    Prints sample logs for debugging.
    """
    try:
        valid_log_types = {"journalctl", "eventlog", "syslog", "siem", "generic"}
        normalized_type = log_type.lower()
        if normalized_type not in valid_log_types:
            normalized_type = "generic"

        query = LogEntry.query.filter_by(log_type=normalized_type)
        if limit:
            query = query.limit(limit)
        logs = query.all()

        log_dicts = [log.to_dict() for log in logs]
        print(f"\n--- Sample logs for type '{normalized_type}' (up to {limit or 10}) ---")
        for i, log in enumerate(log_dicts[:limit or 10]):
            print(f"[{i+1}] {log}")

        return log_dicts

    except Exception as e:
        # Use print instead of logger in case logger is None during startup
        print(f"[ERROR] Error fetching logs for type '{log_type}': {e}")
        return []

def match_logs_to_rules(logs, rules):
    matched_alerts = []
    for log in logs:
        for rule in rules:
            if rule_matches_log(rule, log):
                matched_alerts.append((log, rule))
    return matched_alerts





def rule_matches_log(rule, log):
    message = log.get("message", "")
    raw = json.dumps(log.get("raw_log", {}))
    agent = log.get("agent_name", "")

    # Strict condition matching using RuleEngine first
    if RULE_ENGINE.match_log(log):
        return True

    # Fallback to loose match if severity >= 7
    if rule.get("severity", 0) >= 7:
        search_pool = f"{message} {raw}".lower()

        # Check keywords from match/regex
        for keyword in rule.get("keywords", []):
            if keyword.lower() in search_pool:
                logger.debug(f"[LOOSE MATCH] Rule {rule['id']} matched keyword '{keyword}' in log")
                return True

        # Check description if no keyword matched
        description = rule.get("description", "").lower()
        if description and any(word in search_pool for word in description.split()):
            logger.debug(f"[LOOSE MATCH] Rule {rule['id']} matched description fragment")
            return True

    return False

def extract_log_types(rules_dir):
    """Extracts all unique log types from the RULES list."""
    log_types = set()
    for rule in RULES:
        for log_type in rule.get("log_types", []):
            log_types.add(log_type)
    return list(log_types)

def detect_logs_and_generate_alerts():
    """
    Wrapper to be called from external modules like views/routes.
    Triggers log detection and alert generation for all known log types.
    """
   
    rules_dir = "app/rules/wazuh-ruleset/rules/"
    rules = load_rules(rules_dir)
    log_types = extract_log_types(rules_dir)

    total_new_alerts = 0
    for log_type in log_types:

        logs = fetch_logs_by_type(log_type)
        
        if not logs:
        
            continue

        matched_alerts = match_logs_to_rules(logs, rules)
        alerts = generate_alerts(matched_alerts)
        print(f"generate_alerts returned {len(alerts)} alerts")
        if alerts:
            db.session.add_all(alerts)
            db.session.commit()
            logger.info(f"{len(alerts)} alerts generated for log type '{log_type}'")
            total_new_alerts += len(alerts)

    logger.info(f"DLP complete: {total_new_alerts} new alerts generated")







def generate_alert(log, rule):
    existing = Alert.query.filter_by(
        source=log.get("source"),
        rule_id=rule.get("id"),
        agent_name=log.get("agent_name"),
        timestamp=log.get("timestamp")
    ).first()

    if existing:
        return

    alert = Alert(
        source=log.get("source"),
        message=log.get("message"),
        agent_name=log.get("agent_name"),
        timestamp=log.get("timestamp"),
        severity=rule.get("severity", 1),
        rule_id=rule.get("id"),
        rule_title=rule.get("title"),
        mitre_technique_id=rule.get("technique_id"),
        mitre_technique_link=rule.get("technique_link"),
        extra=log.get("raw_log")
    )
    db.session.add(alert)
    logger.debug(f"[ALERT] Generated for rule {rule.get('id')} on log from {log.get('agent_name')}")


def run_dlp():
    alert_count = 0
    processed_logs = 0

    seen = set()
    for rule in RULES:
        if rule.get("severity", 0) < 12:
            continue  # Skip low severity
        log_types = rule.get("log_types", ["generic"])
        for log_type in log_types:
            logs = fetch_logs_by_type(log_type)
            for log in logs:
                log_uid = (log["timestamp"], log["agent_name"], log["message"])
                if log_uid in seen:
                    continue
                seen.add(log_uid)
                processed_logs += 1
                if rule_matches_log(rule, log):
                    generate_alert(log, rule)
                    alert_count += 1

    db.session.commit()
    logger.info(f"DLP complete: {alert_count} new alerts generated out of {processed_logs} logs")
  
 
