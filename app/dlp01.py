# app/dlp.py - Dynamic Log Processing (Modular Callable)

import re
import os
import logging
import xml.etree.ElementTree as ET
from sqlalchemy import or_
from dateutil.parser import parse as parse_date
from sqlalchemy import and_
from datetime import datetime
from app.utils.mitre import get_mitre_info
from app.extensions import db
from app.models import LogEntry, Playbook
from app.models.alert import Alert
from app.rules.rules_loader import load_rules, parse_detection_conditions
from app.rules.rules_engine import RuleEngine

logger = logging.getLogger(__name__)

print("\n \n\n===Debug: dlp module is loading...") # debug


def extract_log_types(rules_dir: str):
    log_types = set()
    for filename in os.listdir(rules_dir):
        if not filename.endswith('.xml'):
            continue
        filepath = os.path.join(rules_dir, filename)
        try:
            tree = ET.parse(filepath)
            root = tree.getroot()

            for rule in root.findall('rule'):
                for group in rule.findall('group'):
                    group_name = group.attrib.get('name', '')
                    for lt in group_name.split(','):
                        if lt.strip():
                            log_types.add(lt.strip())
                decoded_as = rule.findtext('decoded_as')
                if decoded_as:
                    log_types.add(decoded_as.strip())
        except Exception as e:
            logger.error(f"Error parsing {filename}: {e}")
    return sorted(log_types)

def fetch_logs_by_type(log_type: str):
    #print(f"[DEBUG] fetch_logs_by_type() called with: {log_type}", flush=True)
    try:
        logs = LogEntry.query.filter_by(log_type=log_type).all()
        return [log.to_dict() for log in logs]
    except Exception as e:
        logger.error(f"Error fetching logs for type '{log_type}': {e}")
        return []


def match_logs_to_rules(logs, rules):
    engine = RuleEngine(rules)
    matched_alerts = []

    for log in logs:
        matched_rules = engine.match_log(log)
        for match in matched_rules:
            matched_alerts.append({
                'log': log,
                'rule_id': match.get('rule_id', 'NA'),
                'rule_title': match.get('title', 'NA'),
                'description': match.get('description', 'NA'),
                'severity': match.get('severity', 1),
                'technique_id': match.get('technique_id', 'NA'),
                'technique_link': match.get('technique_link', 'NA'),
                'matched_keywords': match.get('matched_keywords', []),
                'tags': [],  # You may add tags if available
            })

    return matched_alerts


def assign_playbook_to_alert(alert):
    technique_id = alert.technique_id
    if technique_id and technique_id != "NA":
        # Query Playbook by technique_id or some related field (you need a way to map)
        playbook = db.session.query(Playbook).filter_by(name=f"Playbook for {technique_id}").first()
        if playbook:
            alert.playbook = playbook
        else:
            # fallback to default playbook
            default_playbook = db.session.query(Playbook).filter_by(name="Default Playbook").first()
            alert.playbook = default_playbook
    else:
        default_playbook = db.session.query(Playbook).filter_by(name="Default Playbook").first()
        alert.playbook = default_playbook



def generate_alerts(matched_alerts):
    alerts = []

    # Collect all log_ids and rule_ids from matched alerts
    log_ids = [m['log'].get('id') for m in matched_alerts if m['log'].get('id')]
    rule_ids = [m.get('rule_id') for m in matched_alerts if m.get('rule_id')]

    if not log_ids or not rule_ids:
        return alerts  # No valid entries to process

    # Bulk query existing alerts to prevent duplicates
    existing_alerts = Alert.query.filter(
        Alert.log_id.in_(log_ids),
        Alert.rule_id.in_(rule_ids)
    ).all()
    existing_keys = {(a.log_id, a.rule_id) for a in existing_alerts}

    for match in matched_alerts:
        log = match['log']
        if not isinstance(log, dict):
            continue  # Skip malformed logs

        log_id = log.get('id')
        rule_id = match.get('rule_id')

        if not log_id or not rule_id:
            continue  # Missing critical fields

        if (log_id, rule_id) in existing_keys:
            continue  # Skip duplicates

        technique_id = match.get("technique_id", "NA")
        technique_name = match.get("technique_name", "NA")
        severity = int(match.get("severity", 0))
        rule_title = match.get("title", "NA")
        description = match.get("description", "NA")
        tags = match.get("tags", "")
        detected_str = log.get('timestamp')

        # Safe timestamp parsing
        try:
            if isinstance(detected_str, str):
                detected_time = parse_date(detected_str)
            else:
                detected_time = detected_str
        except Exception:
            detected_time = None  # Or set to datetime.utcnow()
        
        if isinstance(tags, list):
            tags = ",".join(tags)

        # Fetch MITRE info if available
        mitre_data = None
        if technique_id and technique_id != "NA":
            mitre_data = get_mitre_info(technique_id)

        if mitre_data:
            technique_name = mitre_data.get("name", technique_name)
            tactic = mitre_data.get("tactic", "NA")
        else:
            tactic = "NA"

        # Get playbook steps based on severity & description
        from app.dlp import get_playbook  # To avoid circular import if any
        playbook_steps = get_playbook(severity, rule_title, description)
        if not playbook_steps:
            playbook_steps = ["No specific playbook found for this alert. Please escalate to Security Officer."]

        alert = Alert(
            agent_name=log.get('agent_name'),
            log_id=log_id,
            detected_time=detected_time,
            rule_id=rule_id,
            rule_title=rule_title,
            severity=severity,
            description=description,
            technique_id=technique_id,
            technique_name=technique_name,
            tags=tags,
            playbook=None,
            tactic=tactic
        )

        # Assign playbook (DB relation)
        from app.dlp import assign_playbook_to_alert
        assign_playbook_to_alert(alert)

        # Store playbook steps for UI rendering
        alert.playbook_steps = playbook_steps

        alerts.append(alert)

    if alerts:
        try:
            db.session.add_all(alerts)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            print(f"[ERROR] Failed to commit alerts: {e}")

    return alerts




def run_dlp_for_log_type(log_type: str, rules_dir: str = "app/rules/wazuh-ruleset/rules/"):
    rules = load_rules(rules_dir)
    logs = fetch_logs_by_type(log_type)
    #print(f"[DEBUG] logs fetched for {log_type}: {type(logs)} with length {len(logs)}")

    if not logs:
        logger.info(f"No logs found for type '{log_type}'")
        return []

    matched_alerts = match_logs_to_rules(logs, rules)
    print("[DEBUG Before alerts]Before generate_alerts()")
    alerts = generate_alerts(matched_alerts)
    print(f"[DEBUG After alerts] matched_alerts count: {len(matched_alerts)}")

    if alerts:
        db.session.add_all(alerts)
        db.session.commit()
        logger.info(f"{len(alerts)} alerts stored for log type '{log_type}'")
    return alerts

def run_dlp():
    from app import create_app
    app = create_app()
    with app.app_context():
        rules_dir = "app/rules/wazuh-ruleset/rules/"
        rules = load_rules(rules_dir)
        log_types = extract_log_types(rules_dir)

        total_new_alerts = 0
        for log_type in log_types:
            logs = fetch_logs_by_type(log_type)
            if not logs:
                continue
            #print(f"[DEBUG] Total logs fetched: {len(logs)}")  # Check logs fetche
            matched_alerts = match_logs_to_rules(logs, rules)
            #print(f"[DEBUG] Total matched alerts: {len(matched_alerts)}")  # Check matches
            alerts = generate_alerts(matched_alerts)

            if alerts:
                db.session.add_all(alerts)
                db.session.commit()
                logger.info(f"{len(alerts)} alerts generated for log type '{log_type}'")
                total_new_alerts += len(alerts)

        print(f"[+] DLP finished. Total new alerts generated: {total_new_alerts}")

def detect_logs_and_generate_alerts():
    """
    Wrapper to be called from external modules like views/routes.
    Triggers log detection and alert generation for all known log types.
    """
   
    rules_dir = "app/rules/wazuh-ruleset/rules/"
    rules = load_rules(rules_dir)
    log_types = extract_log_types(rules_dir)
    #print(f"[Debug 2] Loaded {len(rules)} rules")
    #print(f"[Debug 3]Detected log types: {log_types}")
    total_new_alerts = 0
    for log_type in log_types:
        #print(f"[Debug 4]Processing log type: {log_type}")
        logs = fetch_logs_by_type(log_type)
        #print(f"[Debug 5]Fetched {len(logs) if logs else 0} logs for {log_type}")
        if not logs:
            #print(f"[Debug 6]No logs found for {log_type}, skipping...")
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


def get_playbook(severity, title, description):
    title = title.lower()
    description = description.lower()

    if severity >= 12:
        return [
            "🚨 Critical Threat Response:",
            "1. Isolate the affected system immediately.",
            "2. Notify Security Officer and escalate.",
            "3. Begin forensic analysis.",
            "4. Identify affected assets and check for lateral movement."
        ]
    elif severity >= 10:
        return [
            "🛡️ Privilege Escalation Handling:",
            "1. Disable compromised accounts.",
            "2. Review system logs for suspicious privilege changes.",
            "3. Reset credentials and enable MFA.",
            "4. Run integrity checks on system files."
        ]
    elif severity >= 8:
        return [
            "🦠 Malware Containment Protocol:",
            "1. Quarantine the infected machine.",
            "2. Run antivirus and malware scans.",
            "3. Collect evidence and hash values.",
            "4. Reimage system if needed."
        ]
    elif severity >= 7:
        return [
            "🔍 Suspicious Activity Review:",
            "1. Analyze log source and event trail.",
            "2. Correlate with other alerts.",
            "3. Determine if action is needed or false positive."
        ]
    return None

def find_matching_playbook(keyword, severity):
    return Playbook.query.filter(
        Playbook.keyword.ilike(f'%{keyword}%'),
        Playbook.min_severity <= severity,
        Playbook.max_severity >= severity
    ).first()





if __name__ == "__main__":
    run_dlp()
