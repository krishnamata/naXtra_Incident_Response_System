import json
import hashlib
from datetime import datetime
from flask import current_app
from app.models import LogEntry, Alert, AlertStepWork
from app.kb_indexer import KBIndex
from app.kb_extractor import extract_rule_texts, extract_decoder_texts
from app.utils.log_type_registry import normalize_log_type
from app.rules.rules_cache import RULES_CACHE
from app.extensions import db
from app.rules.rules_loader import load_rules
import logging
import os
import xml.etree.ElementTree as ET
RULE_DIR = "app/rules/wazuh-ruleset/rules/"

# Load rules once globally
rules = load_rules(RULE_DIR)

_title_to_id_cache = None
print("[DEBUG] Imported dlp.py")

NIST_STEPS = {
    "analyst": [
        {"nist_phase": "Detection & Analysis", "sub_step": "Validate alert (positive/negative)"},
        {"nist_phase": "Detection & Analysis", "sub_step": "Gather initial evidence"},
    ],
    "senior_analyst": [
        {"nist_phase": "Containment", "sub_step": "Isolate host"},
        {"nist_phase": "Containment", "sub_step": "Block IP/domain"},
        {"nist_phase": "Containment", "sub_step": "Disable compromised account"},
        {"nist_phase": "Eradication", "sub_step": "Remove malware"},
        {"nist_phase": "Eradication", "sub_step": "Patch vulnerable system"},
        {"nist_phase": "Recovery", "sub_step": "Restore services"},
        {"nist_phase": "Recovery", "sub_step": "Monitor system post-recovery"},
        {"nist_phase": "Post-Incident", "sub_step": "Root cause analysis"},
        {"nist_phase": "Post-Incident", "sub_step": "Document lessons learned"},
    ]
}

def get_logger():
    try:
        return current_app.logger
    except RuntimeError:
        return logging.getLogger(__name__)

logger = get_logger()

# Create a global RuleEngine instance once
from app.rules.rules_engine import RuleEngine
ENGINE = RuleEngine(rules)
# Initialize KB index (assuming you have your knowledge base files set up)
kb_index = KBIndex()
try:
    with open('app/kb_entries.json', 'r') as f:
        kb_entries = json.load(f)
    kb_index.build_index(kb_entries)
    logger.info(f"Loaded {len(kb_entries)} KB entries into index.")
except (FileNotFoundError, json.JSONDecodeError) as e:
    logger.error(f"Failed to load KB entries: {e}")
    kb_entries = []


def extract_log_types(rules):
    log_types = set()
    for rule in rules:
        for log_type in rule.get("log_types", []):
            log_types.add(log_type)
    return sorted(log_types)

def fetch_logs_by_type(log_type: str, limit=None, after_timestamp: datetime = None):
    try:
        normalized_type = normalize_log_type(log_type)
        logger.debug(f"[DEBUG] Normalized log_type: {normalized_type}")

        query = LogEntry.query.filter_by(log_type=normalized_type)
        if after_timestamp:
            query = query.filter(LogEntry.timestamp > after_timestamp)

        query = query.order_by(LogEntry.timestamp.asc())
        if limit:
            query = query.limit(limit)

        logs = query.all()
        logger.debug(f"[DEBUG] Retrieved {len(logs)} logs for type '{normalized_type}' (limit={limit})")

        processed_logs = []
        for log in logs:
            raw_log_json = log.raw_log
            if isinstance(raw_log_json, dict):
                parsed_raw = raw_log_json
            else:
                try:
                   parsed_raw = json.loads(raw_log_json) if raw_log_json else {}
                except Exception as e:
                    logger.error(f"[ERROR] JSON parsing error in raw_log for Log ID {log.id}: {e}")
                    parsed_raw = {}


            log_dict = log.to_dict()
            log_dict['parsed_raw'] = parsed_raw

            if not log_dict.get('agent_name'):
                log_dict['agent_name'] = parsed_raw.get('agent_name', 'Unknown')

            original_log_type = parsed_raw.get('log_type', normalized_type)
            log_dict['log_type'] = normalize_log_type(original_log_type, parsed_raw)

            if not log_dict.get('message'):
                log_dict['message'] = parsed_raw.get('event') or parsed_raw.get('log') or ''

            processed_logs.append(log_dict)

        return processed_logs

    except Exception as e:
        logger.error(f"[ERROR] Exception while fetching logs for type '{log_type}': {e}")
        return []

def generate_alert(log, rule):
    logger.debug("[DEBUG generate_alert] generate_alert() called")
    rule_id = rule.get("id") or rule.get("rule_id") or "Unknown"
    
    detected_time = log.get("timestamp")
    if isinstance(detected_time, str):
        try:
            detected_time = datetime.fromisoformat(detected_time)
        except Exception:
            detected_time = datetime.utcnow()

    existing = Alert.query.filter_by(
        rule_id=rule_id,
        agent_name=log.get("agent_name"),
        detected_time=detected_time
    ).first()

    if existing:
        if existing.matched_log_id is None:
            existing.matched_log_id = log.get("id")
            try:
                db.session.commit()
                logger.debug(f"[PATCHED] Added matched_log_id to existing alert ID {existing.id}")
            except Exception as e:
                logger.error(f"[ERROR] DB commit failed when patching alert: {e}")
        return None

    alert = Alert(
        description=log.get("message"),
        agent_name=log.get("agent_name"),
        detected_time=detected_time,
        severity=rule.get("severity", 1),
        rule_id=rule_id,
        rule_title=rule.get("title"),
        technique_id=rule.get("technique_id"),
        technique_name=rule.get("technique_name"),
        matched_log_id=log.get("id"),
        is_malware=rule.get("is_malware", False) 
    )
    try:
        db.session.add(alert)
        db.session.commit()
        logger.info(f"[ALERT] Created alert for rule {rule_id} on log from {log.get('agent_name')}")
    except Exception as e:
        logger.error(f"[ERROR] DB commit failed when creating alert: {e}")
        db.session.rollback()
        return None

    return alert

def load_title_to_id_map():
    global _title_to_id_cache
    if _title_to_id_cache is None:
        _title_to_id_cache = {}
        for file in os.listdir(RULE_DIR):
            if file.endswith(".xml"):
                path = os.path.join(RULE_DIR, file)
                try:
                    tree = ET.parse(path)
                    root = tree.getroot()
                    for rule in root.findall("rule"):
                        rule_id = rule.attrib.get("id")
                        description = rule.findtext("description")
                        if rule_id and description:
                            _title_to_id_cache[description.strip()] = int(rule_id)
                except Exception as e:
                    print(f"Error parsing {file}: {e}")
    return _title_to_id_cache

def match_logs_to_rules(logs, rules):
    title_to_id = load_title_to_id_map()  # load mapping once

    matched_alerts = []
    for log in logs:
        if isinstance(log, str):
            log = {"message": log}
        matches = ENGINE.match_log(log)  # returns list of matched rules metadata
        for match in matches:
            # Patch rule id if missing
            if not match.get("id") and match.get("title"):
                rule_id = title_to_id.get(match["title"].strip())
                if rule_id:
                    match["id"] = rule_id
                else:
                    print(f"[WARN] No rule_id found for rule title: {match.get('title')}")
            alert = generate_alert(log, match)
            if alert:
                matched_alerts.append(alert)
    return matched_alerts

def seed_nist_steps(alert_id, created_by="system"):
    """
    Populate AlertStepWork entries for a new alert
    according to NIST guideline phases & sub-steps.
    """

    steps_to_insert = []

    # Analyst steps
    for step in NIST_STEPS["analyst"]:
        steps_to_insert.append(
            AlertStepWork(
                alert_id=alert_id,
                nist_phase=step["nist_phase"],
                sub_step=step["sub_step"],
                status="pending",
                notes="",
                updated_by=created_by
            )
        )

    # Senior Analyst steps
    for step in NIST_STEPS["senior_analyst"]:
        steps_to_insert.append(
            AlertStepWork(
                alert_id=alert_id,
                nist_phase=step["nist_phase"],
                sub_step=step["sub_step"],
                status="pending",
                notes="",
                updated_by=created_by
            )
        )

    db.session.bulk_save_objects(steps_to_insert)
    db.session.commit()



def enrich_alert_with_kb(alert, kb_index):
    query_text = f"{alert.rule_title} {alert.description}"
    related_entries = kb_index.query(query_text, top_k=3)
    
    # Create enrichment summary string or JSON
    enrichment_summary = []
    for entry in related_entries:
        enrichment_summary.append({
            'type': entry['type'],
            'id': entry['id'],
            'text': entry['text'][:200],  # truncate for brevity
            'metadata': entry['metadata']
        })
    alert.enrichment_data = enrichment_summary

    # Optionally log or debug
    print(f"[KB Enrichment] Alert {alert.id} enriched with {len(enrichment_summary)} KB entries.")

def get_ai_suggestions():
    """
    Placeholder for AI analysis function.
    Implement your AI logic here, e.g., querying your LLM or AI assistant
    about program strengths, weaknesses, and recommended updates.
    """
    # Example fixed response, replace with real AI calls
    suggestions = {
        "strengths": [
            "Robust rule matching engine.",
            "Comprehensive rule coverage."
        ],
        "weaknesses": [
            "Delayed enrichment on large data volumes.",
            "Limited dynamic decoder generation."
        ],
        "updates": [
            "Add AI-assisted rule tuning.",
            "Integrate real-time decoder suggestions."
        ]
    }
    return suggestions


def add_ai_suggestions_to_alert(alert, suggestions):
    alert.ai_suggestions = suggestions
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to save AI suggestions for alert ID {alert.id}: {e}")


def detect_logs_and_generate_alerts():
    logger.info("=== Starting Alert Detection ===")
    #rules_dir = "app/rules/wazuh-ruleset/rules/"
    #rules = load_rules(rules_dir)
    log_types = sorted(extract_log_types(rules))
    logger.info(f"Loaded {len(rules)} rules for detection.")
    logger.info(f"Discovered log types: {log_types}")

    total_alerts = 0
    for log_type in log_types:
        logger.info(f"--- Processing log type: {log_type} ---")
        logs = fetch_logs_by_type(log_type, limit=None)
        logger.info(f"Fetched {len(logs)} logs for '{log_type}'")

        for log in logs:
            log['log_type'] = normalize_log_type(log.get('log_type', 'generic'), log)
            matches = ENGINE.match_log(log)
            logger.debug(f"[DEBUG] Checking log ID {log.get('id')} with message: {log.get('message')}")

            if not matches:
                logger.debug(f"No matching rules for Log ID {log.get('id')} - Message: {log.get('message')}")
                continue
            logger.debug(f"[MATCHED] Log ID {log.get('id')} matched {len(matches)} rule(s): {[m.get('rule_id') or m.get('id') or 'N/A' for m in matches]}")
            for match in matches:
                detected_time = log.get("timestamp")
                if isinstance(detected_time, str):
                    try:
                        detected_time = datetime.fromisoformat(detected_time)
                    except Exception:
                        detected_time = datetime.utcnow()

                exists = Alert.query.filter_by(
                    rule_id=match["rule_id"],
                    agent_name=log.get("agent_name"),
                    detected_time=detected_time
                ).first()

                if exists:
                    logger.debug(f"Alert already exists for rule {match['rule_id']}, skipping.")
                    continue

                # Try to get real file hashes from parsed raw log data if available
                parsed_raw = log.get("parsed_raw", {})
                message = log.get("message", "")
                

                md5_hash = parsed_raw.get("md5_hash") or parsed_raw.get("md5") or None
                sha256_hash = parsed_raw.get("sha256_hash") or parsed_raw.get("sha256") or None

                 # If no real hashes, fallback to hashing message text (optional)
                if not md5_hash and message:
                    md5_hash = hashlib.md5(message.encode()).hexdigest()
                if not sha256_hash and message:
                    sha256_hash = hashlib.sha256(message.encode()).hexdigest()

                rule_id = match.get("rule_id") or match.get("id")
                if not rule_id and match.get("title"):
                    rule_id = load_title_to_id_map().get(match["title"].strip())
                match["rule_id"] = rule_id
                default_playbook = Playbook.query.filter_by(name="Default Playbook").first()       

                alert = Alert(
                    log_id=log.get("id"),
                    is_new=True,
                    matched_log_id=log.get("id"),
                    rule_id=match["rule_id"],
                    rule_title=match["title"],
                    description=match["description"],
                    severity=match["severity"],
                    tactic=None,
                    technique_id=match["technique_id"],
                    technique_name=None,
                    tags=None,
                    agent_name=log.get("agent_name"),
                    detected_time=detected_time,
                    md5_hash=md5_hash,
                    sha256_hash=sha256_hash,
                    ai_suggestions=suggestions,
                    ioc_type=None,
                    ioc_value=None,
                    enrichment_data=None,
                    enrichment_status=None,
                    enrichment_source=None,
                    enrichment_timestamp=None,
                    playbook=default_playbook,
                )

                try:
                    db.session.add(alert)
                    db.session.commit()
                    total_alerts += 1
                    logger.info(f"[✔] Alert created for Rule {match['rule_id']} with Log ID {log.get('id')}")
                    # Enrich alert with KB index
                    seed_nist_steps(alert.id, created_by="system")

                    enrich_alert_with_kb(alert, kb_index)

                    # Add AI suggestions - you may want to store these in enrichment_data or separate field
                    suggestions = get_ai_suggestions()
                    alert.ai_suggestions = suggestions  # Assuming your Alert model supports this or store in enrichment_data
                    db.session.commit()
                    logger.info(f"[AI] Suggestions added for Alert ID {alert.id}")

                except Exception as e:
                    logger.error(f"[ERROR] DB commit failed when creating alert: {e}")
                    db.session.rollback()

    logger.info(f"=== Detection Complete: {total_alerts} new alerts ===")
