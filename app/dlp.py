import json, re, hashlib, logging, os
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from flask import current_app
from app.models import LogEntry, Alert, AlertStepWork
from app.kb_indexer import KBIndex
from app.utils.log_type_registry import normalize_log_type
from app.extensions import db
from app.rules.rules_loader import load_rules
from app.rules.rules_engine import RuleEngine
from app.utils.NIST_STEPS import NIST_STEPS
from app.utils.mitre_map import MITRE_KEYWORD_MAP, mitre_map
from app.utils.log_services_map import generate_mapping

# ---------------------
# Configuration & Logger
# ---------------------
RULE_DIR = "app/rules/wazuh-ruleset/rules/"
MITRE_LOCAL_PATH = os.path.join(os.path.dirname(__file__), "data", "enterprise-attack.json")
MITRE_UPDATE_INTERVAL_DAYS = 90
LOGTYPE_TO_RULESETS = generate_mapping()

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# ---------------------
# Global Caches
# ---------------------
SERVICE_RULES_CACHE = {}
kb_index = KBIndex()
LOG_AGENT_RULE_MAP = {}
LINUX_RULE_MAPPING = {"journal": ["authlog", "syslog", "kernlog"]}

# ---------------------
# KB Entries Loading
# ---------------------
try:
    with open('app/kb_entries.json', 'r') as f:
        kb_entries = json.load(f)
    kb_index.build_index(kb_entries)
    logger.info(f"Loaded {len(kb_entries)} KB entries into index.")
except (FileNotFoundError, json.JSONDecodeError) as e:
    logger.error(f"Failed to load KB entries: {e}")
    kb_entries = []

# ---------------------
# MITRE Lookup Stub
# ---------------------
def build_mitre_lookup(force_update=False, skip_prompt=True):
    download_new = not os.path.exists(MITRE_LOCAL_PATH) or \
        (datetime.utcnow() - datetime.fromtimestamp(os.path.getmtime(MITRE_LOCAL_PATH)) > timedelta(days=MITRE_UPDATE_INTERVAL_DAYS))
    if download_new or force_update:
        logger.info("[MITRE] Skipping download, using local copy")
    return True
MITRE_LOOKUP = build_mitre_lookup(skip_prompt=True)


def resolve_mitre_id(rule, log_message=None):
    """
    Return MITRE technique ID from the rule, if present.
    No mapping or fallback is done.
    """
    mitre_id = rule.get("technique_id")
    if mitre_id and not mitre_id.upper().startswith("T"):
        mitre_id = f"T{mitre_id.strip()}"
    return mitre_id







# ---------------------
# Utility: Extract MITRE
# ---------------------
#normalized_mitre_map = {k.lower().strip(): v for k, v in mitre_map.items()}  # precomputed for speed

VALID_MITRE_ID_PATTERN = re.compile(r'^T\d{4}(?:\.\d{3})?$')  # T1059 or T1021.001

def extract_mitre_id(title, mitre_elem, fallback_text=None):
    candidates = []

    if mitre_elem:
        candidates.append(str(mitre_elem).strip().upper())
    if title:
        candidates.append(str(title).upper())
    if fallback_text:
        candidates.append(str(fallback_text).upper())

    for cand in candidates:
        if VALID_MITRE_ID_PATTERN.match(cand):
            return cand, title

    # Fallback to MITRE_KEYWORD_MAP
    text = fallback_text.lower() if fallback_text else ""
    for keyword, mitre in MITRE_KEYWORD_MAP.items():
        if keyword in text:
            mitre_id = mitre if isinstance(mitre, str) else mitre.get("id")
            return mitre_id, title

    return None, title





# ---------------------
# Build Service Rules Cache
# ---------------------
def build_service_rules_cache():
    global SERVICE_RULES_CACHE
    SERVICE_RULES_CACHE = {}

    for fname in os.listdir(RULE_DIR):
        if not fname.endswith("_rules.xml"):
            continue
        filepath = os.path.join(RULE_DIR, fname)
        try:
            tree = ET.parse(filepath)
            root = tree.getroot()
            groups = [root] if root.tag == 'group' else root.findall('.//group')

            for group in groups:
                group_name = group.attrib.get("name", "")
                raw_log_types = [lt.strip().lower() for lt in group_name.split(",") if lt.strip()]
                log_types = [normalize_log_type(lt) for lt in raw_log_types] or ["generic"]

                for rule_elem in group.findall("rule"):
                    rule_id = rule_elem.attrib.get("id")
                    try:
                        level = int(rule_elem.attrib.get("level", 1))
                    except Exception:
                        level = 1
                    if level <= 3:
                        continue
                    title = (rule_elem.findtext("description") or "No description").strip()

                    # --- Detection conditions ---
                    conditions = []
                    for field_elem in rule_elem.findall("field"):
                        field_name = field_elem.attrib.get("name", "message")
                        pattern = (field_elem.text or "").strip()
                        if pattern:
                            try:
                                compiled = re.compile(pattern)
                            except re.error:
                                logger.error(f"Invalid regex in {fname}, rule {rule_id}: {pattern}")
                                continue
                            conditions.append({"field": field_name, "pattern": compiled, "type": "regex"})

                    for match_elem in rule_elem.findall("match"):
                        pattern = (match_elem.text or "").strip()
                        if pattern:
                            match_type = match_elem.attrib.get("type", "regex")
                            if match_type == "regex":
                                try:
                                    compiled = re.compile(pattern)
                                except re.error:
                                    logger.error(f"Invalid regex in {fname}, rule {rule_id}: {pattern}")
                                    continue
                                conditions.append({"field": "message", "pattern": compiled, "type": "regex"})
                            else:
                                conditions.append({"field": "message", "pattern": pattern, "type": match_type})

                    for list_elem in rule_elem.findall("list"):
                        field_name = list_elem.attrib.get("field", "message")
                        check_value = list_elem.attrib.get("check_value", "")
                        if check_value:
                            conditions.append({"field": field_name, "pattern": check_value, "type": "list"})

                    # --- MITRE extraction (explicit only) ---
                    technique_id = None
                    mitre_elem = rule_elem.find("mitre")
                    # 1) <mitre><id>Txxxx</id></mitre>
                    if mitre_elem is not None:
                        mitre_id_text = mitre_elem.findtext("id") or mitre_elem.text or ""
                        mitre_id_text = (mitre_id_text or "").strip()
                        if mitre_id_text:
                            # normalize numeric-only values like "1110" to "T1110"
                            if not mitre_id_text.upper().startswith("T") and re.match(r'^\d{3,4}(?:\.\d{3})?$', mitre_id_text):
                                mitre_id_text = "T" + mitre_id_text
                            mitre_id_text = mitre_id_text.upper()
                            if VALID_MITRE_ID_PATTERN.match(mitre_id_text):
                                technique_id = mitre_id_text

                    # 2) Fallback: check rule description/title for explicit T#### pattern (not keyword mapping)
                    if not technique_id:
                        combined = (title or "") + " " + (rule_elem.findtext("description") or "")
                        found = re.search(r'(T\d{4}(?:\.\d{3})?)', combined, flags=re.IGNORECASE)
                        if found:
                            cand = found.group(1).upper()
                            if VALID_MITRE_ID_PATTERN.match(cand):
                                technique_id = cand

                    # --- Build rule dict ---
                    rule_dict = {
                        "id": rule_id,
                        "title": title,
                        "severity": level,
                        "log_types": log_types,
                        "detection": {"conditions": conditions},
                        "source_file": fname
                    }
                    if technique_id:
                        rule_dict["technique_id"] = technique_id
                        # store technique_name as the rule title (can be overwritten later by enrichment)
                        rule_dict["technique_name"] = title

                    for lt in log_types:
                        SERVICE_RULES_CACHE.setdefault(lt, []).append(rule_dict)

        except Exception as e:
            logger.error(f"Failed to parse {fname}: {e}")

    total_rules = sum(len(v) for v in SERVICE_RULES_CACHE.values())
    logger.info(f"[RULES CACHE] Built SERVICE_RULES_CACHE with {total_rules} rules across {len(SERVICE_RULES_CACHE)} log_types")


build_service_rules_cache()



# ---------------------
# Get Rules for Log
# ---------------------
def get_rules_for_log(log):
    normalized_log_type = normalize_log_type(log.get("log_type", "generic"), log.get("source"))
    candidate_rules = SERVICE_RULES_CACHE.get(normalized_log_type, []) or SERVICE_RULES_CACHE.get("generic", [])

    raw_log = log.get("raw_log", {})
    message = log.get("message", "")
    if isinstance(raw_log, dict):
        message = message or raw_log.get("MESSAGE") or raw_log.get("log") or raw_log.get("event", "")
    elif isinstance(raw_log, str):
        message = message or raw_log
    log["message"] = message or ""

    matched_rules = []

    for rule in candidate_rules:
        try:
            rule_matched = False
            for cond in rule.get("detection", {}).get("conditions", []):
                field_value = log.get(cond.get("field", "message"), "")
                if isinstance(raw_log, dict) and cond.get("field") in raw_log:
                    field_value = raw_log[cond.get("field")]
                elif isinstance(raw_log, str) and cond.get("field") == "message":
                    field_value = raw_log
                if not field_value:
                    continue

                if cond["type"] == "regex" and cond["pattern"].search(field_value):
                    rule_matched = True
                    break
                elif cond["type"] == "contains" and cond["pattern"] in field_value:
                    rule_matched = True
                    break
                elif cond["type"] == "list" and field_value == cond["pattern"]:
                    rule_matched = True
                    break

            if rule_matched:
                matched_rules.append(rule)

        except re.error as e:
            logger.error(f"Invalid regex in rule {rule.get('id')}: {cond['pattern']} ({e})")

    return matched_rules  # return **all matched rules**, not just highest



# ---------------------
# ---------------------
# Generate Alert (One per matched rule)
def generate_alert(log, matched_rules, created_by=0, commit_batch=True):
    if not matched_rules:
        return []

    created_alerts = []

    for rule in matched_rules:
        detected_time = parse_timestamp(log.get("timestamp"))
        agent_name = log.get("source") if isinstance(log, dict) else getattr(log, "source", "unknown")
        log_id = log.get("id")

        # Avoid duplicate alert for the same log & rule
        existing = Alert.query.filter_by(
            rule_id=rule.get("id"),
            agent_name=agent_name,
            detected_time=detected_time
        ).first()
        if existing:
            existing.matched_log_id = existing.matched_log_id or log_id
            continue

        message = log.get("message") or ""
        parsed_raw = log.get("parsed_raw", {})

        # Use technique_id directly from parsed rule (explicit only)
        mitre_id = rule.get("technique_id")  # may be None

        # Create Alert object
        alert = Alert(
            description=message,
            agent_name=agent_name,
            detected_time=detected_time,
            severity=rule.get("severity", 1),
            rule_id=rule.get("id"),
            rule_title=rule.get("title"),
            technique_id=mitre_id,
            matched_log_id=log_id,
            is_malware=rule.get("is_malware", False),
            md5_hash=parsed_raw.get("md5_hash") or hashlib.md5((message or "").encode()).hexdigest(),
            sha256_hash=parsed_raw.get("sha256_hash") or hashlib.sha256((message or "").encode()).hexdigest()
        )

        db.session.add(alert)
        created_alerts.append(alert)

        # Defensive logging: use get to avoid attribute errors when passing dicts
        logger.debug(f"[ALERT] Generated alert for log {log_id}, rule={rule.get('id')}, MITRE={mitre_id}")
        print(f"Alert generated: Log {log_id} → Rule {rule.get('id')} (MITRE {mitre_id})")

    if commit_batch and created_alerts:
        db.session.commit()

    return created_alerts






# ---------------------
# Timestamp parser
# ---------------------
def parse_timestamp(ts):
    if isinstance(ts, str):
        try:
            return datetime.fromisoformat(ts)
        except Exception:
            return datetime.utcnow()
    return ts or datetime.utcnow()

def fetch_logs_by_type(log_type: str, limit=None, after_timestamp: datetime = None, normalize=True):
    """
    Fetch logs from DB by log_type.

    If normalize=True, normalize log_type (used for rules mapping).
    If normalize=False, fetch raw DB log_type (useful for testing existing logs).
    """
    query_type = normalize_log_type(log_type) if normalize else log_type
    print(f"[DEBUG] Fetching logs for log_type: {log_type} (using query_type: {query_type})")
    
    query = LogEntry.query.filter_by(log_type=query_type)
    if after_timestamp:
        query = query.filter(LogEntry.timestamp > after_timestamp)
    
    query = query.order_by(LogEntry.timestamp.asc())
    if limit:
        query = query.limit(limit)
    
    logs = query.all()
    print(f"[DEBUG] Fetched {len(logs)} logs from DB")
    return logs







def seed_nist_steps(alert_id, alert_type="normal", created_by=0):
    steps = []
    for role_steps in NIST_STEPS.values():
        for step in role_steps:
            if alert_type=="normal" and step["nist_phase"] in ["containment", "isolation"]:
                continue
            steps.append(AlertStepWork(
                alert_id=alert_id,
                nist_phase=step["nist_phase"],
                sub_step=step["sub_step"],
                status="pending",
                notes="",
                updated_by=created_by
            ))
    db.session.bulk_save_objects(steps)
    db.session.commit()
    return steps

def enrich_alert_with_kb(alert, kb_index, top_k=3, min_similarity=0.5):
    if not kb_index or not hasattr(kb_index, "query"):
        return
    query_text = f"{alert.rule_title or ''} {alert.description or ''}".strip()
    if not query_text:
        return
    related_entries = kb_index.query(query_text, top_k=top_k, min_similarity=min_similarity)
    enrichment_summary = [{
        'id': e.get('id'),
        'type': e.get('type'),
        'text': e.get('text')[:200],
        'metadata': e.get('metadata', {}),
        'similarity': e.get('similarity', 0)
    } for e in related_entries]
    alert.enrichment_data = enrichment_summary
    logger.debug(f"[KB Enrichment] Alert {alert.id} enriched with {len(enrichment_summary)} KB entries.")





def detect_logs_and_generate_alerts_for_selected_logs(logs, commit_batch=True):
    """
    Detect rules for each log and generate alerts.
    Prints a debug summary of matched rules and MITRE IDs per log.
    """
    created_alerts = []

    for log in logs:
        log_dict = {
            "id": log.id,
            "log_type": normalize_log_type(log.log_type, log.source),
            "source": log.source,
            "message": log.message,
            "raw_log": log.raw_log,
            "timestamp": log.timestamp,
        }

        matched_rules = get_rules_for_log(log_dict)
        if not matched_rules:
            continue

        alerts = generate_alert(log_dict, matched_rules, commit_batch=False)
        if alerts:
            created_alerts.extend(alerts)

            # Debug per rule
            for r in matched_rules:
                resolved_id = resolve_mitre_id(r)
                logger.debug(f"Log {log.id} → Rule {r.get('id')}, MITRE={resolved_id}")

    if commit_batch and created_alerts:
        db.session.commit()

    logger.debug(f"[ALERTS] Generated {len(created_alerts)} alerts for {len(logs)} logs")
    return created_alerts




def extract_log_types(rules):
    log_types = set()
    for rule in rules:
        for lt in rule.get("log_types", []):
            log_types.add(lt)
    return sorted(log_types)

# -------------------------------------------------------------------
# Utilities for running detection over all logs / all log_types
# -------------------------------------------------------------------
def get_all_log_types(normalize=True):
    """
    Return sorted list of distinct log_type values from LogEntry table.
    If normalize=True, apply normalize_log_type to each.
    """
    types = [t[0] for t in db.session.query(LogEntry.log_type).distinct().all()]
    if normalize:
        types = list({ normalize_log_type(t) for t in types if t })
    types = sorted([t for t in types if t])
    return types

def process_all_logs(batch_size=1000, normalize_types=True, commit_batch=True, after_timestamp=None):
    """
    Process all logs in DB grouped by log_type.
    Returns: summary dict {log_type: {processed: N, alerts: M}}
    """
    summary = {}
    log_types = get_all_log_types(normalize=normalize_types)
    logger.info(f"[PROCESS_ALL] Found {len(log_types)} distinct log_types: {log_types}")

    for lt in log_types:
        summary.setdefault(lt, {'processed': 0, 'alerts': 0})
        offset = 0

        while True:
            logs = fetch_logs_by_type(lt, limit=batch_size, after_timestamp=after_timestamp, normalize=normalize_types)
            if not logs:
                break

            alerts = detect_logs_and_generate_alerts_for_selected_logs(logs, commit_batch=commit_batch)
            summary[lt]['processed'] += len(logs)
            summary[lt]['alerts'] += len(alerts)

            if not batch_size or len(logs) < batch_size:
                break

    total_processed = sum(v['processed'] for v in summary.values())
    total_alerts = sum(v['alerts'] for v in summary.values())
    logger.info(f"[PROCESS_ALL] Done. Processed {total_processed} logs, generated {total_alerts} alerts.")
    return summary
