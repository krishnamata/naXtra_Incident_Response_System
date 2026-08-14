# app/utils/log_type_registry.py

from threading import Lock
from app.models import LogEntry
from app.extensions import db

_lock = Lock()

# Map specific source agent names to generalized agent categories
SOURCE_AGENT_MAP = {
    "kali": "linux",
    "ubuntu": "linux",
    "centos": "linux",
    "debian": "linux",
    # add more Linux distros as needed
}

# Agent → log type mapping (baseline allowed types)
AGENT_LOG_TYPE_MAP = {
    "linux": ["syslog", "sulog", "auth", "maillog", "journal", "kernlog", "sendmail-reject"],
    "windows": ["security_log", "system_log", "application_log", "setup_log"],
    "network_device": ["network_snmp", "network_cdp", "network_lldp", "network_ntp", "network_syslog"],
}


# Map journal-type logs to rule-compatible log types
JOURNAL_TO_RULE_MAP = {
    "journal": "syslog",  # all journal logs use syslog rules
}

def normalize_log_type(log_type: str, agent_type: str = None) -> str:
    """
    Normalize a log type:
    - Maps agent_name via SOURCE_AGENT_MAP
    - Maps 'journal' to 'syslog' for Linux
    - If agent_type missing, attempt to infer from known Linux log types
    - Unknown types become 'other_<agent_type>' or 'generic'
    """
    log_type = (log_type or "generic").strip().lower()

    # If agent_type not provided, infer Linux logs
    if not agent_type:
        if log_type in ["syslog", "sulog", "auth", "maillog", "journal", "kernlog", "sendmail-reject"]:
            agent_type = "linux"
        elif log_type in ["security_log", "system_log", "application_log", "setup_log"]:
            agent_type = "windows"
        else:
            agent_type = "unknown"

    # Map agent name to generic type
    mapped_agent_type = SOURCE_AGENT_MAP.get(agent_type.lower(), agent_type.lower())
    allowed_types = AGENT_LOG_TYPE_MAP.get(mapped_agent_type, [])

    # Map journal logs to syslog rules
    if log_type in JOURNAL_TO_RULE_MAP and mapped_agent_type == "linux":
        return JOURNAL_TO_RULE_MAP[log_type]

    if log_type in allowed_types:
        return log_type
    else:
        return f"other_{mapped_agent_type}"



def get_existing_log_types() -> list[str]:
    """
    Get distinct log types currently present in the database.
    """
    with _lock:
        results = db.session.query(LogEntry.log_type).distinct().all()
        return [row[0] for row in results if row[0]]
