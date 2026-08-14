import json
import os
from threading import Lock

LOG_TYPES_FILE = os.path.join(os.path.dirname(__file__), 'log_types.json')
_lock = Lock()

def _load_known_log_types():
    try:
        with open(LOG_TYPES_FILE, 'r') as f:
            return set(json.load(f))
    except Exception:
        # If file missing or corrupt, return default set
        return {
            "windows",
            "windows_security",
            "windows_system",
            "linux",
            "sshd",
            "clamd",
            "freshclam",
            "suricata",
            "osquery",
            "apache",
            "nginx",
            "roundcube"
        }

def _save_known_log_types(log_types):
    with _lock:
        with open(LOG_TYPES_FILE, 'w') as f:
            json.dump(sorted(list(log_types)), f, indent=2)

# Load known types at module import
KNOWN_LOG_TYPES = _load_known_log_types()

def normalize_log_type(log_type: str, log_data: dict = None) -> str:
    log_type = log_type.strip().lower()

    # Heuristics based on log_data if available
    if log_data:
        agent_name = log_data.get("agent_name", "").lower()
        if "windows" in agent_name or "win" in agent_name:
            return "windows"
        if "clamd" in agent_name or "freshclam" in agent_name:
            return "clamd"

    if log_type not in KNOWN_LOG_TYPES:
        print(f"[WARN] Unknown log_type '{log_type}' received. Adding to KNOWN_LOG_TYPES and saving.")
        KNOWN_LOG_TYPES.add(log_type)  # Add dynamically in-memory
        _save_known_log_types(KNOWN_LOG_TYPES)  # Persist to file
        return log_type

    return log_type
