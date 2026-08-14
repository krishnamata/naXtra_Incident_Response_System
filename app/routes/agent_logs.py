from datetime import datetime
import hashlib
from flask import request, jsonify, Blueprint, Response, stream_with_context, current_app
from app.models import LogEntry
from app.extensions import db
from app.utils.log_type_registry import SOURCE_AGENT_MAP, normalize_log_type
from typing import Dict, Any
import threading
import json
import time
import queue
import logging

# Initialize Blueprint
agent_bp = Blueprint('agent', __name__)

# Agent Log Types Mapping
AGENT_LOG_TYPES = {
    "linux": ["authlog", "sulog", "syslog", "maillog", "kernlog"],
    "windows": ["security", "system", "application", "setup"],
    "network": ["snmp", "cdp", "lldp", "ntp", "syslog"]
}

# Agent Progress
agent_progress = {}
progress_lock = threading.Lock()
log_event_queue = queue.Queue()

# Logger Setup
logger = logging.getLogger(__name__)
ALLOWED_GENERIC_DECODERS = ["cron-service", "systemd", "rsyslog"]


def get_log_types_for_agent(agent_type):
    return AGENT_LOG_TYPES.get(agent_type.lower(), [])


# =============================
# --- Stream SSE Progress ---
# =============================
@agent_bp.route('/logs/progress')
def stream_progress():
    def event_stream():
        while True:
            try:
                with progress_lock:
                    progress_snapshot = {}
                    for agent, data in agent_progress.items():
                        progress_snapshot[agent] = {
                            "received": data.get("received", 0),
                            "total": data.get("total_logs", 0),
                            "start_time": data.get("start_time", datetime.utcnow()).isoformat()
                        }
                yield f"data: {json.dumps(progress_snapshot)}\n\n"
                time.sleep(1)
            except Exception as e:
                logger.error(f"Error in SSE loop: {e}")
                continue
    return Response(stream_with_context(event_stream()), mimetype='text/event-stream')


# =============================
# --- Receive Logs Endpoint ---
# =============================
@agent_bp.route('/logs/upload', methods=['POST'])
def receive_log():
    try:
        log_data = request.get_json(silent=True) or {}
        logger.debug(f"Received log payload: {log_data}")

        # Decode and validate
        parsed_log = _apply_and_validate_decoders(log_data)

        # Determine agent and log type
        agent_name, log_type = _get_agent_and_log_type(parsed_log)

        # Initialize progress for summary
        if log_type == "summary":
            _initialize_progress(parsed_log, agent_name)

        # Persist log
        log_entry = _persist_log(parsed_log, agent_type=parsed_log.get("agent_type"))

        # Update progress for normal logs
        if log_type != "summary":
            _update_progress(agent_name)

        # Push to SSE
        _push_to_sse_queue(log_entry)

        return jsonify({"status": "success", "log_type": log_type}), 201

    except Exception as e:
        logger.error("Error in receive_log: %s", e, exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


# =============================
# --- Decoder / Validator ---
# =============================
def _apply_and_validate_decoders(log_data: Dict[str, Any]) -> Dict[str, Any]:
    decoded: Dict[str, Any] = {}

    raw_message = log_data.get("message") or log_data.get("log") or ""
    decoded["message"] = raw_message if raw_message else "Empty log from unknown/unknown"
    decoded["decoder"] = "unknown_generic"
    decoded["log_type"] = log_data.get("log_type") or "other_unknown"

    decoded["agent_name"] = log_data.get("agent_name") or None
    decoded["agent_type"] = log_data.get("agent_type") or None
    decoded["source"] = log_data.get("source") or "unknown"

    agent_type = (log_data.get("agent_type") or "").lower()

    # --- Windows Agent Handling ---
    if agent_type == "windows" and isinstance(raw_message, str):
        try:
            # Attempt JSON parsing
            event_obj = json.loads(raw_message)
            if isinstance(event_obj, dict):
                decoded["decoder"] = "windows_eventlog"
                decoded["event_id"] = event_obj.get("event_id")
                decoded["source_name"] = event_obj.get("source_name")
                decoded["event_level"] = event_obj.get("event_level")
                decoded["message"] = event_obj.get("message") or decoded["message"]
                decoded["source"] = decoded.get("source_name") or decoded["source"]

            elif isinstance(event_obj, list) and event_obj:
                first = event_obj[0]
                decoded["decoder"] = "windows_eventlog"
                decoded["event_count"] = len(event_obj)
                decoded["event_id"] = first.get("event_id")
                decoded["source_name"] = first.get("source_name")
                decoded["event_level"] = first.get("event_level")
                decoded["message"] = first.get("message") or decoded["message"]
                decoded["source"] = decoded.get("source_name") or decoded["source"]

        except (json.JSONDecodeError, TypeError):
            # Handle tuple-like string: ('user','KRISHNARAMPURI',...)
            s = raw_message.strip()
            if s.startswith("(") and s.endswith(")"):
                decoded["message"] = ", ".join([x.strip(" '\"") for x in s[1:-1].split(",")])
            else:
                decoded["message"] = f"Invalid Windows payload from {decoded['source']}"
            decoded["decoder"] = "windows_eventlog_broken"

    # --- Linux Agent ---
    elif agent_type == "linux":
        decoded["platform"] = "linux"
        decoded["decoder"] = "linux_generic"

    # --- Fallbacks ---
    decoded["message"] = decoded.get("message") or f"Empty log from {decoded.get('source')}/{decoded.get('agent_type') or 'unknown'}"
    decoded["decoder"] = decoded.get("decoder") or "unknown_generic"
    decoded["log_type"] = decoded.get("log_type") or "other_unknown"
    decoded["agent_type"] = decoded.get("agent_type") or decoded.get("source")

    return decoded


# =============================
# --- Helper: Determine Agent / Log Type ---
# =============================
def _get_agent_and_log_type(parsed_log):
    # Ensure Linux agent always has valid agent_name and agent_type
    agent_name = parsed_log.get("agent_name") or parsed_log.get("source") or "linux-agent"
    agent_type = parsed_log.get("agent_type") or "linux"

    raw_log_type = parsed_log.get("log_type", "generic").lower()
    log_type = normalize_log_type(raw_log_type, agent_type)

    return agent_name, log_type



# =============================
# --- Initialize Progress ---
# =============================
def _initialize_progress(parsed_log, agent_name):
    total_logs = int(parsed_log.get("total_logs") or 0)
    with progress_lock:
        agent_progress[agent_name] = {"total_logs": total_logs, "received": 0, "start_time": datetime.utcnow()}


# =============================
# --- Persist Log to DB ---
# =============================
def _persist_log(parsed_log: dict, agent_type: str = None):
    decoder_name = parsed_log.get("decoder")
    raw_log = parsed_log.copy()  # preserve parsed log

    source = (
        parsed_log.get("agent_name")
        or parsed_log.get("source")
        or parsed_log.get("agent_type")
        or "unknown"
    )

    log_type = parsed_log.get("log_type") or "other_unknown"

    # Display message
    message = parsed_log.get("message") or json.dumps(parsed_log, ensure_ascii=False)

    # Safety: handle Windows JSON or tuple-style strings
    if agent_type == "windows" and isinstance(message, str):
        try:
            msg_json = json.loads(message)
            message = msg_json.get("message") or message
        except (json.JSONDecodeError, TypeError):
            s = message.strip()
            if s.startswith("(") and s.endswith(")"):
                message = ", ".join([x.strip(" '\"") for x in s[1:-1].split(",")])
            # else keep as-is

    message = str(message).strip() or f"Empty log from {source}/{agent_type or 'unknown'}"

    md5_hash_val = parsed_log.get("md5_hash") or hashlib.md5(message.encode()).hexdigest()
    ip_address = parsed_log.get("ip_address") or "127.0.0.1"

    log_entry = LogEntry(
        source=source,
        log_type=log_type,
        message=message,
        raw_log=raw_log,
        md5_hash=md5_hash_val,
        ip_address=ip_address,
        decoder_name=decoder_name,
        rule_group=None
    )

    db.session.add(log_entry)
    db.session.commit()
    return log_entry


# =============================
# --- Heartbeat / Progress ---
# =============================
def _update_heartbeat(agent_name):
    pass  # implement if needed

def _update_progress(agent_name):
    with progress_lock:
        if agent_name in agent_progress:
            agent_progress[agent_name]["received"] += 1


# =============================
# --- Push to SSE Queue ---
# =============================
def _push_to_sse_queue(log_entry):
    try:
        log_event_queue.put_nowait(log_entry.to_dict())
    except Exception as e:
        logger.error(f"Failed to push log to SSE queue: {e}")




logger = logging.getLogger(__name__)

# The correct server-side API key (must match config.ini)
#api_key = "naxtraSOAR-key"


def verify_api_key():
    """Check Authorization header for correct API key."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return False
    token = auth_header.split(" ", 1)[1].strip()
    return token == current_app.config.get("AGENT_API_KEY")


@agent_bp.route('/fim/logs/fim', methods=['POST'])
def receive_fim_log():
    # --- Verify API Key ---
    if not verify_api_key():
        return jsonify({"error": "Unauthorized: invalid API key"}), 403

    try:
        log_data = request.get_json(silent=True) or {}

        # Extract message or default
        raw_message = log_data.get("log") or "Empty FIM log"
        message = str(raw_message).strip()

        md5_hash_val = hashlib.md5(message.encode()).hexdigest()
        ip_address = log_data.get("ip_address") or "127.0.0.1"

        # Save to database
        fim_entry = LogEntry(
            source=log_data.get("agent_name") or log_data.get("agent_type") or "unknown",
            log_type=log_data.get("log_type") or "fim",
            message=message,
            raw_log=log_data,
            md5_hash=md5_hash_val,
            ip_address=ip_address,
            decoder_name="fim_monitor",
            rule_group=None
        )

        db.session.add(fim_entry)
        db.session.commit()

        return jsonify({"status": "success", "log_type": fim_entry.log_type}), 201

    except Exception as e:
        logger.error(f"Error saving FIM log: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500
