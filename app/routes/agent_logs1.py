from datetime import datetime
import hashlib
from flask import request, jsonify, Blueprint, Response, stream_with_context
from app.models import LogEntry
from app.extensions import db
from app.utils.log_type_registry import SOURCE_AGENT_MAP, normalize_log_type
from app.utils.decoder_log_rule import get_decoder_and_rules
from app.decoders.loader import apply_decoders, DECODERS_CACHE
from app.utils.log_services_map import SERVICE_KEYWORDS, GROUP_TO_LOGTYPE
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
ALLOWED_GENERIC_DECODERS = ["cron-service", "systemd", "rsyslog"]  # add any other decoders
def get_log_types_for_agent(agent_type):
    return AGENT_LOG_TYPES.get(agent_type.lower(), [])

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

@agent_bp.route('/logs/upload', methods=['POST'])
def receive_log():
    try:
        log_data = request.get_json(silent=True) or {}
        logger.debug(f"Received log payload: {log_data}")
        # Apply Decoders and Validate Log
        parsed_log = _apply_and_validate_decoders(log_data)

        # Determine Agent and Log Types
        agent_name, log_type = _get_agent_and_log_type(parsed_log)

        # Extract Message and Compute Hashes
        #raw_message, md5_hash_val, ip_address = _extract_message_and_compute_hashes(parsed_log, log_data)

        # Initialize Progress for Summary Logs
        if log_type == "summary":
            _initialize_progress(parsed_log, agent_name)

        # Persist Log and Update Heartbeat
        # Persist Log and Update Heartbeat
        log_entry = _persist_log(parsed_log, agent_type=parsed_log.get("agent_type"))


        # Update Progress for Non-Summary Logs
        if log_type != "summary":
            _update_progress(agent_name)

        # Push to SSE Queue
        _push_to_sse_queue(log_entry)
        
        return jsonify({"status": "success", "log_type": log_type}), 201
    except Exception as e:
        logger.error("Error in receive_log: %s", e, exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


def _apply_and_validate_decoders(log_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Apply decoders safely and guarantee schema invariants.
    For Windows single-event logs, parse JSON and extract human-readable message.
    """
    decoded: Dict[str, Any] = {}

    # Step 1: Extract raw message safely
    raw_message = log_data.get("message") or log_data.get("log") or ""
    decoded["message"] = raw_message if raw_message else "Empty log from unknown/unknown"
    decoded["decoder"] = "unknown_generic"
    decoded["log_type"] = log_data.get("log_type") or "other_unknown"

    # Step 2: Use provided fields or defaults
    decoded["agent_name"] = log_data.get("agent_name") or None
    decoded["agent_type"] = log_data.get("agent_type") or None
    decoded["source"] = log_data.get("source") or "unknown"

    # Step 3: Detect Windows agent payload
    agent_type = (log_data.get("agent_type") or "").lower()
    if agent_type == "windows" and isinstance(raw_message, str):
        try:
            event_obj = json.loads(raw_message)
            if isinstance(event_obj, dict):
                # Single event: extract human-readable message
                decoded["decoder"] = "windows_eventlog"
                decoded["event_id"] = event_obj.get("event_id")
                decoded["source_name"] = event_obj.get("source_name")
                decoded["event_level"] = event_obj.get("event_level")
                decoded["message"] = event_obj.get("message") or decoded["message"]
                decoded["source"] = decoded.get("source_name") or decoded["source"]

            elif isinstance(event_obj, list) and event_obj:
                # Fallback for batched events
                first = event_obj[0]
                decoded["decoder"] = "windows_eventlog"
                decoded["event_count"] = len(event_obj)
                decoded["event_id"] = first.get("event_id")
                decoded["source_name"] = first.get("source_name")
                decoded["event_level"] = first.get("event_level")
                decoded["message"] = first.get("message") or decoded["message"]
                decoded["source"] = decoded.get("source_name") or decoded["source"]

        except json.JSONDecodeError:
            decoded["message"] = f"Invalid JSON payload from {decoded['source']}/windows"
            decoded["decoder"] = "windows_eventlog_broken"

    # Step 4: Linux placeholder
    elif agent_type == "linux":
        decoded["platform"] = "linux"
        decoded["decoder"] = "linux_generic"

    # Step 5: Absolute invariants
    if not decoded.get("message"):
        decoded["message"] = f"Empty log from {decoded.get('source')}/{decoded.get('agent_type') or 'unknown'}"
    if not decoded.get("decoder"):
        decoded["decoder"] = "unknown_generic"
    if not decoded.get("log_type"):
        decoded["log_type"] = "other_unknown"
    if not decoded.get("agent_type"):
        decoded["agent_type"] = decoded["source"]

    return decoded





def _get_agent_and_log_type(parsed_log):
    agent_name = parsed_log.get("agent_name") or "unknown"
    agent_type = parsed_log.get("agent_type") or SOURCE_AGENT_MAP.get(agent_name.lower(), "unknown")

    raw_log_type = parsed_log.get("log_type", "generic").lower()
    log_type = normalize_log_type(raw_log_type, agent_type)

    return agent_name, log_type



def _initialize_progress(parsed_log, agent_name):
    total_logs = int(parsed_log.get("total_logs") or 0)
    with progress_lock:
        agent_progress[agent_name] = {"total_logs": total_logs, "received": 0, "start_time": datetime.utcnow()}



def _persist_log(parsed_log: dict, agent_type: str = None):
    """
    Persist an already-decoded log into the database.
    For Windows single-event logs, extract 'message' field from JSON string
    for dashboard display, while keeping full raw log in raw_log.
    """
    decoder_name = parsed_log.get("decoder")
    raw_log = parsed_log

    # Use source from parsed_log or fallback
    source = parsed_log.get("source") or "unknown"
    log_type = parsed_log.get("log_type") or "other_unknown"

    # Step 1: Extract the display message
    message = parsed_log.get("message") or json.dumps(parsed_log, ensure_ascii=False)

    # If message is a JSON string (Windows agent single-event)
    if parsed_log.get("agent_type") == "windows" and isinstance(message, str):
        try:
            msg_json = json.loads(message)
            # If 'message' field exists, use it for display
            message = msg_json.get("message") or message
        except (json.JSONDecodeError, TypeError):
            # Keep original string if parsing fails
            if message.startswith("(") and message.endswith(")"):
            # Remove parentheses and split by comma
                message = ", ".join([x.strip(" '\"") for x in message[1:-1].split(",")])
            

    message = str(message).strip() or f"Empty log from {source}/{agent_type or 'unknown'}"

    # Step 2: Compute MD5 hash and IP metadata
    md5_hash_val = parsed_log.get("md5_hash") or hashlib.md5(message.encode()).hexdigest()
    ip_address = parsed_log.get("ip_address") or "127.0.0.1"

    # Step 3: Save to database
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








def _update_heartbeat(agent_name):
    # Heartbeat update logic
    pass

def _update_progress(agent_name):
    with progress_lock:
        # Update progress logic
        pass

def _push_to_sse_queue(log_entry):
    try:
        log_event_queue.put_nowait(log_entry.to_dict())
    except Exception as e:
        logger.error(f"Failed to push log to SSE queue: {e}")
