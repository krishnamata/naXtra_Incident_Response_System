from datetime import datetime
from app.utils.agent_heartbeat import AgentHeartbeat
import hashlib
from flask import request, jsonify, Blueprint
from app.models import LogEntry
from app.extensions import db
from app.dlp import detect_logs_and_generate_alerts
from app.rules.rules_loader import load_rules
from app.decoders.loader import apply_decoders, load_wazuh_decoders
from app.utils.log_type_registry import normalize_log_type
import os
import logging

agent_bp = Blueprint('agent', __name__)
rules = load_rules(os.path.expanduser("~/wazuh-ruleset/rules"))
decoders = load_wazuh_decoders(os.path.expanduser("~/wazuh-ruleset/decoders"))
logger = logging.getLogger(__name__)
print(f"[DEBUG] Loaded {len(decoders)} decoders")
print("start of receive_log from agent_logs.py")

@agent_bp.route('/logs/upload', methods=['POST'])
def receive_log():
    try:
        log_data = request.get_json()

        # Apply decoder logic
        parsed_log = apply_decoders(log_data, decoders)

        # Normalize log_type
        log_type = normalize_log_type(parsed_log.get("log_type", "generic"), parsed_log)

        # Compute md5 hash (from message or event or fallback)
        raw_message = parsed_log.get("message") or parsed_log.get("event") or ""
        if not raw_message and isinstance(parsed_log.get("raw_log"), dict):
            raw_message = parsed_log["raw_log"].get("event", "")

        md5_hash = parsed_log.get("md5_hash") or hashlib.md5(raw_message.encode()).hexdigest()

        # IP extraction: prefer explicit, fallback to remote address
        ip_address = parsed_log.get("ip_address") or request.remote_addr

        log_entry = LogEntry(
            source=parsed_log.get("source") or parsed_log.get("agent_name"),
            log_type=log_type,
            message=raw_message,
            raw_log=parsed_log,
            md5_hash=md5_hash,
            ip_address=ip_address
        )

        db.session.add(log_entry)

        # Update heartbeat
        agent_name = (log_data.get('agent_name') or parsed_log.get('agent_name') or parsed_log.get('source') or 'unknown').strip().lower()
        timestamp = datetime.utcnow()
        existing = AgentHeartbeat.query.filter_by(agent_name=agent_name).first()
        if existing:
            existing.last_seen = timestamp
        else:
            db.session.add(AgentHeartbeat(agent_name=agent_name, last_seen=timestamp))

        db.session.commit()

        detect_logs_and_generate_alerts()

        return jsonify({"status": "success"}), 201

    except Exception as e:
        logger.error(f"Error in receive_log: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500
