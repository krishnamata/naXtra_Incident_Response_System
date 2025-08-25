from app.utils.agent_utils import get_active_agents
from flask import Blueprint, request, jsonify
from datetime import datetime, timedelta
from app.utils.agent_heartbeat import AgentHeartbeat
from app.models import LogEntry
from app.extensions import db
import os

api_bp = Blueprint('api', __name__)

#LOG_DIR = '/var/www/modular-soar/agent_logs'
connected_agents = {}

@api_bp.route('/api/agent-logs/upload', methods=['POST'])
def receive_logs():
    data = request.get_json()

    log_line = data.get('log')
    if not log_line:
        return jsonify({"error": "Missing or empty log"}), 400

    log_type = data.get('log_type', 'general').strip().lower()
    os_name = data.get('os', 'Unknown').strip().lower()
    severity = data.get('severity')  # Optional
    rule_id = data.get('rule_id')    # Optional

    timestamp = datetime.utcnow()

 

    # Insert into LogEntry table
    db.session.add(LogEntry(
        message=log_line,
        log_type=log_type,
        source=os_name,
        timestamp=timestamp
    ))

    # Update heartbeat
    agent_name = data.get('agent_name', '').strip().lower()
    connected_agents[agent_name] = timestamp
    existing = AgentHeartbeat.query.filter_by(agent_name=agent_name).first()
    if existing:
        existing.last_seen = timestamp
    else:
        db.session.add(AgentHeartbeat(agent_name=agent_name, last_seen=timestamp))

    db.session.commit()
    return jsonify({"status": "received"}), 200


@api_bp.route('/api/agent-status', methods=['GET'])
def agent_status():
    return jsonify(get_active_agents()), 200
