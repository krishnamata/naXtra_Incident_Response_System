import os
from flask import Blueprint, request, jsonify
from app.extensions import db
from app.models import LogEntry, Alert
from app.decoders.loader import apply_decoders, load_wazuh_decoders
from app.rules.loader import detect_alerts_from_log, load_wazuh_rules

# Blueprint
agent_bp = Blueprint('agent', __name__)

# Load decoders and rules at startup
decoders = load_wazuh_decoders(os.path.expanduser("~/wazuh-ruleset/decoders"))
rules = load_wazuh_rules(os.path.expanduser("~/wazuh-ruleset/rules"))

@agent_bp.route('/api/logs', methods=['POST'])
def receive_log():
    log_data = request.get_json()

    # Step 1: Apply decoders to normalize/parse the raw log
    parsed_log = apply_decoders(log_data, decoders)
    print("[Debug]Parsed log:",parsed_log)
    print("[DEBUG] Received log:", log_data)
    #print("[DEBUG] Decoded log:", parsed_log)
    print("[DEBUG] Matched alerts:", matched_alerts)
    return jsonify ({"status": "received"}), 200
    # Step 2: Save raw log to DB
    log_entry = LogEntry(
        source=log_data.get("source"),
        log_type=log_data.get("log_type"),
        message=log_data.get("message"),
        raw_log=log_data
    )
    db.session.add(log_entry)
    db.session.commit()

    # Step 3: Apply rules to the decoded/parsed log
    matched_alerts = detect_alerts_from_log(parsed_log, rules)

    for alert in matched_alerts:
        alert_record = Alert(
            rule_id=alert.get("rule_id"),
            level=alert.get("level"),
            description=alert.get("description"),
            log_entry_id=log_entry.id
        )
        db.session.add(alert_record)

    db.session.commit()
    return jsonify({
        "status": "success",
        "alerts_generated": len(matched_alerts)
    }), 201
