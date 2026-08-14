from flask import Blueprint, request, jsonify, render_template, make_response, current_app
from app.models import FimEvent, FimBaseline, LogEntry
from app.extensions import db
from collections import defaultdict
from datetime import datetime

# --- Blueprint ---
fim_bp = Blueprint("fim", __name__)

# --- Dashboard ---
@fim_bp.route('/')
def dashboard():
    agents = [row[0] for row in LogEntry.query.with_entities(LogEntry.source).distinct()]
    total_agents = len(agents)

    baseline_count = FimBaseline.query.count()
    event_count = FimEvent.query.count()

    agent_events = defaultdict(list)
    agent_unresolved_count = defaultdict(int)
    
    all_events = FimEvent.query.order_by(FimEvent.detected_at.desc()).all()
    for event in all_events:
        agent_name = event.file_path.split("/")[0] if "/" in event.file_path else "unknown"
        event_dict = event.to_dict()
        event_dict["detected_at"] = event.detected_at.strftime("%Y-%m-%d %H:%M:%S")
        agent_events[agent_name].append(event_dict)
        if not event.resolved:
            agent_unresolved_count[agent_name] += 1

    return make_response(render_template(
        'fim_dashboard.html',
        agents=agents,
        total_agents=total_agents,
        baseline_count=baseline_count,
        event_count=event_count,
        agent_events=agent_events,
        agent_unresolved_count=agent_unresolved_count
    ))

# --- Get FIM events ---
@fim_bp.route("/events")
def get_events():
    agent_name = request.args.get("agent")
    query = FimEvent.query
    if agent_name:
        query = query.filter(FimEvent.file_path.like(f"{agent_name}/%"))

    events = query.order_by(FimEvent.detected_at.desc()).limit(200).all()

    items = []
    for e in events:
        signature_status = getattr(e, "signature_status", "unknown")
        reason = "Local file, NSRL not checked"
        items.append({
            "id": e.id,
            "file_path": e.file_path,
            "old_hash": e.old_hash,
            "new_hash": e.new_hash,
            "change_type": e.change_type,
            "signature_status": signature_status,
            "reason": reason,
            "detected_at": e.detected_at.strftime("%Y-%m-%d %H:%M:%S"),
            "resolved": e.resolved
        })
    return jsonify(items=items)

# --- Mark event resolved ---
@fim_bp.route("/event/<int:event_id>", methods=["PATCH"])
def mark_event_resolved(event_id):
    event = FimEvent.query.get_or_404(event_id)
    event.resolved = True
    db.session.commit()
    return jsonify(status="success", message="Event marked resolved")

# --- Agent FIM POST endpoint (with API key auth) ---
@fim_bp.route("/logs/fim", methods=["POST"])
def receive_fim_event():
    """Receive FIM event from Linux agent."""
    # --- Secure API key validation ---
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing or invalid Authorization header"}), 401

    api_key = auth_header.split("Bearer ")[1].strip()
    expected_key = str(current_app.config.get("AGENT_API_KEY", "")).strip()

    if api_key != expected_key:
        return jsonify({
            "error": "Unauthorized: invalid API key",
            "received": api_key,
            "expected": expected_key
        }), 403

    expected_key = getattr(current_app.config, "AGENT_API_KEY", None)
    if not expected_key or api_key != expected_key:
        return jsonify({"error": "Unauthorized: invalid API key"}), 403
    

    # --- Parse JSON payload ---
    data = request.get_json() or {}
    raw_log = data.get("raw_log", {})

    # Derive change_type dynamically from event name
    event_name = raw_log.get("event", "modified")
    change_type = event_name.replace("fim_event_", "")

    # Derive agent_name from file_path (first directory component)
    file_path = raw_log.get("file_path", "unknown")
    agent_name = file_path.split("/")[0] if "/" in file_path else "unknown"

    # Create and store the FIM event
    event = FimEvent(
        file_path=file_path,
        old_hash=raw_log.get("baseline_hash"),
        new_hash=raw_log.get("current_hash"),
        change_type=change_type,
        resolved=False
    )

    db.session.add(event)
    db.session.commit()

    return jsonify({"status": "success", "agent": agent_name, "change_type": change_type}), 201
