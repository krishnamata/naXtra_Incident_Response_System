# app/dashboard/routes.py
from flask import session, Blueprint, render_template, redirect, jsonify, url_for, make_response, request, Response, stream_with_context, send_file
from datetime import datetime, timedelta
from sqlalchemy import func
from app.models import Alert, LogEntry, User, UnmatchedLog
from app.naxtraai.generator import generator
from app.utils.agent_heartbeat import AgentHeartbeat
from app.utils.cvss_loader import load_cvss_mappings, compute_cvss_score
from app.utils.endpoint_risk import get_endpoint_risk_from_db
from app import db 
from app.rules.rules_loader import load_rules
from app.decoders.loader import load_wazuh_decoders
from jinja2.runtime import Undefined
from collections import defaultdict
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from datetime import datetime
from app.dlp import (
    extract_log_types,
    LOG_AGENT_RULE_MAP,
    fetch_logs_by_type,
    detect_logs_and_generate_alerts_for_selected_logs,
)

import time
import re
import random
import json

dashboard_bp = Blueprint('dashboard', __name__, url_prefix='/dashboard', template_folder='templates')
config_bp = Blueprint('config', __name__)
# Load rules/decoders (caches)
RULES_CACHE = load_rules("/var/www/modular-soar/app/rules/wazuh-ruleset/rules")
DECODERS_CACHE = load_wazuh_decoders("/home/kali/wazuh-ruleset/decoders")


def safe_list(val):
    """Ensure a value is JSON-serializable as a list."""
    if isinstance(val, (list, tuple)):
        return list(val)
    if val is None:
        return []
    return [val]

def get_total_agents():
    # Count distinct agents from LogEntry table
    return LogEntry.query.with_entities(LogEntry.source).distinct().count()


def get_log_summary():
    total_logs = LogEntry.query.count()
    processed_logs = LogEntry.query.filter_by(processed=True).count()
    unprocessed_logs = total_logs - processed_logs
    recent_logs = LogEntry.query.order_by(LogEntry.timestamp.desc()).limit(5).all()
    recent_logs_list = [log.to_dict() for log in recent_logs]
    
    return {
        "total": total_logs,
        "processed": processed_logs,
        "unprocessed": unprocessed_logs,
        "recent_logs": recent_logs_list
    }


def get_alert_summary():
    total_alerts = Alert.query.count()
    # Add more details if needed
    return {"total": total_alerts}

def get_agent_names():
    return [row[0] for row in LogEntry.query.with_entities(LogEntry.source).distinct()]

def get_alert_counts():
    counts = defaultdict(int)
    for alert in Alert.query.all():
        counts[alert.agent_name] += 1
    return counts

def get_endpoint_risk():
    return {
        row.agent_name: {
            "values": [round(float(row.avg_risk) if row.avg_risk is not None else 0.0, 2)]
        }
        for row in Alert.query.with_entities(
            Alert.agent_name,
            func.avg(Alert.cvss_score).label("avg_risk")
        ).group_by(Alert.agent_name)
    }

def sanitize_endpoint_risk(risk_dict):
    clean = {}
    for agent, data in (risk_dict or {}).items():
        agent_key = str(agent) if agent is not None else "unknown"
        values = data.get('values') or []
        clean_values = []
        for v in values:
            try:
                clean_values.append(float(v))
            except (TypeError, ValueError):
                clean_values.append(0.0)
        clean[agent_key] = {"values": clean_values, "dates": data.get("dates", [])}
    return clean





def get_generator_summary():
    # Example: placeholder
    return "AI insights placeholder"






@dashboard_bp.route("/summary", methods=["GET"])
def dashboard_summary():
    # Logs
    total_logs = LogEntry.query.count()
    unprocessed_logs = LogEntry.query.filter_by(processed=False).count()
    processed_logs = LogEntry.query.filter_by(processed=True).count()
    recent_logs = LogEntry.query.order_by(LogEntry.timestamp.desc()).limit(20).all()
    recent_logs_list = [log.to_dict() for log in recent_logs]

    # Alerts
    total_alerts = Alert.query.count()
    alerts_summary = {
        "total": total_alerts,
        "unprocessed": 0,
        "processed": 0,
        "recent": []
    }

    # Unmatched Logs
    unmatched_logs = UnmatchedLog.query.count()

    return jsonify({
        "logs": {
            "total": total_logs,
            "unprocessed": unprocessed_logs,
            "processed": processed_logs,
            "recent_logs": recent_logs_list
        },
        "alerts": alerts_summary,
        "unmatched_logs": {
            "total": unmatched_logs
        }
    })

@dashboard_bp.route("/unmatched_logs", methods=["GET"])
def get_unmatched_logs():
    limit = int(request.args.get("limit", 50))
    offset = int(request.args.get("offset", 0))

    logs = UnmatchedLog.query.order_by(UnmatchedLog.timestamp.desc())\
        .offset(offset).limit(limit).all()

    logs_list = [
        {
            "id": log.id,
            "timestamp": log.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "agent_name": log.source if log.log else "unknown",
            "log_type": log.log_type,
            "message": log.message
        } for log in logs
    ]

    total = UnmatchedLog.query.count()
    return jsonify({"unmatched_logs": logs_list, "total": total})



@dashboard_bp.route("/process_logs", methods=["POST"])
def process_logs():
    data = request.get_json()
    log_ids = data.get("log_ids", [])

    if not log_ids:
        return jsonify({"error": "No logs specified"}), 400

    logs_to_process = LogEntry.query.filter(LogEntry.id.in_(log_ids)).all()
    if not logs_to_process:
        return jsonify({"message": "No logs found for the selected IDs."})

    # Optional: delete previous alerts for these logs to avoid duplicates
    for log in logs_to_process:
        Alert.query.filter_by(agent_name=log.source, matched_log_id=log.id).delete()
    db.session.commit()

    # Detect alerts for these logs
    logs_dict_list = logs_to_process  # pass objects directly
    created_alerts = detect_logs_and_generate_alerts_for_selected_logs(logs_dict_list)

    created_alert_ids = [a.matched_log_id for a in created_alerts]

    # Populate unmatched logs
    for log in logs_to_process:
        if log.id not in created_alert_ids:
            unmatched = UnmatchedLog(
                log_id=log.id,
                agent_name=log.source,
                log_type=log.log_type,
                timestamp=log.timestamp,
                message=log.message
            )
            db.session.add(unmatched)

    # Mark logs as processed
    for log in logs_to_process:
        log.processed = True

    db.session.commit()

    return jsonify({
        "message": f"Processed {len(logs_to_process)} logs, created {len(created_alerts)} alerts."
    })


@dashboard_bp.route("/process_unmatched_logs", methods=["POST"])
def process_unmatched_logs():
    unmatched_logs = UnmatchedLog.query.all()
    if not unmatched_logs:
        return jsonify({"message": "No unmatched logs to process."})

    logs_dict_list = []
    for ulog in unmatched_logs:
        log_entry = LogEntry.query.get(ulog.log_id)
        if log_entry:
            logs_dict_list.append(log_entry)

    created_alerts = detect_logs_and_generate_alerts_for_selected_logs(logs_dict_list)

    created_alert_ids = [a.matched_log_id for a in created_alerts]

    # Remove successfully matched logs from unmatched table
    for ulog in unmatched_logs:
        if ulog.log_id in created_alert_ids:
            db.session.delete(ulog)

    db.session.commit()
    return jsonify({
        "message": f"Processed {len(logs_dict_list)} unmatched logs, created {len(created_alerts)} alerts."
    })

@dashboard_bp.route("/process_realtime")
def process_realtime():
    log_type = request.args.get("type", "unprocessed")  # 'unprocessed' or 'unmatched'

    def generate():
        if log_type == "unprocessed":
            logs = LogEntry.query.filter_by(processed=False).all()
        elif log_type == "unmatched":
            unmatched = UnmatchedLog.query.all()
            logs = []
            for ulog in unmatched:
                log = LogEntry.query.get(ulog.log_id)
                if log:
                    logs.append(log)
        else:
            logs = []

        total = len(logs)
        counts = {
            "logs": {
                "total": LogEntry.query.count(),
                "processed": LogEntry.query.filter_by(processed=True).count(),
                "unprocessed": LogEntry.query.filter_by(processed=False).count()
            },
            "alerts": {"total": Alert.query.count()},
            "unmatched_logs": {"total": UnmatchedLog.query.count()}
        }

        processed_count = 0
        batch_size = 10  # process 50 logs at a time

        for i in range(0, total, batch_size):
            batch = logs[i:i+batch_size]
            created_alerts = detect_logs_and_generate_alerts_for_selected_logs(batch)

            # Mark logs as processed
            for log in batch:
                log.processed = True
            db.session.commit()

            processed_count += len(batch)
            # update counts dynamically
            counts["logs"]["processed"] = LogEntry.query.filter_by(processed=True).count()
            counts["logs"]["unprocessed"] = LogEntry.query.filter_by(processed=False).count()
            counts["alerts"]["total"] = Alert.query.count()
            counts["unmatched_logs"]["total"] = UnmatchedLog.query.count()

            yield f"data: {json.dumps({'processed': processed_count, 'total': total, 'counts': counts})}\n\n"
            time.sleep(0.1)  # small delay to avoid flooding client

        # Done event
        yield f"event: done\ndata: {json.dumps({'message': f'Processed {total} logs.'})}\n\n"

    return Response(stream_with_context(generate()), mimetype="text/event-stream")






@dashboard_bp.route('/')
def dashboard():
    context = get_dashboard_context()
    return render_template("dashboard.html", **context)

def get_dashboard_context():
    username = session.get('username', 'Guest')
    role = session.get('role', 'analyst')

    # --- Agents ---
    agent_names = [row[0] for row in LogEntry.query.with_entities(LogEntry.source).distinct()]
    total_agents = len(agent_names)

    # --- OS counts ---
    os_counts = defaultdict(int)
    for agent, in LogEntry.query.with_entities(LogEntry.source).distinct():
        os_counts[agent] += LogEntry.query.filter_by(source=agent).count()

    # --- Alerts per agent ---
    cvss_mappings = load_cvss_mappings()
    alert_counts = defaultdict(int)
    agent_alerts = defaultdict(list)
    alerts = Alert.query.all()
    alerts_to_update = []

    # --- Resolve CVSS and prepare alerts ---
    for alert in alerts:
        if alert.cvss_score is None:
            alert.cvss_score, _ = resolve_cvss(alert, cvss_mappings)
            alerts_to_update.append(alert)

        alert_counts[alert.agent_name] += 1
        agent_alerts[alert.agent_name].append({
            'timestamp': alert.detected_time.strftime("%Y-%m-%d %H:%M:%S"),
            'cvss': alert.cvss_score,
            'message': alert.description or alert.rule_title
        })

    # --- Bulk commit only once ---
    if alerts_to_update:
        db.session.bulk_save_objects(alerts_to_update)
        db.session.commit()

    # --- Calculate average CVSS per agent ---
    alerts_avg = {
        row.agent_name: round(float(row.avg_risk or 0.0), 2)
        for row in Alert.query.with_entities(
            Alert.agent_name,
            func.avg(Alert.cvss_score).label("avg_risk")
        ).group_by(Alert.agent_name)
    }

    # --- Recent logs ---
    logs = defaultdict(dict)
    for agent in agent_names:
        log_entries = LogEntry.query.filter_by(source=agent).order_by(LogEntry.timestamp.desc()).limit(5)
        for log in log_entries:
            logs[agent][log.log_type] = log.message[:500] if log.message else ""

    # --- Endpoint risk trend ---
    # --- Endpoint risk trend ---
    endpoint_risk = {
        (str(agent) if agent is not None else "unknown"): {
            'dates': [datetime.utcnow().strftime("%Y-%m-%d")],
            'values': [alerts_avg.get(agent, 0.0)]
        }
        for agent in agent_names
    }


    # --- Global trend (placeholder) ---
    global_trend = {
        'dates': [datetime.utcnow().strftime("%Y-%m-%d")],
        'values': [0]
    }

    # --- Debug output ---
    for agent, alerts_list in agent_alerts.items():
        print(f"DEBUG00000: Agent {agent}, first CVSS -> {alerts_list[0]['cvss']}")

    generator_summary = "AI insights here" if role == 'admin' else None
    
    endpoint_risk = sanitize_endpoint_risk(endpoint_risk) 
    context = {
        "username": username,
        "role": role,
        "total_agents": get_total_agents(),
        "logs": get_log_summary(),
        "alerts": get_alert_summary(),
        "agent_names": get_agent_names(),
        "alert_counts": get_alert_counts(),
        "endpoint_risk": endpoint_risk,
        "generator_summary": get_generator_summary()
    }
    print("DEBUG CONTEXT:", context)

    return context




@dashboard_bp.route('/configurations', methods=['GET', 'POST'])
def configurations():
    import os, json
    from flask import request, redirect, url_for, flash, render_template

    CONFIG_FILE = "/var/www/modular-soar/app/dashboard/config.json"
    DEFAULT_SOURCES = {}

    # --- Helper functions ---
    def load_config():
        if not os.path.exists(CONFIG_FILE):
            save_config(DEFAULT_SOURCES)
            return DEFAULT_SOURCES
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)

    def save_config(data):
        with open(CONFIG_FILE, 'w') as f:
            json.dump(data, f, indent=4)

    # --- Load existing config ---
    config_data = load_config()

    if request.method == 'POST':
        source_name = request.form.get('source_name')
        log_key = request.form.get('log_key')
        log_path = request.form.get('log_path')

        if source_name and log_key and log_path:
            config_data.setdefault(source_name, {})[log_key] = log_path
            save_config(config_data)
            flash('Configuration updated successfully!', 'success')
        else:
            flash('Please fill all fields.', 'danger')

        return redirect(url_for('dashboard.configurations'))

    # --- Render template with config data ---
    return render_template('config.html', config=config_data)


@dashboard_bp.route('/logs')
def logs():
    agent_name = request.args.get('agent_name')

    # Get all distinct agents from logs
    agent_names = [row[0] for row in LogEntry.query.with_entities(LogEntry.source).distinct()]
    logs = []
    selected_agent = None

    if agent_name:
        selected_agent = agent_name
        logs = LogEntry.query.filter_by(source=agent_name)\
                             .order_by(LogEntry.timestamp.desc())\
                             .limit(50).all()

    if request.args.get('ajax') == '1':
        # Return JSON for AJAX
        return {
            "logs": [
                {
                    "timestamp": log.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    "message": log.message,
                    "log_type": log.log_type,
                    "source": log.source
                }
                for log in logs
            ]
        }

    return render_template(
        'logs.html',
        agent_names=agent_names,
        logs=logs,
        selected_agent=selected_agent
    )



@dashboard_bp.route('/ai_insights')
def ai_insights():
    # Example content
    return render_template('ai_insights.html')  # you also need to create this template


@dashboard_bp.route('/endpoint_risk_details')
def endpoint_risk_details():
    agent_name = request.args.get('agent_name')
    if not agent_name:
        return {"error": "No agent specified"}, 400

    offset = int(request.args.get('offset', 0))
    limit = int(request.args.get('limit', 50))
    sort_by = request.args.get('sort_by', 'cvss')

    # Base query
    alerts_query = Alert.query.filter_by(agent_name=agent_name)
    alerts_query = alerts_query.filter(Alert.cvss_score >= 3.0)

    # Sorting
    if sort_by == 'time':
        alerts_query = alerts_query.order_by(Alert.detected_time.desc())
    else:  # default: CVSS descending
        alerts_query = alerts_query.order_by(Alert.cvss_score.desc())

    total_alerts = alerts_query.count()

    # Pagination: fetch only the subset
    paginated_alerts = alerts_query.offset(offset).limit(limit).all()

    # Load CVSS mappings once
    cvss_mappings = load_cvss_mappings()

    # Resolve CVSS deterministically only for the paginated alerts
    for alert in paginated_alerts:
        if alert.cvss_score is None or getattr(alert, "metrics", None) is None:
            resolve_cvss(alert, cvss_mappings)
    db.session.commit()  # commit updated cvss_score and metrics

    # Prepare response
    risk_details = []
    for alert in paginated_alerts:
        risk_details.append({
            "detected_time": alert.detected_time.strftime("%Y-%m-%d %H:%M:%S"),
            "cvss_score": round(float(alert.cvss_score), 2),
            "description": alert.description or alert.rule_title,
            "rule_id": alert.rule_id,
            "metrics": getattr(alert, "metrics", {})  # deterministic CVSS metrics
        })

    return {
        "agent_name": agent_name,
        "risk_details": risk_details,
        "total": total_alerts
    }











# --- Real-time logs progress ---



# --- Batch queue SSE ---
@dashboard_bp.route("/batch_queue")
def batch_queue():
    def generate():
        all_logs = LogEntry.query.order_by(LogEntry.timestamp).all()
        total_logs = len(all_logs)
        queued = 0

        for log in all_logs:
            if not log.processed:
                queued += 1
                yield f"data: {json.dumps({'received': queued, 'total': total_logs})}\n\n"
                time.sleep(0.05)

        yield f"event: done\ndata: {json.dumps({'total_logs': queued})}\n\n"

    return Response(stream_with_context(generate()), mimetype="text/event-stream")


# --- Batch detection SSE ---
@dashboard_bp.route("/run_batch_detection")
def run_batch_detection():
    def generate():
        logs_to_process = LogEntry.query.filter_by(processed=False).all()
        total_logs = len(logs_to_process)
        total_alerts = 0

        yield f"data: {json.dumps({'received': 0, 'total': total_logs})}\n\n"

        for i, log in enumerate(logs_to_process, start=1):
            alerts = detect_logs_and_generate_alerts_for_selected_logs([log])
            total_alerts += len(alerts)
            log.processed = True
            db.session.commit()

            yield f"data: {json.dumps({'received': i, 'total': total_logs})}\n\n"
            time.sleep(0.05)

        yield f"event: done\ndata: {json.dumps({'total_logs': total_logs, 'total_alerts': total_alerts})}\n\n"

    return Response(stream_with_context(generate()), mimetype="text/event-stream")


def estimate_metrics_from_description(description: str):
    """
    Deterministic heuristic CVSS estimator if no mapping exists.
    Returns values (AV, AC, PR, UI, C, I, A) scaled 0–1.
    """

    # Default mid-values
    AV = AC = PR = UI = C = I = A = 0.5

    if not description:
        return (AV, AC, PR, UI, C, I, A)

    desc = description.lower()

    # Attack Vector (AV)
    if "remote" in desc:
        AV = 0.9
    elif "local" in desc:
        AV = 0.6
    else:
        AV = 0.7  # default

    # Attack Complexity (AC)
    if "complex" in desc:
        AC = 0.4
    elif "simple" in desc:
        AC = 0.8
    else:
        AC = 0.6

    # Privileges Required (PR)
    if "privilege" in desc or "admin" in desc:
        PR = 0.3
    else:
        PR = 0.7

    # User Interaction (UI)
    if "user" in desc or "click" in desc:
        UI = 0.6
    else:
        UI = 0.9

    # Impact metrics
    if "confidential" in desc or "data leak" in desc:
        C = 0.9
    else:
        C = 0.5

    if "integrity" in desc or "tamper" in desc:
        I = 0.9
    else:
        I = 0.5

    if "availability" in desc or "denial" in desc:
        A = 0.9
    else:
        A = 0.5

    return (AV, AC, PR, UI, C, I, A)


def resolve_cvss(alert, cvss_mappings):
    """
    Ensure an alert always has a deterministic CVSS score and metrics.
    Updates alert.cvss_score and alert.metrics if missing.
    Returns (cvss_score, metrics)
    """
    # If alert already has CVSS and metrics, return them
    if alert.cvss_score is not None and getattr(alert, "metrics", None):
        return float(alert.cvss_score), alert.metrics

    # Check mapping first
    mapping_entry = cvss_mappings.get(str(alert.rule_id), {})
    metrics = mapping_entry.get("metrics")

    if metrics:
        try:
            base_score = compute_cvss_score(metrics)
        except KeyError:
            base_score = 0.0
    else:
        # Fallback deterministic heuristic
        AV, AC, PR, UI, C, I, A = estimate_metrics_from_description(alert.description)
        metrics = {"AV": AV, "AC": AC, "PR": PR, "UI": UI, "C": C, "I": I, "A": A}
        # Compute CVSS base score deterministically
        base_score = round(((AV + AC + PR + UI) / 4 + (C + I + A) / 3) / 2 * 10, 1)

    # Persist values on alert
    alert.cvss_score = round(base_score, 2)
    alert.metrics = metrics

    return alert.cvss_score, metrics



@dashboard_bp.route('/endpoint_risk_metrics')
def endpoint_risk_metrics():
    alert_id = request.args.get('alert_id')
    if not alert_id:
        return {"error": "No alert specified"}, 400

    alert = Alert.query.get(alert_id)
    if not alert:
        return {"error": "Alert not found"}, 404

    # Load CVSS mappings
    cvss_mappings = load_cvss_mappings()
    cvss_score, metrics = resolve_cvss(alert, cvss_mappings)

    return {
        "alert_id": alert.id,
        "cvss_score": round(cvss_score, 2),
        "metrics": metrics
    }


@dashboard_bp.route('/endpoint_summary_pdf')
def endpoint_summary_pdf():
    context = get_dashboard_context()  # Reuse dashboard context
    endpoint_risk = context.get("endpoint_risk", {})
    
    # PDF in-memory buffer
    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, height - 50, "Endpoint Summary Report")
    
    c.setFont("Helvetica", 12)
    y = height - 80
    for agent, data in endpoint_risk.items():
        score = data.get('values', [0])[0]
        if score < 4:
            level = "Low"
        elif score < 7:
            level = "Medium"
        elif score < 9:
            level = "High"
        else:
            level = "Critical"
        
        c.drawString(50, y, f"Agent: {agent}")
        c.drawString(200, y, f"Score: {score}")
        c.drawString(300, y, f"Level: {level}")
        y -= 20
        if y < 50:  # new page
            c.showPage()
            y = height - 50

    c.showPage()
    c.save()
    
    buffer.seek(0)
    return send_file(buffer, as_attachment=True,
                     download_name="endpoint_summary.pdf",
                     mimetype='application/pdf')
