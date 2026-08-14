from flask import request, jsonify
from app.audit.report_progress import progress_store, run_report_task
from app.audit.audit_routes import audit_bp  # ensure blueprint imported
from app.models import Alert, User
from app.extensions import db
import threading, uuid

@audit_bp.route("/start_alerts_report", methods=["POST"])
def start_alerts_report():
    data = request.form
    start = data.get("start_date")
    end = data.get("end_date")
    agent = data.get("agent")
    nist_phase = data.get("nist_phase")
    mitre_id = data.get("mitre_id")
    rule_id = data.get("rule_id")
    malware = data.get("malware")
    cvss_min = float(data.get("cvss_min") or 0)
    risk_min = float(data.get("risk_min") or 0)
    analyst = data.get("analyst")

    # Build query with filters
    query = db.session.query(Alert).filter(Alert.detected_time >= start, Alert.detected_time <= end)
    if agent:
        query = query.filter(Alert.agent_name.ilike(f"%{agent}%"))
    if nist_phase:
        query = query.filter(Alert.nist_phase.ilike(f"%{nist_phase}%"))
    if mitre_id:
        query = query.filter(Alert.technique_id.ilike(f"%{mitre_id}%"))
    if rule_id:
        query = query.filter(Alert.rule_id.ilike(f"%{rule_id}%"))
    if malware:
        query = query.filter(Alert.malware_name.ilike(f"%{malware}%"))
    if cvss_min:
        query = query.filter(Alert.cvss_score >= cvss_min)
    if risk_min:
        query = query.filter(Alert.risk_score >= risk_min)
    if analyst:
        query = query.join(User, Alert.assigned_to_user_id==User.id).filter(User.full_name.ilike(f"%{analyst}%"))

    task_id = str(uuid.uuid4())
    filepath = f"/tmp/alerts_report_{task_id}.xlsx"

    # Columns to include in the report
    columns = ["id", "severity", "cvss_score", "technique_id", "nist_phase", 
               "rule_id", "malware_name", "risk_score", "agent_name", "assigned_to_user_id"]

    # Initialize progress
    progress_store[task_id] = 0

    # Start async report generation
    threading.Thread(
        target=run_report_task,
        args=(task_id, query, columns, filepath)
    ).start()

    return jsonify({"task_id": task_id, "filepath": filepath})
