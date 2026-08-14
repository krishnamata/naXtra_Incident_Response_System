from flask import request, jsonify
from app.audit.report_progress import progress_store, run_report_task
from app.audit.audit_routes import audit_bp  # ensure blueprint imported
from app.models import LogEntry
from app.extensions import db
import threading, uuid

@audit_bp.route("/start_logs_report", methods=["POST"])
def start_logs_report():
    data = request.form
    start = data.get("start_date")
    end = data.get("end_date")
    agent = data.get("agent")
    log_type = data.get("log_type")
    cvss_min = float(data.get("cvss_min") or 0)
    risk_min = float(data.get("risk_min") or 0)

    # Build query with filters
    query = db.session.query(LogEntry).filter(LogEntry.timestamp >= start, LogEntry.timestamp <= end)
    if agent:
        query = query.filter(LogEntry.source.ilike(f"%{agent}%"))
    if log_type:
        query = query.filter(LogEntry.log_type.ilike(f"%{log_type}%"))
    if cvss_min:
        query = query.filter(LogEntry.cvss_score >= cvss_min)
    if risk_min:
        query = query.filter(LogEntry.risk_score >= risk_min)

    task_id = str(uuid.uuid4())
    filepath = f"/tmp/logs_report_{task_id}.xlsx"

    # Columns to include in the report
    columns = ["timestamp", "source", "log_type", "message", "cvss_score", "risk_score"]

    # Initialize progress
    progress_store[task_id] = 0

    # Start async report generation
    threading.Thread(
        target=run_report_task,
        args=(task_id, query, columns, filepath)
    ).start()

    return jsonify({"task_id": task_id, "filepath": filepath})


