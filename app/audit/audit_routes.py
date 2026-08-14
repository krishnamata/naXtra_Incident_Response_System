from flask import Blueprint, request, jsonify, render_template, current_app, send_file
from app.models import User, LogEntry, Alert, AlertEvidence, AlertStepWork, FimEvent
from app.extensions import db
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from dateutil.parser import parse as parse_date
from PIL import Image as PILImage
from openpyxl import Workbook
from openpyxl.styles import Font, Alignment
from openpyxl.chart import BarChart, PieChart, LineChart, Reference
from app.dashboard.routes import get_dashboard_context
from openpyxl.utils import get_column_letter
from collections import defaultdict
import os, threading, time, json, io
from datetime import datetime, timedelta
from sqlalchemy import func, distinct
from reportlab.graphics.charts.piecharts import Pie
from reportlab.platypus import Image as XImage
from reportlab.graphics.charts.linecharts import HorizontalLineChart
from reportlab.graphics.shapes import Drawing
from collections import Counter
import matplotlib.pyplot as plt
from reportlab.lib.colors import red, green, yellow, blue
from reportlab.graphics import renderPDF
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import cm
import psutil  # Needed for system_metrics
import pandas as pd

audit_bp = Blueprint("audit", __name__, url_prefix="/audit")

# --- Task dictionary ---
tasks = {}
TASKS_FILE = "tasks.json"  # or any suitable path



def get_task_by_id(task_id):
    return tasks.get(task_id)

# Helper functions for persistent task storage
def load_tasks():
    if not os.path.exists(TASKS_FILE):
        return {}
    try:
        with open(TASKS_FILE, "r") as f:
            return json.load(f) or {}
    except (json.JSONDecodeError, ValueError):
        return {}


def save_tasks(tasks):
    os.makedirs(os.path.dirname(TASKS_FILE), exist_ok=True)
    with open(TASKS_FILE, "w") as f:
        json.dump(tasks, f)

def get_recent_logs(limit=100):
    return LogEntry.query.order_by(LogEntry.timestamp.desc()).limit(limit).all()

def get_recent_alerts(limit=100):
    return Alert.query.order_by(Alert.detected_time.desc()).limit(limit).all()

def get_recent_fim_events(limit=100):
    return FimEvent.query.order_by(FimEvent.detected_at.desc()).limit(limit).all()





# --- Helper: compute per-agent average CVSS and metrics ---
def compute_alert_risk(alerts_list, include_metrics=False):
    """
    Given a list of Alert objects, compute average CVSS per agent.
    Returns (avg_risks, avg_metrics) dictionaries.
    """
    cvss_mappings = load_cvss_mappings()
    avg_risks = {}
    avg_metrics = {}

    agents = sorted({a.agent_name for a in alerts_list if a.agent_name})
    for agent in agents:
        agent_alerts = [a for a in alerts_list if a.agent_name == agent]
        scores = []
        metrics_list = []
        for alert in agent_alerts:
            score, metrics = resolve_cvss(alert, cvss_mappings)
            scores.append(score)
            if include_metrics:
                metrics_list.append(metrics)
        avg_risks[agent] = round(sum(scores) / max(len(scores), 1), 2)
        if include_metrics:
            # Collapse metrics if only one alert; else take first alert for summary
            avg_metrics[agent] = metrics_list[0] if metrics_list else {}
    return avg_risks, avg_metrics



# ---------------- Dashboard Page ----------------



# ---------------- System Metrics (Optimized) ----------------
@audit_bp.route("/api/system_metrics")
def system_metrics():
    start_str = request.args.get("start")
    end_str = request.args.get("end")

    try:
        start_date = datetime.fromisoformat(start_str).date() if start_str else datetime.utcnow().date() - timedelta(days=6)
        end_date = datetime.fromisoformat(end_str).date() if end_str else datetime.utcnow().date()
    except ValueError:
        return jsonify({"error": "Invalid start/end date format"}), 400

    if start_date > end_date:
        start_date, end_date = end_date, start_date

    num_days = (end_date - start_date).days + 1
    days = [(start_date + timedelta(days=i)).isoformat() for i in range(num_days)]

    # CPU/RAM
    cpu_percent = psutil.cpu_percent(interval=1)
    vm = psutil.virtual_memory()
    ram_percent = vm.percent
    ram_used_mb = vm.used / (1024 * 1024)

    # Aggregate counts (fixed)
    total_logs = db.session.query(func.count(LogEntry.id)).scalar() or 0
    total_alerts = db.session.query(func.count(Alert.id)).scalar() or 0
    total_mitre_mapped = db.session.query(func.count()).filter(Alert.technique_id.isnot(None)).scalar() or 0
    total_nist_evidence = db.session.query(func.count(AlertEvidence.id)).scalar() or 0

    # Logs & Alerts by day
    logs_map = {str(r[0]): r[1] for r in db.session.query(func.date(LogEntry.timestamp), func.count(LogEntry.id))
                 .filter(LogEntry.timestamp >= start_date, LogEntry.timestamp <= end_date)
                 .group_by(func.date(LogEntry.timestamp)).all()}
    logs_by_day = [logs_map.get(d, 0) for d in days]

    alerts_map = {str(r[0]): r[1] for r in db.session.query(func.date(Alert.detected_time), func.count(Alert.id))
                   .filter(Alert.detected_time >= start_date, Alert.detected_time <= end_date)
                   .group_by(func.date(Alert.detected_time)).all()}
    alerts_by_day = [alerts_map.get(d, 0) for d in days]

    # Alerts by severity
    buckets = {"high": 0, "medium": 0, "low": 0}
    for sev, cnt in db.session.query(Alert.severity, func.count(Alert.id)).group_by(Alert.severity).all():
        if sev is None:
            continue
        if sev >= 8:
            buckets["high"] += cnt
        elif sev >= 4:
            buckets["medium"] += cnt
        else:
            buckets["low"] += cnt

    # Log→Alert deltas
    deltas_by_day = defaultdict(list)
    rows = db.session.query(Alert.detected_time, LogEntry.timestamp)\
        .join(LogEntry, Alert.matched_log_id == LogEntry.id)\
        .filter(Alert.detected_time >= start_date, Alert.detected_time <= end_date).all()
    for detected_time, log_ts in rows:
        if detected_time and log_ts:
            delta = (detected_time - log_ts).total_seconds()
            deltas_by_day[detected_time.date().isoformat()].append(delta)
    log_to_alert_avg_by_day = [
        (sum(deltas_by_day[d]) / len(deltas_by_day[d])) if deltas_by_day.get(d) else 0.0
        for d in days
    ]

    # Recent deltas (last 100 alerts)
    recent_deltas = [
        (d - l).total_seconds()
        for d, l in db.session.query(Alert.detected_time, LogEntry.timestamp)
            .join(LogEntry, Alert.matched_log_id == LogEntry.id)
            .order_by(Alert.detected_time.desc())
            .limit(100).all()
        if d and l
    ]

    # Evidence by user
    evidence_by_user = [
        {"username": r[0], "count": r[1]}
        for r in db.session.query(User.username, func.count(AlertEvidence.id))
            .join(AlertEvidence, User.id == AlertEvidence.uploaded_by)
            .group_by(User.username).all()
    ]

    # CPU/RAM history (simulate)
    cpu_history = [cpu_percent] * num_days
    ram_history = [ram_percent] * num_days

    return jsonify({
        "cpu_percent": cpu_percent,
        "ram_percent": ram_percent,
        "ram_used_mb": ram_used_mb,
        "total_logs": total_logs,
        "total_alerts": total_alerts,
        "total_mitre_mapped": total_mitre_mapped,
        "total_nist_evidence": total_nist_evidence,
        "days": days,
        "logs_by_day": logs_by_day,
        "alerts_by_day": alerts_by_day,
        "alerts_by_severity": buckets,
        "log_to_alert_avg_by_day": log_to_alert_avg_by_day,
        "recent_log_alert_deltas": recent_deltas,
        "evidence_by_user": evidence_by_user,
        "cpu_history": cpu_history,
        "ram_history": ram_history
    })

# ----------------- Helper Functions -----------------
# ---------------- Dashboard Page ----------------
@audit_bp.route("/")
def audit_dashboard():
    log_agents = db.session.query(distinct(LogEntry.source)).all()
    alert_agents = db.session.query(distinct(Alert.agent_name)).all()
    agent_names = sorted({a[0] for a in log_agents + alert_agents if a[0]})

    log_types = sorted([lt[0] for lt in db.session.query(distinct(LogEntry.log_type)).all() if lt[0]])
    nist_phases = sorted({alert.nist_phase for alert in AlertStepWork.query.all() if getattr(alert, "nist_phase", None)})
    rule_options = {alert.rule_id: alert.technique_name for alert in Alert.query.all() if alert.rule_id and alert.technique_name}

    return render_template(
        'audit_dashboard.html',
        agent_names=agent_names,
        log_types=log_types,
        nist_phases=nist_phases,
        rule_options=rule_options
    )

# ----------------- Chart generator helper -----------------
def generate_pie_chart(data_dict):
    import matplotlib.pyplot as plt
    import io

    fig, ax = plt.subplots()
    ax.pie(data_dict.values(), labels=data_dict.keys(), autopct="%1.1f%%")
    img = io.BytesIO()
    plt.savefig(img, format='png')
    plt.close(fig)
    img.seek(0)
    return img







# ----------------- audit_routes.py (PDF sections) -----------------
def create_title_page(doc_elements, styles, report_type="Log Report"):
    """Add title page with report info and endpoint summary placeholder."""
    # Title
    doc_elements.append(Paragraph(report_type, styles["Title"]))
    doc_elements.append(Spacer(1, 24))
    
    # Generated time
    doc_elements.append(Paragraph(f"Generated on: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC", styles["Normal"]))
    doc_elements.append(Spacer(1, 24))
    
    # Endpoint Summary Table
    context = get_dashboard_context()  # from dashboard_routes.py
    endpoint_risk = context.get("endpoint_risk", {})
    
    table_data = [["Agent", "Risk Score", "Level"]]
    for agent, data in endpoint_risk.items():
        score = data.get("values", [0])[0]
        if score < 4:
            level = "Low"
        elif score < 7:
            level = "Medium"
        elif score < 9:
            level = "High"
        else:
            level = "Critical"
        table_data.append([agent, score, level])
    
    t = Table(table_data, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.gray),
        ("TEXTCOLOR",(0,0),(-1,0),colors.whitesmoke),
        ("ALIGN",(0,0),(-1,-1),"CENTER"),
        ("GRID",(0,0),(-1,-1),0.5,colors.black)
    ]))
    doc_elements.append(t)
    doc_elements.append(PageBreak())


def create_log_report_pdf():
    """Generate PDF with Title Page, Endpoint Summary, Log details, and Log Type chart."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    styles = getSampleStyleSheet()
    elements = []

    # Title + Endpoint summary
    create_title_page(elements, styles, report_type="Log Report")

    # Logs section
    logs = get_recent_logs(100)
    elements.append(Paragraph("Logs", styles["Heading2"]))
    table_data = [["Timestamp", "Source", "Log Type", "Message"]]
    for l in logs:
        table_data.append([l.timestamp.strftime('%Y-%m-%d %H:%M:%S'), l.source, l.log_type, l.message])
    elements.append(Table(table_data, repeatRows=1))
    elements.append(Spacer(1,12))

    # Log Type Chart
    log_type_counts = Counter(l.log_type for l in logs)
    if log_type_counts:
        img_io = generate_pie_chart(log_type_counts)
        pil_img = PILImage.open(img_io)
        pil_img.save("tmp_log_type.png")
        elements.append(Paragraph("Logs by Type", styles["Heading3"]))
        elements.append(XImage("tmp_log_type.png", width=400, height=300))
        elements.append(Spacer(1,12))

    doc.build(elements)
    buffer.seek(0)
    return buffer


def create_alert_report_pdf():
    """Generate PDF with Title Page, Endpoint Summary, Alerts, FIM and charts."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    styles = getSampleStyleSheet()
    elements = []

    # Title + Endpoint summary
    create_title_page(elements, styles, report_type="Alert Report")

    # Alerts section
    alerts = get_recent_alerts(100)
    elements.append(Paragraph("Alerts", styles["Heading2"]))
    table_data = [["Timestamp", "Agent", "Severity", "Rule", "Description"]]
    for a in alerts:
        table_data.append([a.detected_time.strftime('%Y-%m-%d %H:%M:%S'), a.agent_name, a.severity, a.rule_id, a.description])
    elements.append(Table(table_data, repeatRows=1))
    elements.append(Spacer(1,12))

    # Alerts by Agent Chart
    agent_counts = Counter(a.agent_name for a in alerts)
    if agent_counts:
        img_io = generate_pie_chart(agent_counts)
        pil_img = PILImage.open(img_io)
        pil_img.save("tmp_alerts_agent.png")
        elements.append(Paragraph("Alerts by Agent", styles["Heading3"]))
        elements.append(XImage("tmp_alerts_agent.png", width=400, height=300))
        elements.append(Spacer(1,12))

    # FIM Section
    fim_events = get_recent_fim_events(100)
    elements.append(Paragraph("FIM Events", styles["Heading2"]))
    table_data = [["Timestamp", "File Path", "Change Type", "Old Hash", "New Hash", "Resolved"]]
    for f in fim_events:
        table_data.append([f.detected_at.strftime('%Y-%m-%d %H:%M:%S'), f.file_path, f.change_type, f.old_hash or '', f.new_hash or '', 'Yes' if f.resolved else 'No'])
    elements.append(Table(table_data, repeatRows=1))
    elements.append(Spacer(1,12))

    # FIM Change Type Charts
    agent_map = defaultdict(list)
    for f in fim_events:
        agent = f.file_path.split('/')[0] if '/' in f.file_path else 'unknown'
        agent_map[agent].append(f.change_type)
    for agent, changes in agent_map.items():
        counts = Counter(changes)
        if counts:
            img_io = generate_pie_chart(counts)
            pil_img = PILImage.open(img_io)
            pil_img.save(f"tmp_fim_{agent}.png")
            elements.append(Paragraph(f"FIM Change Types - {agent}", styles["Heading3"]))
            elements.append(XImage(f"tmp_fim_{agent}.png", width=400, height=300))
            elements.append(Spacer(1,12))

    doc.build(elements)
    buffer.seek(0)
    return buffer





# ----------------- Routes -----------------
@audit_bp.route("/start_log_report_pdf", methods=["POST"])
def start_log_report_pdf():
    buffer = create_log_report_pdf()
    return send_file(buffer, as_attachment=True, download_name="log_report.pdf", mimetype="application/pdf")


@audit_bp.route("/start_alert_report_pdf", methods=["POST"])
def start_alert_report_pdf():
    buffer = create_alert_report_pdf()
    return send_file(buffer, as_attachment=True, download_name="alert_report.pdf", mimetype="application/pdf")
