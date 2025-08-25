# app/dashboard/routes.py
from flask import session, Blueprint, render_template, redirect, url_for, make_response
from datetime import datetime, timedelta
from sqlalchemy import func
from app.models import Alert, LogEntry, User
from app.naxtraai.generator import generator
from app.utils.agent_heartbeat import AgentHeartbeat
from app.utils.endpoint_risk import get_endpoint_risk_from_db
from app import db
from app.dlp import extract_log_types
from app.rules.rules_loader import load_rules
from app.decoders.loader import load_wazuh_decoders
from jinja2.runtime import Undefined
from collections import defaultdict


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

@dashboard_bp.route('/')
def dashboard():
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
    alert_counts = defaultdict(int)
    agent_alerts = defaultdict(list)
    alerts = Alert.query.all()
    for alert in alerts:
        agent = alert.agent_name
        alert_counts[agent] += 1
        agent_alerts[agent].append({
            'timestamp': alert.detected_time.strftime("%Y-%m-%d %H:%M:%S"),
            'cvss': float(alert.cvss_score or 0),
            'message': alert.description or alert.rule_title
        })

    # --- Calculate average CVSS per agent ---
    alerts_avg = {
        row.agent_name: float(row.avg_risk or 0)
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

    # --- Endpoint risk (numeric placeholder) ---
    endpoint_risk = {}
    for agent in agent_names:
        avg_cvss = db.session.query(func.avg(Alert.cvss_score)).filter(Alert.agent_name == agent).scalar()
        avg_cvss = float(avg_cvss) if avg_cvss is not None else 0.0
        endpoint_risk[agent] = {
            'dates': [datetime.utcnow().strftime("%Y-%m-%d")],
            'values': [avg_cvss]
        }


    # --- Global trend ---
    global_trend = {
        'dates': [(datetime.utcnow()).strftime("%Y-%m-%d")],
        'values': [0]
    }

    # --- AI summary for admin only ---
    generator_summary = "AI insights here" if role == 'admin' else None

    return make_response(render_template(
        'dashboard.html',
        username=username,
        role=role,
        agent_names=agent_names,
        total_agents=total_agents,
        os_counts=os_counts,
        alert_counts=alert_counts,
        agent_alerts=agent_alerts,
        logs=logs,
        endpoint_risk=endpoint_risk,
        global_trend=global_trend,
        generator_summary=generator_summary
    ))

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
    agent_id = request.args.get('agent_id')
    agents = Agent.query.all()

    logs = []
    selected_agent = None
    if agent_id:
        selected_agent = Agent.query.get(agent_id)
        if selected_agent:
            logs = LogEntry.query.filter_by(agent_id=agent_id).order_by(LogEntry.timestamp.desc()).limit(50).all()

    if request.args.get('ajax') == '1':
        # Return JSON for AJAX
        return {
            "logs": [
                {"timestamp": log.timestamp.strftime("%Y-%m-%d %H:%M:%S"), "message": log.message}
                for log in logs
            ]
        }

    return render_template(
        'logs.html',
        agents=agents,
        logs=logs,
        selected_agent=selected_agent
    )


@dashboard_bp.route('/ai_insights')
def ai_insights():
    # Example content
    return render_template('ai_insights.html')  # you also need to create this template
