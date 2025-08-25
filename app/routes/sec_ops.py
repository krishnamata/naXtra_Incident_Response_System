from flask import Blueprint, render_template, session
from app.models import LogEntry, Alert, Tasks
from app.extensions import db

sec_ops_bp = Blueprint('sec_ops', __name__, url_prefix='/sec_ops')

@sec_ops_bp.route('/', methods=['GET'])
def view_sec_ops():
    current_user_id = session.get('user_id')
    role = session.get('role')

    # Fetch logs and alerts
    logs = LogEntry.query.all()
    alerts = Alert.query.all()

    # Prepare endpoint risk table
    risk_table = []
    endpoints = {log.source for log in logs}
    for endpoint in endpoints:
        endpoint_logs = [l for l in logs if l.source == endpoint]
        endpoint_alerts = [a for a in alerts if a.agent_name == endpoint]
        
        # Example risk calculation (you can replace with your formula)
        risk_score = sum(a.severity or 0 for a in endpoint_alerts)
        critical_alerts = sum(1 for a in endpoint_alerts if (a.severity or 0) >= 7)
        
        risk_table.append({
            'endpoint': endpoint,
            'risk_score': risk_score,
            'critical_alerts': critical_alerts,
            'total_logs': len(endpoint_logs),
            'total_alerts': len(endpoint_alerts)
        })

    # Prepare behavior patterns (placeholder)
    behavior_patterns = {}  # e.g., repeated log types, frequent alerts

    return render_template(
        'report/sec_ops.html',
        role=role,
        logs=logs,
        alerts=alerts,
        risk_table=risk_table,
        behavior_patterns=behavior_patterns
    )
