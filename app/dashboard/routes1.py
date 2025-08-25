from flask import Blueprint, render_template
import os

dashboard_bp = Blueprint('dashboard', __name__, template_folder='templates')

LOG_FILES = {
    'Auth Log': '/app/logs/auth.log',
    'Boot Log': '/app/logs/boot.log',
    'DPKG Log': '/app/logs/dpkg.log',
}

@dashboard_bp.route('/')
def dashboard():
    logs = {}
    for name, path in LOG_FILES.items():
        try:
            with open(path, 'r') as f:
                logs[name] = f.read()
        except Exception as e:
            logs[name] = f"Error reading {path}: {str(e)}"
    return render_template('dashboard.html', logs=logs)

