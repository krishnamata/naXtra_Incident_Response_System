import os
from flask import Blueprint, render_template, send_from_directory

agents_bp = Blueprint('agents', __name__, template_folder='templates')

@agents_bp.route('/')
def index():
    return render_template('/agent_management.html')  # or wherever your UI template is


@agents_bp.route('/management')
def management():
    return render_template('agent_management.html')

@agents_bp.route('/linux')
def linux():
    os_logs = {
        "auth": "",
        "syslog": "",
        "journal": ""
    }

    return render_template(
        'linux_agent_deploy.html',
        os_logs=os_logs,
        os_name="linux"
    )



@agents_bp.route('/windows')
def windows():
    return render_template('windows_agent.html')


@agents_bp.route('/network')
def network():
    return "Log Forwarding Guide - Coming Soon"
