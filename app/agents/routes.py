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
    return render_template('linux_agent_deploy.html')

@agents_bp.route('/download/linux')
def download_linux_agent():
    agent_dir = '/var/www/modular-soar/app/agents/linux_agents/'  # assumes folder is in project root
    return send_from_directory(agent_dir, 'linux_agent.tar.gz', as_attachment=True)





@agents_bp.route('/windows')
def windows():
    return render_template('windows_agent.html')

@agents_bp.route('/mac')
def mac():
    return "macOS Agent Deployment - Coming Soon"

@agents_bp.route('/network')
def network():
    return "Log Forwarding Guide - Coming Soon"
