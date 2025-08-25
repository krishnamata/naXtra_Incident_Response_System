from flask import Blueprint, jsonify
from app.dlp import detect_logs_and_generate_alerts

dlp_bp = Blueprint('dlp', __name__)

@dlp_bp.route('/run-dlp', methods=['POST'])
def run_dlp_route():
    detect_logs_and_generate_alerts()
    return jsonify({"status": "DLP run completed"}), 200
