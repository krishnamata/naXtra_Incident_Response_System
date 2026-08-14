from flask import request, jsonify, Blueprint
from app.utils.fim_helpers import handle_fim_log
import logging

# Initialize Blueprint
fim_bp = Blueprint('fim_bp', __name__)

# Logger Setup
logger = logging.getLogger(__name__)

@fim_bp.route('/api/logs/fim', methods=['POST'])
def receive_fim():
    try:
        fim_data = request.get_json(silent=True) or {}

        # Handle FIM Log
        result = handle_fim_log(fim_data)

        return jsonify({"status": "success", "message": result}), 201
    except Exception as e:
        logger.error("Error in receive_fim: %s", e, exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@fim_bp.route('/test', methods=['GET'])
def test():
    return "FIM blueprint works!", 200
