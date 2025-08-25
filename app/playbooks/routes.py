# app/playbook/routes.py

from flask import Blueprint, request, session, abort, jsonify
from app.automation.dispatcher import isolate_system


playbook_bp = Blueprint('playbook', __name__)

@playbook_bp.route('/execute_step', methods=['POST'])
def execute_step():
    if not session.get('is_admin'):
        abort(403)  # Only admins can run automated steps

    step = request.form.get('step')
    target = request.form.get('target')

    if not step or not target:
        return jsonify({'status': 'error', 'message': 'Missing parameters'}), 400

    # Example: simulate isolation logic
    if step == 'isolate_host':
        # Here you'd call your isolation logic, e.g., API or system command
        print(f"[ACTION] Isolating host: {target}")
        return jsonify({'status': 'success'if status == 200 else 'error', 'message': response})


    return jsonify({'status': 'error', 'message': 'Unknown step'}), 400
