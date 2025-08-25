from sqlalchemy.orm import joinedload
from flask import request, render_template, session, redirect, url_for, jsonify, Blueprint
from sqlalchemy import asc, desc, cast, Integer, func
from markupsafe import Markup
from app.models import Alert, User, AlertStepWork, AlertEvidence, AlertHistory
from app.extensions import db
from app.rules.rules_loader import load_rules, parse_rule_description
from app.models import AlertStepWork
from werkzeug.utils import secure_filename
from app.playbooks.dispatcher import dispatch_playbook, assign_playbook_to_alert
from app.utils.mitre import get_mitre_info
from app.dlp import detect_logs_and_generate_alerts, NIST_STEPS
from app.integrations.ioc_enrichment import enrich_ioc
import logging
import time
import hashlib
import os
import json

logger = logging.getLogger(__name__)

alerts_bp = Blueprint('alerts', __name__, template_folder='templates', url_prefix='/alerts')


# -------------------------------
# Add Evidence to Alert Step
# -------------------------------

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "pdf", "txt", "log"}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@alerts_bp.route("/<int:alert_id>/step/<int:step_id>/add_evidence", methods=["POST"])
def add_alert_evidence(alert_id, step_id):
    try:
        if 'user_id' not in session:
            return jsonify({"success": False, "message": "Login required"}), 403

        step = AlertStepWork.query.filter_by(id=step_id, alert_id=alert_id).first()
        if not step:
            return jsonify({"success": False, "message": "Step not found"}), 404

        evidence_text = request.form.get("notes")
        file = request.files.get("file")
        file_path, file_hash = None, None

        if file:
            filename = secure_filename(file.filename)
            if not allowed_file(filename):
                return jsonify({"success": False, "message": "File type not allowed"}), 400

            timestamp = time.strftime("%Y%m%d_%H%M%S")
            filename = f"{timestamp}_{filename}"

            upload_folder = os.path.join("uploads", "alert_evidence", str(alert_id))
            os.makedirs(upload_folder, exist_ok=True)
            file_path = os.path.join(upload_folder, filename)
            file.save(file_path)

            with open(file_path, "rb") as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()

        # Save evidence
        evidence = AlertEvidence(
            step_id=step.id,
            evidence_text=evidence_text,
            file_path=file_path,
            file_hash=file_hash,
            uploaded_by=session['user_id']
        )
        db.session.add(evidence)

        # Audit trail
        details = f"Evidence added to step {step.sub_step}"
        if file_path:
            details += f" | File: {file_path} | Hash: {file_hash}"

        history = AlertHistory(
            alert_id=alert_id,
            action="added_evidence",
            details=details,
            performed_by=session['user_id']
        )
        db.session.add(history)
        db.session.commit()

        return jsonify({"success": True, "message": f"Evidence added to step '{step.sub_step}'"})

    except Exception as e:
        # Log full exception
        logger.exception(f"Error adding evidence for alert {alert_id}, step {step_id}: {e}")
        return jsonify({"success": False, "message": "An unexpected error occurred. Please try again."}), 500




@alerts_bp.route("/<int:alert_id>/steps_partial")
def alert_steps_partial(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    non_admin_users = User.query.filter(User.role != 'admin').all()
    return render_template("alerts_steps_partial.html", alert=alert, non_admin_users=non_admin_users)




# -------------------------------
# Update Alert Step Status
# -------------------------------
@alerts_bp.route("/<int:alert_id>/step/<int:step_id>/update_status", methods=["POST"])
def update_alert_step_status(alert_id, step_id):
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    step = AlertStepWork.query.filter_by(id=step_id, alert_id=alert_id).first_or_404()
    new_status = request.form.get("status")
    notes = request.form.get("notes")

    step.status = new_status
    if notes:
        step.notes = notes
    step.updated_by = session['user_id']

    # Log history
    history = AlertHistory(
        alert_id=alert_id,
        action=f"step_{new_status}",
        details=f"Step {step.sub_step} marked {new_status}",
        performed_by=session['user_id']
    )
    db.session.add(history)
    db.session.commit()

    return jsonify({"success": True, "message": f"Step updated to {new_status}"})


# -------------------------------
# Restore False Positive Alert Step
# -------------------------------
@alerts_bp.route("/<int:alert_id>/step/<int:step_id>/restore", methods=["POST"])
def restore_alert_step(alert_id, step_id):
    if 'user_id' not in session or session.get('role') not in ['admin', 'senior_analyst']:
        return jsonify({"success": False, "message": "Unauthorized"}), 403

    step = AlertStepWork.query.filter_by(id=step_id, alert_id=alert_id).first_or_404()
    previous_status = step.status
    step.status = "pending"

    # Log history
    history = AlertHistory(
        alert_id=alert_id,
        action="restored_step",
        details=f"Step {step.sub_step} restored from {previous_status}",
        performed_by=session['user_id']
    )
    db.session.add(history)
    db.session.commit()

    return jsonify({"success": True, "message": f"Step restored from {previous_status}"})


# -------------------------------
# List All Steps & Evidence for Alert
# -------------------------------
@alerts_bp.route("/<int:alert_id>/steps")
def get_alert_steps(alert_id):
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    steps = AlertStepWork.query.filter_by(alert_id=alert_id).all()
    data = []
    for step in steps:
        evidences = [{
            "id": e.id,
            "type": e.evidence_type,
            "text": e.evidence_text,
            "file_path": e.file_path,
            "uploaded_by": User.query.get(e.uploaded_by).username if e.uploaded_by else None,
            "uploaded_at": e.uploaded_at
        } for e in step.evidences]

        data.append({
            "step_id": step.id,
            "nist_phase": step.nist_phase,
            "sub_step": step.sub_step,
            "status": step.status,
            "notes": step.notes,
            "updated_by": User.query.get(step.updated_by).username if step.updated_by else None,
            "updated_at": step.updated_at,
            "evidences": evidences
        })

    return jsonify({"steps": data})


@alerts_bp.route('/api/new_alerts_count')
def new_alerts_count_api():
    count = Alert.query.filter_by(is_new=True).count()
    return jsonify({'new_alert_count': count})


@alerts_bp.route("/escalate/<int:alert_id>", methods=["POST"])
def escalate_alert(alert_id):
    if 'user_id' not in session or session.get('role') == 'admin':
        return jsonify({"success": False, "message": "Unauthorized"}), 403

    alert = Alert.query.get_or_404(alert_id)

    if not alert.is_escalated:
        alert.is_escalated = True
        senior_analyst = User.query.filter(User.role == "senior_analyst").first()
        if senior_analyst:
            alert.assigned_to_id = senior_analyst.id
        db.session.commit()
        return jsonify({"success": True, "message": "Alert escalated"})
    else:
        return jsonify({"success": False, "message": "Alert already escalated"})




@alerts_bp.route('/notifications')
def alert_notifications():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    new_alerts = Alert.query.filter_by(is_new=True).order_by(Alert.detected_time.desc()).all()
    return render_template('alerts_notifications.html', alerts=new_alerts)


@alerts_bp.route("/assign/<int:alert_id>", methods=["POST"])
def assign_alert(alert_id):
    user_id = request.form.get("user_id")
    alert = Alert.query.get_or_404(alert_id)
    if user_id:
        alert.assigned_to_id = user_id
        db.session.commit()
    return redirect(url_for("alerts.view_alerts"))


@alerts_bp.route('/')
def view_alerts():
    agent_name = request.args.get('agent_name', None)
    page = request.args.get('page', 1, type=int)
    sort_by = request.args.get('sort_by', 'severity')
    sort_order = request.args.get('sort_order', 'desc')
    show_malware = request.args.get("malware", "false").lower() == "true"

    # Base query
    query = db.session.query(Alert).options(joinedload(Alert.playbook))
    query = query.filter(Alert.is_malware == show_malware)
    if agent_name:
        query = query.filter(func.lower(Alert.agent_name) == agent_name.lower())
    if 'user_id' in session and session.get('role') != 'admin':
        query = query.filter(Alert.assigned_to_id == session['user_id'])

    # Sorting
    order_column = Alert.detected_time if sort_by == 'time' else cast(Alert.severity, Integer)
    query = query.order_by(desc(order_column), Alert.detected_time.desc()) if sort_order != 'asc' else query.order_by(asc(order_column), Alert.detected_time.desc())

    pagination = query.paginate(page=page, per_page=20, error_out=False)
    alerts_page = pagination.items

    enriched_alerts = []
    for alert in alerts_page:
        # Seed missing steps if none exist
        steps_worked = AlertStepWork.query.filter_by(alert_id=alert.id).all()
        if not steps_worked:
            from app.dlp import seed_nist_steps
            seed_nist_steps(alert.id, created_by="system")
            steps_worked = AlertStepWork.query.filter_by(alert_id=alert.id).all()

        worked_dict = {f"{s.nist_phase}-{s.sub_step}": s for s in steps_worked}

        # Select steps based on role
        role = session.get("role")
        remedy_steps = NIST_STEPS.get(role, []) if role in ["analyst", "senior_analyst", "admin"] else []

        step_summaries = []
        for step in remedy_steps:
            key = f"{step['nist_phase']}-{step['sub_step']}"
            if key in worked_dict:
                s = worked_dict[key]
                evidence_count = len(s.evidences)
                updated_by_user = User.query.get(s.updated_by).username if s.updated_by and User.query.get(s.updated_by) else "-"
                reviewer_user = User.query.get(s.reviewed_by).username if s.reviewed_by and User.query.get(s.reviewed_by) else "-"
                step_summaries.append({
                    "step_id": s.id,
                    "nist_phase": step["nist_phase"],
                    "sub_step": step["sub_step"],
                    "status": s.status,
                    "updated_by": updated_by_user,
                    "reviewer": reviewer_user,
                    "review_status": getattr(s, "review_status", None),
                    "updated_at": s.updated_at,
                    "evidence_count": evidence_count
                })
            else:
                # Should not happen, fallback
                step_summaries.append({
                    "step_id": None,
                    "nist_phase": step["nist_phase"],
                    "sub_step": step["sub_step"],
                    "status": "pending",
                    "updated_by": "-",
                    "reviewer": "-",
                    "review_status": None,
                    "updated_at": None,
                    "evidence_count": 0
                })

        assigned_to = getattr(alert.assigned_to_user, "username", "-")
        enriched_alerts.append({
            "id": alert.id,
            "detected_time": alert.detected_time,
            "description": Markup(alert.description or "-"),
            "step_objects": steps_worked,
            "step_summaries": step_summaries,
            "rule_id": getattr(alert, "rule_id", None),
            "level": alert.severity,
            "agent_name": alert.agent_name,
            "assigned_to": assigned_to,
            "status": alert.status,
        })

    non_admin_users = User.query.filter(User.role != 'admin').all()

    if request.args.get("ajax") == "true":
        return render_template(
            'alerts_table_rows.html',
            alerts=enriched_alerts,
            show_malware=show_malware,
            non_admin_users=non_admin_users
        )

    agent_names = [name[0] for name in db.session.query(Alert.agent_name).distinct().all() if name[0] is not None]
    return render_template(
        'alerts.html',
        alerts=enriched_alerts,
        agent_names=agent_names,
        pagination=pagination,
        non_admin_users=non_admin_users,
        selected_agent=agent_name,
        show_malware=show_malware
    )







@alerts_bp.route("/dlp-run")
def run_dlp_manually():
    print("[DEBUG] /dlp-run route accessed")
    run_dlp()
    return "DLP triggered manually"
