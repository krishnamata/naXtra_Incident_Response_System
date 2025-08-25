from flask import current_app
from datetime import datetime, timedelta
import json

tasks_bp = Blueprint('tasks', __name__, url_prefix='/tasks')


# -------------------------------
# Utility: get least loaded user
# -------------------------------
def get_least_loaded_user(role='analyst'):
    users = User.query.filter_by(role=role).all()
    if not users:
        return None
    user_load = {u.id: Tasks.query.filter_by(assigned_to=u.id, status='pending').count() for u in users}
    return min(user_load, key=user_load.get)


# -------------------------------
# View tasks page
# -------------------------------


@tasks_bp.route('/', methods=['GET'])
def view_tasks():
    print("start view_tasks")
    current_user_id = session.get('user_id')
    role = session.get('role')
    if not current_user_id:
        return "User not logged in", 401

    # Tasks for current user
    tasks_query = Tasks.query.options(joinedload(Tasks.assigned_user))\
                             .filter(Tasks.assigned_to == current_user_id).all()
    tasks_list = [{
        'task_id': t.task_id,
        'type': t.type,
        'content_id': t.content_id,
        'assigned_to_username': t.assigned_user.username if t.assigned_user else 'N/A',
        'priority': t.priority,
        'status': t.status,
        'notes': t.notes or ''
    } for t in tasks_query]

    # Agents list from logs and alerts
    log_agents = [row[0] for row in db.session.query(LogEntry.source).distinct()]
    alert_agents = [row[0] for row in db.session.query(Alert.agent_name).distinct()]
    all_agents = sorted([a for a in set(log_agents + alert_agents) if a is not None])
    current_app.logger.info(f"Agents list: {all_agents}")

    return render_template('tasks.html', tasks=tasks_list, role=role, agents=all_agents)


@tasks_bp.route('/get_my_tasks', methods=['GET'], endpoint= 'get_my_tasks_json')
def get_my_tasks():
    current_user_id = session.get('user_id')
    if not current_user_id:
        return jsonify([])

    tasks_query = Tasks.query.options(joinedload(Tasks.assigned_user), joinedload(Tasks.created_user))\
                             .filter(Tasks.assigned_to == current_user_id).all()

    tasks_list = []
    for t in tasks_query:
        assigned_username = t.assigned_user.username if t.assigned_user else "N/A"
        agent_name = timestamp = description = '-'

        if t.type == 'log':
            log_entry = LogEntry.query.get(t.content_id)
            if log_entry:
                agent_name = log_entry.source
                timestamp = log_entry.timestamp.strftime("%Y-%m-%d %H:%M:%S")
                description = log_entry.message or ''
        elif t.type == 'alert':
            alert = Alert.query.get(t.content_id)
            if alert:
                agent_name = alert.agent_name
                timestamp = alert.detected_time.strftime("%Y-%m-%d %H:%M:%S")
                description = alert.description or alert.rule_title or ''

        tasks_list.append({
            'task_id': t.task_id,
            'type': t.type,
            'content_id': t.content_id,
            'assigned_to_username': assigned_username,
            'agent_name': agent_name,
            'timestamp': timestamp,
            'description': description,
            'priority': t.priority,
            'status': t.status,
            'notes': t.notes or ''
        })

    return jsonify(tasks_list)




# -------------------------------
# Assign single log/alert as task
# -------------------------------
@tasks_bp.route('/assign_task_single', methods=['POST'])
def assign_task_single():
    content_id = request.form.get('content_id')
    type_ = request.form.get('type')

    # Check if a task already exists
    existing_task = Tasks.query.filter_by(type=type_, content_id=content_id).first()
    if existing_task:
        assigned_user = User.query.get(existing_task.assigned_to)
        return jsonify({
            'message': f'Task already assigned to {assigned_user.username if assigned_user else "Auto-assign"}',
            'task': {
                'task_id': existing_task.task_id,
                'type': existing_task.type,
                'content_id': existing_task.content_id,
                'assigned_to_username': assigned_user.username if assigned_user else 'Auto-assign',
                'priority': existing_task.priority,
                'status': existing_task.status,
                'notes': existing_task.notes or ''
            },
            'assigned_to_id': existing_task.assigned_to
        })

    # Auto-assign if not selected
    assigned_to = request.form.get('assigned_to') or get_least_loaded_user(
        role='senior analyst' if type_ == 'alert' else 'analyst'
    )
    created_by = session.get('user_id')

    task = Tasks(
        type=type_,
        content_id=content_id,
        assigned_to=assigned_to,
        created_by=created_by,
        status='pending'
    )
    db.session.add(task)
    db.session.commit()

    assigned_user = User.query.get(assigned_to)

    return jsonify({
        'message': f'Task {type_} {content_id} assigned successfully',
        'task': {
            'task_id': task.task_id,
            'type': task.type,
            'content_id': task.content_id,
            'assigned_to_username': assigned_user.username if assigned_user else 'Auto-assign',
            'priority': task.priority,
            'status': task.status,
            'notes': task.notes or ''
        },
        'assigned_to_id': assigned_to
    })


# -------------------------------
# Polling: get tasks for current user
# -------------------------------



@tasks_bp.route('/upload_evidence', methods=['POST'])
def upload_evidence():
    step_id = request.form.get('step_id')
    text = request.form.get('text', '')
    file = request.files.get('file')
    
    step = TaskStep.query.get(step_id)
    if not step:
        return jsonify({'error': 'Step not found'}), 404
    
    if text:
        step.evidence_text = text
    if file:
        filename = secure_filename(file.filename)
        file.save(os.path.join(current_app.config['UPLOAD_FOLDER'], filename))
        step.evidence_file = filename
    
    step.completed = True
    db.session.commit()
    return jsonify({'message': 'Evidence uploaded and step marked complete'})



def flatten_to_bullets(obj):
    """Flatten dicts/lists into HTML bullet points for readable description."""
    if isinstance(obj, dict):
        items = []
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                items.append(f"<strong>{k}:</strong><ul>{flatten_to_bullets(v)}</ul>")
            else:
                items.append(f"<li><strong>{k}:</strong> {v}</li>")
        return ''.join(items)
    elif isinstance(obj, list):
        items = []
        for i, v in enumerate(obj):
            if isinstance(v, (dict, list)):
                items.append(f"<ul>{flatten_to_bullets(v)}</ul>")
            else:
                items.append(f"<li>{v}</li>")
        return ''.join(items)
    else:
        return f"<li>{obj}</li>"

# -------------------------------
# Polling: get items for admin


@tasks_bp.route('/get_items', methods=['GET'])
def get_items():
    current_user_id = session.get('user_id')
    current_role = session.get('role')
    if not current_user_id:
        return jsonify({'items': [], 'users': []})

    item_type = request.args.get('type', 'log')
    agent_filter = request.args.get('agent', None)

    # Base query
    if item_type == 'log':
        query = LogEntry.query
    elif item_type == 'alert':
        query = Alert.query
    else:
        return jsonify({'error': 'Invalid type'}), 400

    if agent_filter:
        if item_type == 'log':
            query = query.filter(LogEntry.source == agent_filter)
        else:
            query = query.filter(Alert.agent_name == agent_filter)

    # Preload tasks to minimize DB hits
    tasks_map = {t.content_id: t for t in Tasks.query.filter_by(type=item_type).all()}

    items = []
    for obj in query.all():
        task = tasks_map.get(obj.id)
        assigned_user = task.assigned_user.username if task and task.assigned_user else None
        status = task.status if task else 'pending'

        # Skip unassigned tasks for non-admin
        if current_role != 'admin' and (not task or task.assigned_to != current_user_id):
            continue

        if item_type == 'log':
            agent_name = obj.source
            timestamp = obj.timestamp
            description = json.dumps(obj.raw_log or {}, indent=2)
            playbook_steps = []
            rule_id = None
            technique_id = None
            mitre_link = None
            ioc_enrichment = {}
        else:
            agent_name = obj.agent_name
            timestamp = obj.detected_time
            description = obj.description or obj.rule_title or ''

            # Assign playbook and get steps if not already assigned
            if not getattr(obj, "playbook_steps", None):
                assign_playbook_to_alert(obj)
                playbook_steps = dispatch_playbook(obj) or []
            else:
                playbook_steps = obj.playbook_steps

            rule_id = getattr(obj, 'rule_id', None)
            technique_id = getattr(obj, 'technique_id', None)
            ioc_enrichment = getattr(obj, 'ioc_enrichment', {})

            # MITRE link
            if technique_id and technique_id != 'NA':
                mitre_link = f"https://attack.mitre.org/techniques/{technique_id}/"
                mitre_info = get_mitre_info(technique_id)
            else:
                mitre_link = None
                mitre_info = None

        items.append({
            'id': obj.id,
            'agent_name': agent_name or '-',
            'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S') if timestamp else '-',
            'description': description,
            'status': status,
            'assigned_to': assigned_user or '-',
            'assigned_to_id': task.assigned_to if task else None,
            'playbook_steps': playbook_steps,
            'rule_id': rule_id,
            'technique_id': technique_id,
            'mitre_link': mitre_link,
            'mitre_info': mitre_info,
            'ioc_enrichment': ioc_enrichment
        })

    # Admin users: return list of analysts for assignment
    users_list = []
    if current_role == 'admin':
        users = User.query.filter(User.role.in_(['analyst', 'senior analyst'])).all()
        users_list = [{'id': u.id, 'username': u.username} for u in users]

    return jsonify({'items': items, 'users': users_list})
