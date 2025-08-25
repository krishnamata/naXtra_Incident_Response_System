from flask import (
    Blueprint, render_template, request, redirect, url_for, flash, session, current_app
)
from app.forms import AddUserForm
from werkzeug.security import generate_password_hash, check_password_hash
from app.models import User
from app.extensions import db
from app.utils.permissions_loader import load_role_permissions
from app.email_utils import send_email  # Your email helper if you use it
from app.utils.enums import UserStatus 
from datetime import datetime

auth_bp = Blueprint('auth', __name__, template_folder='templates')
role_permissions = load_role_permissions()
roles = role_permissions.get('roles', {}).keys()

from flask import request, flash, redirect, url_for, render_template
from flask_login import login_user
from werkzeug.security import check_password_hash
from app.models import User




@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        user = User.query.filter_by(username=username).first()

        if not user:
            flash('Invalid username or password.', 'danger')
            return redirect(url_for('auth.login'))

        if user.status != 'active':
            flash('Your account is not active. Please contact admin.', 'danger')
            return redirect(url_for('auth.login'))

        if not check_password_hash(user.password_hash, password):
            flash('Invalid username or password.', 'danger')
            return redirect(url_for('auth.login'))

        # Set session manually instead of login_user
        session['user_id'] = user.id
        session['username'] = user.username
        session['role'] = user.role

        flash('Logged in successfully.', 'success')
        return redirect(url_for('dashboard.dashboard'))  # Adjust as per your app

    return render_template('login.html')




@auth_bp.route('/users', methods=['GET'])
#@jwt_required(admin_only=True)
def manage_users():
    roles = role_permissions.get('roles', {}).keys()
    users = User.query.filter_by(status='active').all()
    form = AddUserForm()
    return render_template('user_management.html', users=users, roles=roles, role_permissions=role_permissions, form=form)
from datetime import datetime

@auth_bp.route('/users/add', methods=['POST'])
def add_user():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    role = request.form.get('role', 'user').strip().lower()
    office_email = request.form.get('office_email', '').strip()
    contact_number = request.form.get('contact_number', '').strip()
    

    # Backend validation
    if not username:
        flash('Username is required.', 'danger')
        return redirect(url_for('auth.add_user_form'))

    if not password:
        flash('Password is required.', 'danger')
        return redirect(url_for('auth.add_user_form'))

    valid_roles = [r.lower() for r in role_permissions.get('roles', {}).keys()]
    if role not in valid_roles:
        flash('Invalid role selected.', 'danger')
        return redirect(url_for('auth.manage_users'))

    if User.query.filter_by(username=username).first():
        flash('Username already exists.', 'danger')
        return redirect(url_for('auth.manage_users'))

    import re
    email_regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    if not re.match(email_regex, office_email):
        flash('Invalid email format.', 'danger')
        return redirect(url_for('auth.manage_users'))

    if User.query.filter_by(office_email=office_email).first():
        flash('Email already in use.', 'danger')
        return redirect(url_for('auth.manage_users'))

    # Create and save user
    user = User(
        username=username,
        role=role,
        office_email=office_email,
        contact_number=contact_number,
        status='active',
        created_at=datetime.utcnow()
    )
    user.set_password(password)

    db.session.add(user)
    db.session.commit()

    flash('User added successfully.', 'success')
    return redirect(url_for('auth.manage_users'))



@auth_bp.route('/users/delete/<int:user_id>', methods=['POST'])
#@jwt_required(admin_only=True)
def delete_user(user_id):
    user = User.query.get(user_id)
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('auth.manage_users'))
    if user.username == 'admin':
        flash('Cannot delete main admin user.', 'danger')
        return redirect(url_for('auth.manage_users'))

    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully.', 'success')
    return redirect(url_for('auth.manage_users'))


@auth_bp.route('/users/reset/<int:user_id>', methods=['POST'])
#@jwt_required(admin_only=True)
def reset_password(user_id):
    user = User.query.get(user_id)
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('auth.manage_users'))

    user.set_password('default123')
    db.session.commit()
    flash(f"Password for {user.username} has been reset to 'default123'", 'success')
    return redirect(url_for('auth.manage_users'))


@auth_bp.route('/users/update/<int:user_id>', methods=['POST'])
def update_user(user_id):
    form_data = request.form.copy()
    current_app.logger.info(f"Form data: {form_data}")
    user = User.query.get_or_404(user_id)

    new_username = request.form.get('new_username', '').strip()
    new_role = request.form.get('new_role', '').strip()
    new_email = request.form.get('new_email', '').strip()
    new_status = request.form.get('new_status', '').strip().lower()

    # Validate role
    if new_role not in role_permissions.get('roles', {}).keys():
        flash('Invalid role selected.', 'danger')
        return redirect(url_for('auth.manage_users'))

    # Validate status
    valid_statuses = ['active', 'disabled', 'pending']
    if new_status not in valid_statuses:
        flash('Invalid status selected.', 'danger')
        return redirect(url_for('auth.manage_users'))

    # Validate username uniqueness
    if new_username != user.username and User.query.filter_by(username=new_username).first():
        flash('Username already taken.', 'danger')
        return redirect(url_for('auth.manage_users'))

    # Validate email format (simple regex)
    import re
    email_regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    if not re.match(email_regex, new_email):
        flash('Invalid email format.', 'danger')
        return redirect(url_for('auth.manage_users'))

    # Validate email uniqueness
    if new_email != user.personal_email and User.query.filter_by(personal_email=new_email).first():
        flash('Email already in use.', 'danger')
        return redirect(url_for('auth.manage_users'))

    # Update fields
    user.username = new_username
    user.role = new_role
    user.personal_email = new_email
    user.status = new_status

    db.session.commit()
    flash('User updated successfully.', 'success')
    return redirect(url_for('auth.manage_users'))




@auth_bp.route('/pending-users')
def pending_users():
    # Fetch users with status 'pending'
    pending = User.query.filter_by(status='pending').all()
    return render_template('pending_users.html', users=pending)




@auth_bp.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))


@auth_bp.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        email = request.form.get('email', '').strip()
        cell = request.form.get('cell', '').strip()

        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return redirect(url_for('auth.signup'))

        new_user = User(
            username=username,
            email=email,
            cell=cell,
            role='user',
            status='pending'
        )
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        # Notify admin email about new signup request
        admin_email = current_app.config.get('ADMIN_EMAIL')
        if admin_email:
            send_email(
                to=admin_email,
                subject='New Signup Request',
                template='email/admin_notification.html',
                user=new_user
            )

        flash('Signup successful. Your request is pending admin approval.', 'info')
        return redirect(url_for('auth.login'))

    return render_template('auth/signup.html')


@auth_bp.route('/profile')
def profile():
    if 'username' not in session:
        flash('Please login first.', 'warning')
        return redirect(url_for('auth.login'))

    return render_template('profile.html', username=session.get('username'), role=session.get('role'))


@auth_bp.route('/tasks')
def tasks_view():
    if 'username' not in session:
        flash('Please login first.', 'warning')
        return redirect(url_for('auth.login'))

    return render_template('tasks.html')

@auth_bp.route('/users/approve/<int:user_id>', methods=['POST'])
def approve_user(user_id):
    user = User.query.get_or_404(user_id)
    user.status = 'active'
    db.session.commit()
    flash(f'User {user.username} approved successfully.', 'success')
    return redirect(url_for('auth.pending_users'))

@auth_bp.route('/users/reject/<int:user_id>', methods=['POST'])
def reject_user(user_id):
    user = User.query.get_or_404(user_id)

    # ✅ Render the template manually
    body = render_template('email/rejection.html', user=user)

    # ✅ Call send_email with correct arguments
    send_email(
        to=user.personal_email,  # or user.email if that's your model
        subject="Signup Request Rejected",
        body=body
    )

    # Delete user
    db.session.delete(user)
    db.session.commit()

    flash(f'User {user.username} rejected and deleted.', 'info')
    return redirect(url_for('auth.pending_users'))


@auth_bp.route('/users/pre_approve/<int:user_id>', methods=['GET', 'POST'])
def pre_approve_user(user_id):
    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        office_email = request.form.get('office_email', '').strip()
        contact_number = request.form.get('contact_number', '').strip()
        created_at_str = request.form.get('created_at', '').strip()

        # Validate
        if not office_email or not contact_number or not created_at_str:
            flash("All fields are required.", 'danger')
            return redirect(url_for('auth.pre_approve_user', user_id=user.id))

        try:
            from datetime import datetime
            created_at = datetime.strptime(created_at_str, '%Y-%m-%dT%H:%M')
        except ValueError:
            flash("Invalid datetime format.", 'danger')
            return redirect(url_for('auth.pre_approve_user', user_id=user.id))

        # Update user
        user.office_email = office_email
        user.contact_number = contact_number
        user.created_at = created_at
        user.status = 'approved'

        db.session.commit()
        flash(f"User {user.username} pre-approved successfully.", 'success')
        return redirect(url_for('auth.manage_users'))

    return render_template('pre_approve_user.html', user=user)





# Add more routes as needed, using `session` for authentication checks.
