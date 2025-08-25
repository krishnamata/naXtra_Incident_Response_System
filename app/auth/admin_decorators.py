from functools import wraps
from flask import session, redirect, url_for, flash

def role_required(required_role):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if  session.get('role') != 'required_role':
            flash(f"{required_role.capitalize()} access required.", "danger")
            return redirect(url_for('auth.login'))  # Adjust if your login route is named differently
        return f(*args, **kwargs)
    return decorated_function
