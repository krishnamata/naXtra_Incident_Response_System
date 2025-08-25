from functools import wraps
from flask import request, redirect, url_for, flash, abort

def permission_required(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_info = getattr(request, 'user', None)
            if not user_info:
                flash("Not authenticated", "danger")
                return redirect(url_for('auth.login'))

            permissions = user_info.get('permissions', {})
            if not permissions.get(permission, False):
                flash("Permission denied", "danger")
                return abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator


from functools import wraps
from flask import request, jsonify
from app.models import User
from app.extensions import db

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = getattr(request, 'user', None)
        if not user or not user.role or user.role != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated_function
