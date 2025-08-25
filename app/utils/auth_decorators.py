# app/utils/auth_decorators.py
from functools import wraps
from flask import g, request, redirect, url_for, make_response, current_app, abort
from flask_jwt_extended import verify_jwt_in_request, get_jwt, get_jwt_identity
import jwt

# Gracefully handle login route
EXEMPT_ROUTES = ['/login', '/static']



def permission_required(permission):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            user_info = getattr(request, 'user', None)
            if not user_info:
                current_app.logger.warning("No user info found in request")
                abort(403)

            perms = user_info.get("permissions", {})
            current_app.logger.info(f"Checking permission {permission} against: {perms}")
            if not perms.get(permission, False):
                current_app.logger.warning(f"Permission '{permission}' not granted")
                abort(403)

            return func(*args, **kwargs)
        return wrapper
    return decorator



def login_required(fn):
    @wraps(fn)
    def decorated_function(*args, **kwargs):
        try:
            verify_jwt_in_request()
            return fn(*args, **kwargs)
        except Exception:
            if request.path not in EXEMPT_ROUTES:
                return redirect(url_for('auth.login'))
            return fn(*args, **kwargs)
    return decorated_function

from app.models import User  # Ensure correct import

def jwt_required(admin_only=False):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                verify_jwt_in_request()
                claims = get_jwt()
                g.user = {
                    "username": get_jwt_identity(),
                    "role": claims.get("role")
                }
                if admin_only and claims.get("role") != 'admin':
                    abort(403)
            except Exception as e:
                current_app.logger.warning(f"JWT validation failed: {e}")
                abort(403)
            return func(*args, **kwargs)
        return wrapper
    return decorator
