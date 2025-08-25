# app/utils/auth_utils.py
from flask import request
from app.utils.jwt_utils import verify_jwt



def get_current_user():
    token = request.cookies.get('access_token')
    if not token:
        return None
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return {'username': decoded.get('username'), 'role': decoded.get('role')}
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

