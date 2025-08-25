import jwt
import logging
import datetime
from flask import current_app

def generate_jwt(user_id, username, role):
    secret = current_app.config.get("JWT_SECRET_KEY", "naxtra-secret-key")
    algorithm = current_app.config.get("JWT_ALGORITHM", "HS256")
    exp_minutes = current_app.config.get("JWT_EXP_DELTA_MINUTES", 540)  # default to 9 hours

    payload = {
        "username": user.username,
        "role": user.role,
        "exp": datetime.utcnow() + timedelta(minutes=1)
    }
    token = jwt.encode(payload, current_app.config['JWT_SECRET_KEY'], algorithm='HS256')
    return token


def verify_jwt(token):
    try:
        decoded = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
        current_app.logger.info(f"JWT verified: {decoded}")
        return decoded
    except Exception as e:
        current_app.logger.warning(f"JWT verification error: {e}")
        return None
