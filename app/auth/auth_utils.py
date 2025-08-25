# app/auth/auth_utils.py
from werkzeug.security import check_password_hash, generate_password_hash

def verify_password(plain_password, hashed_password):
    return check_password_hash(hashed_password, plain_password)

def hash_password(password):
    return generate_password_hash(password)

# Add other auth utility functions here if needed
