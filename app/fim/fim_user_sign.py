import os
import hashlib
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from app import create_app
from app.extensions import db
from app.models import FimBaseline

# Path to private key (PEM)
PRIVATE_KEY_FILE = "keys/private_key.pem"

def load_private_key(path):
    with open(path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    return private_key

def compute_sha256(file_path):
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        print(f"[ERROR] Cannot hash {file_path}: {e}")
        return None

def sign_hash(file_hash, private_key):
    signature = private_key.sign(
        file_hash.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature.hex()  # store as hex string

def user_sign_file(file_path):
    if not os.path.isfile(file_path):
        print(f"[ERROR] File does not exist: {file_path}")
        return

    private_key = load_private_key(PRIVATE_KEY_FILE)
    file_hash = compute_sha256(file_path)
    signature = sign_hash(file_hash, private_key)

    app = create_app()
    with app.app_context():
        entry = FimBaseline(
            file_path=file_path,
            hash_sha256=file_hash,
            hash_algo="SHA256",
            signature_status="UserSigned",
            signature_hex=signature,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        db.session.add(entry)
        db.session.commit()
        print(f"[OK] File signed and added to baseline: {file_path}")
        print(f"SHA256: {file_hash}")
        print(f"Signature: {signature[:32]}...")

if __name__ == "__main__":
    file_path = input("Enter file path to sign: ").strip()
    user_sign_file(file_path)
