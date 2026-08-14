from app.models import FimBaseline, FimEvent
from app.extensions import db
import hashlib
import os
from datetime import datetime
import pwd, stat

def calculate_file_hash(file_path):
    """Compute SHA-256 hash of a file safely."""
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (PermissionError, FileNotFoundError) as e:
        print(f"[WARN] Cannot hash {file_path}: {e}")
        return None

def get_file_metadata(file_path):
    """Return owner, permissions, and size info."""
    try:
        st = os.stat(file_path)
        owner = pwd.getpwuid(st.st_uid).pw_name if hasattr(pwd, "getpwuid") else str(st.st_uid)
        permissions = oct(st.st_mode)[-3:]
        size_kb = st.st_size // 1024
        return owner, permissions, size_kb
    except Exception as e:
        return "-", "-", 0

def add_baseline(file_path):
    """Add a file to the baseline dynamically."""
    if not os.path.isfile(file_path):
        print(f"[WARN] Skipping non-file {file_path}")
        return None

    file_hash = calculate_file_hash(file_path)
    if not file_hash:
        return None

    owner, permissions, size_kb = get_file_metadata(file_path)

    baseline = FimBaseline(
        file_path=file_path,
        hash_sha256=file_hash,
        hash_algo="SHA256",
        owner=owner,
        permissions=permissions,
        size=size_kb,
        signature_status="Unknown",
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )
    db.session.add(baseline)
    db.session.commit()
    print(f"[OK] Baseline added: {file_path}")
    return baseline

def check_file_integrity(file_path):
    """Compare file hash to baseline and create event if changed."""
    baseline = FimBaseline.query.filter_by(file_path=file_path).first()
    if not baseline:
        return None  # no baseline

    current_hash = calculate_file_hash(file_path)
    if not current_hash or current_hash == baseline.hash_sha256:
        return None

    owner, permissions, size_kb = get_file_metadata(file_path)

    event = FimEvent(
        baseline_id=baseline.id,
        file_path=file_path,
        old_hash=baseline.hash_sha256,
        new_hash=current_hash,
        change_type="hash_mismatch",
        severity="high",
        detected_at=datetime.utcnow(),
        owner=owner,
        permissions=permissions,
        size=size_kb
    )
    db.session.add(event)
    db.session.commit()
    return event

def check_all_files_integrity():
    """Check integrity of all baseline files."""
    for baseline in FimBaseline.query.all():
        event = check_file_integrity(baseline.file_path)
        if event:
            print(f"[ALERT] Integrity issue: {baseline.file_path}")
        else:
            print(f"[OK] No change: {baseline.file_path}")
