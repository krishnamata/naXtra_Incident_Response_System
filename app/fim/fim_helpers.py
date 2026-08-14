import hashlib
from datetime import datetime
from app.models import FimEvent, NSRLFile, LogEntry
from app.extensions import db

def calculate_hash(file_path, algo="sha256"):
    """Calculate file hash (sha256, sha1, md5)."""
    h = hashlib.new(algo)
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

def get_os_files_for_agent(agent_name):
    """Return list of files with OS-aware NSRL info for the given agent."""
    # Use LogEntry.source instead of agent_name column if possible
    agent_exists = LogEntry.query.filter_by(source=agent_name).first()
    if not agent_exists:
        return []

    events = FimEvent.query.filter_by(agent_name=agent_name).all()
    result = []

    for e in events:
        # Determine if file is local or vendor/OS/package binary
        is_os_binary = e.os in ['Windows', 'Linux']  # extend as needed

        # Default values
        signature_status = "baseline-only"
        reason = "Local file, NSRL not checked"

        if is_os_binary:
            # Lookup NSRL hash
            nsrl_entry = NSRLFile.query.filter_by(sha256=e.old_hash).first()
            if nsrl_entry:
                signature_status = "valid" if e.old_hash == e.new_hash else "invalid"
                reason = "Matched NSRL entry"
            else:
                signature_status = "invalid"
                reason = "Not found in NSRL"

        # Build structured dict
        result.append({
            "id": e.id,
            "file_path": e.file_path,
            "old_hash": e.old_hash,
            "new_hash": e.new_hash,
            "change_type": e.change_type,
            "signature_status": signature_status,
            "reason": reason,
            "updated_at": e.updated_at.strftime("%Y-%m-%d %H:%M:%S"),
            "resolved": e.resolved
        })

    return result

def update_file_event(file_path, new_hash, agent_name, change_type="modified", os_name=None):
    """Update or create a FimEvent for a file change."""
    event = FimEvent.query.filter_by(agent_name=agent_name, file_path=file_path).first()
    if not event:
        event = FimEvent(file_path=file_path, agent_name=agent_name)
        db.session.add(event)

    event.old_hash = event.new_hash or new_hash
    event.new_hash = new_hash
    event.change_type = change_type
    event.os = os_name or "Unknown"
    event.updated_at = datetime.utcnow()

    # OS-aware NSRL logic
    if event.os in ['Windows', 'Linux']:
        nsrl_entry = NSRLFile.query.filter_by(sha256=new_hash).first()
        if nsrl_entry:
            event.signature_status = "valid" if event.old_hash == event.new_hash else "invalid"
            event.reason = "Matched NSRL entry"
        else:
            event.signature_status = "invalid"
            event.reason = "Not found in NSRL"
    else:
        event.signature_status = "baseline-only"
        event.reason = "Local file, NSRL not checked"

    db.session.commit()
    return event
