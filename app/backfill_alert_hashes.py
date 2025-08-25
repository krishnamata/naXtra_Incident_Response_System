import hashlib
from app.models import Alert, Log  # Adjust if your Log model name or import path differs
from app.extensions import db

def calculate_hashes_for_alerts():
    # Query alerts with missing both md5 and sha256 hashes
    alerts = Alert.query.filter(
        (Alert.md5_hash.is_(None) | (Alert.md5_hash == '')) &
        (Alert.sha256_hash.is_(None) | (Alert.sha256_hash == ''))
    ).all()

    print(f"Found {len(alerts)} alerts without hashes.")

    for alert in alerts:
        # Fetch linked log entry via matched_log_id
        if not alert.matched_log_id:
            print(f"Alert ID {alert.id} has no matched_log_id, skipping.")
            continue

        log_entry = Log.query.get(alert.matched_log_id)
        if not log_entry or not hasattr(log_entry, 'raw_data'):
            print(f"Log entry for alert {alert.id} missing or has no raw_data, skipping.")
            continue

        raw_data = log_entry.raw_data  # Adjust attribute name as per your model

        # Compute hashes
        md5_hash = hashlib.md5(raw_data.encode('utf-8')).hexdigest()
        sha256_hash = hashlib.sha256(raw_data.encode('utf-8')).hexdigest()

        # Update alert record
        alert.md5_hash = md5_hash
        alert.sha256_hash = sha256_hash
        print(f"Alert ID {alert.id}: md5={md5_hash}, sha256={sha256_hash}")

    db.session.commit()
    print("Backfill completed.")

# Run this inside Flask shell or script with app context
if __name__ == "__main__":
    from app import create_app
    app = create_app()
    with app.app_context():
        calculate_hashes_for_alerts()
