# fill_alert_hashes.py
import hashlib
from app import create_app, db
from app.models import Alert

app = create_app()
app.app_context().push()

alerts = Alert.query.filter(
    (Alert.md5_hash.is_(None)) | (Alert.md5_hash == '') |
    (Alert.sha256_hash.is_(None)) | (Alert.sha256_hash == '')
).all()

for alert in alerts:
    # Try to use parsed_raw if available, else fallback to description
    message = getattr(alert, 'description', '') or ''
    
    # Compute hashes if missing
    if not alert.md5_hash:
        alert.md5_hash = hashlib.md5(message.encode()).hexdigest()
    if not alert.sha256_hash:
        alert.sha256_hash = hashlib.sha256(message.encode()).hexdigest()
    
    print(f"[UPDATED] Alert ID {alert.id}: MD5={alert.md5_hash}, SHA256={alert.sha256_hash}")

try:
    db.session.commit()
    print(f"✅ Updated {len(alerts)} alerts with missing hashes")
except Exception as e:
    db.session.rollback()
    print(f"❌ Failed to update alerts: {e}")
