# scripts/populate_alert_cvss.py

from app import create_app, db
from app.models import Alert
from app.utils import endpoint_risk

app = create_app()
app.app_context().push()

alerts = Alert.query.all()
print(f"[INFO] Total alerts to process: {len(alerts)}")

for alert in alerts:
    cvss_score = endpoint_risk.compute_alert_cvss(alert)
    print(f"Alert ID {alert.id} - CVSS: {cvss_score}")

print("[INFO] CVSS scores populated for all alerts.")
