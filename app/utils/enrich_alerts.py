# app/utils/enrich_alerts_run.py
import os
import logging
from datetime import datetime
from app import create_app
from app.extensions import db
from app.models import Alert
from app.integrations.ioc_enrichment import enrich_ioc

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def run_enrichment():
    alerts = Alert.query.filter(Alert.enrichment_data.is_(None)).all()
    if not alerts:
        logger.info("No alerts found that need IOC enrichment.")
        return

    for alert in alerts:
        logger.info(f"Processing Alert ID {alert.id}...")
        result = enrich_ioc(md5_hash=alert.md5_hash, sha256_hash=alert.sha256_hash)
        if result:
            alert.enrichment_data = result
            alert.enrichment_status = "enriched"
            alert.enrichment_source = ", ".join(result.keys())
            alert.enrichment_timestamp = datetime.utcnow()
            try:
                db.session.commit()
                logger.info(f"[✔] Alert {alert.id} enriched successfully.")
            except Exception as e:
                db.session.rollback()
                logger.error(f"[✖] Failed to update Alert {alert.id}: {e}")
        else:
            logger.warning(f"No IOC enrichment found for Alert ID {alert.id}.")

if __name__ == "__main__":
    app = create_app()
    with app.app_context():
        run_enrichment()
