from app import create_app
import os
import xml.etree.ElementTree as ET
from app.models import Alert
from app.extensions import db

RULE_DIR = "app/rules/wazuh-ruleset/rules/"
app = create_app()

def build_rule_title_to_id_map():
    title_to_id = {}
    for file in os.listdir(RULE_DIR):
        if file.endswith(".xml"):
            path = os.path.join(RULE_DIR, file)
            try:
                tree = ET.parse(path)
                root = tree.getroot()
                for rule in root.findall("rule"):
                    rule_id = rule.attrib.get("id")
                    description = rule.findtext("description")
                    if rule_id and description:
                        title_to_id[description.strip()] = int(rule_id)
            except Exception as e:
                print(f"Error parsing {file}: {e}")
    return title_to_id

def patch_missing_rule_ids():
    title_to_id = build_rule_title_to_id_map()
    alerts = Alert.query.filter_by(rule_id=None).all()
    patched = 0

    for alert in alerts:
        if alert.rule_title:
            rule_id = title_to_id.get(alert.rule_title.strip())
            if rule_id:
                alert.rule_id = rule_id
                patched += 1
            else:
                print(f"[WARN] No matching rule_id found for title: {alert.rule_title}")
        else:
            print("[WARN] Alert with missing rule_title")

    try:
        db.session.commit()
        print(f"[DONE] Patched {patched} alerts with missing rule_id")
    except Exception as e:
        print(f"[ERROR] Commit failed: {e}")
        db.session.rollback()

if __name__ == "__main__":
    with app.app_context():
        patch_missing_rule_ids()
