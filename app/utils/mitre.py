import json
import re
import os

ATTACK_JSON = os.path.join(os.path.dirname(__file__), '../../data/attack.json')
VALID_MITRE_ID_PATTERN = re.compile(r'^T\d{4}(?:\.\d{3})?$')  # e.g., T1059 or T1021.001

def sanitize_mitre_id(mitre_entry):
    """Sanitize and return valid MITRE technique ID or None."""
    if not mitre_entry:
        return None
    mitre_entry = str(mitre_entry).strip("() ").upper()
    return mitre_entry if VALID_MITRE_ID_PATTERN.match(mitre_entry) else None


def load_attack_data():
    with open(ATTACK_JSON, 'r') as f:
        return json.load(f)

attack_data = load_attack_data()

def get_mitre_info(technique_id):
    for obj in attack_data['objects']:
        if obj.get('type') == 'attack-pattern':
            for ext_ref in obj.get('external_references', []):
                if ext_ref.get('external_id') == technique_id:
                    return {
                        "name": obj.get("name"),
                        "description": obj.get("description"),
                        "mitigations": extract_mitigations(technique_id),
                        "url": ext_ref.get("url", "")
                    }
    return None

def extract_mitigations(technique_id):
    # Simple placeholder — real logic can cross-reference relationships
    return [
        "Use application layer filtering",
        "Monitor abnormal command-line activity",
        "Apply least privilege on user accounts"
    ]


def map_alert_to_mitre(alert_title_or_desc):
    """
    Map an alert title or description to MITRE technique info from attack.json.
    Returns a dict: { 'technique_id': str, 'technique_name': str } or None if no match.
    """
    if not alert_title_or_desc:
        return None

    alert_text = str(alert_title_or_desc).lower()
    for obj in attack_data.get('objects', []):
        if obj.get('type') != 'attack-pattern':
            continue
        technique_name = obj.get('name', '').lower()
        if technique_name in alert_text or alert_text in technique_name:
            # Take first external reference ID
            ext_refs = obj.get('external_references', [])
            if ext_refs:
                ext_id = ext_refs[0].get('external_id')
                if ext_id:
                    return {
                        "technique_id": ext_id,
                        "technique_name": obj.get('name')
                    }
    return None
