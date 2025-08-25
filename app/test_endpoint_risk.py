from app.utils.cvss_metrics import EXPLOITABILITY_METRICS, IMPACT_METRICS
from app import db
from app.models import Alert
from app.utils.endpoint_risk import compute_alert_cvss, compute_endpoint_risk, summarize_endpoint_behavior
import json
import os

def load_cvss_mappings():
    path = os.path.join(os.path.dirname(__file__), "cvss_rule_mapping.json")
    with open(path, "r") as f:
        return json.load(f)

def compute_alert_cvss(alert, mappings=None):
    """
    Compute CVSS for a single alert based on JSON mappings.
    Returns None if no mapping found.
    """
    if not mappings:
        mappings = {}
    rule_id = getattr(alert, "rule_id", None)
    if rule_id and rule_id in mappings:
        return mappings[rule_id]["cvss_score"]
    return None
