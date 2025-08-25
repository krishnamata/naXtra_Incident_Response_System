# app/utils/cvss_loader.py
import json
import os
#from app.utils.cvss_metrics import compute_cvss_score
from app.utils.cvss_metrics import EXPLOITABILITY_METRICS, IMPACT_METRICS

MAPPING_FILE = os.path.join(os.path.dirname(__file__), "cvss_rule_mapping.json")

def load_cvss_mappings():
    """Load CVSS rule mappings from JSON."""
    with open(MAPPING_FILE, "r") as f:
        return json.load(f)

def compute_alert_cvss(alert, mappings):
    """
    Compute CVSS score for an alert using rule_id → metrics mapping.
    :param alert: dict-like row from alerts table
    :param mappings: loaded JSON mapping
    """
    rule_id = str(alert.get("rule_id"))
    metrics = mappings.get(rule_id)

    if not metrics:
        # default: very low severity if no mapping found
        metrics = {
            "AV": "N",   # Network
            "AC": "L",   # Low
            "PR": "N",   # None
            "UI": "N",   # None
            "C": "N",    # None
            "I": "N",    # None
            "A": "N",    # None
        }

    return compute_cvss_score(metrics)


def compute_cvss_score(metrics):
    AV = EXPLOITABILITY_METRICS["AV"][metrics["AV"]]
    AC = EXPLOITABILITY_METRICS["AC"][metrics["AC"]]
    PR = EXPLOITABILITY_METRICS["PR"][metrics["PR"]]
    UI = EXPLOITABILITY_METRICS["UI"][metrics["UI"]]
    C = IMPACT_METRICS["C"][metrics["C"]]
    I = IMPACT_METRICS["I"][metrics["I"]]
    A = IMPACT_METRICS["A"][metrics["A"]]

    impact = 1 - ((1 - C) * (1 - I) * (1 - A))
    exploitability = 8.22 * AV * AC * PR * UI
    if impact <= 0:
        return 0.0
    return round(min(impact + exploitability, 10), 1)
