# app/utils/cvss_loader.py
import json
import os
import math
from app.utils.cvss_metrics import EXPLOITABILITY_METRICS, IMPACT_METRICS

# Updated to full mapping
MAPPING_FILE = os.path.join(os.path.dirname(__file__), "cvss_rule_mapping_full.json")

def load_cvss_mappings():
    """Load CVSS rule mappings from full JSON."""
    with open(MAPPING_FILE, "r") as f:
        return json.load(f)

def compute_alert_cvss(alert, mappings):
    """
    Compute CVSS score for an alert using rule_id → metrics mapping.
    :param alert: dict-like row from alerts table
    :param mappings: loaded JSON mapping
    """
    rule_id = str(alert.get("rule_id"))
    metrics_entry = mappings.get(rule_id)

    if not metrics_entry:
        # Default very low severity if no mapping found
        metrics = {
            "AV": "N",  # Network
            "AC": "L",  # Low
            "PR": "N",  # None
            "UI": "N",  # None
            "C": "N",   # None
            "I": "N",   # None
            "A": "N",   # None
            "S": "U"    # Scope Unchanged
        }
    else:
        metrics = metrics_entry.get("metrics", {})

    return compute_cvss_score(metrics)


def _round_up_one_decimal(value: float) -> float:
    """CVSS requires rounding up (ceiling) to one decimal place."""
    return math.ceil(value * 10) / 10.0

def compute_cvss_score(metrics: dict) -> float:
    """
    Compute CVSS v3.1 Base Score (official formula).
    Accepts a metrics dict with keys: AV, AC, PR, UI, C, I, A, optionally S (Scope)
    """
    required = ("AV", "AC", "PR", "UI", "C", "I", "A")
    for k in required:
        if k not in metrics:
            raise KeyError(f"Missing CVSS metric: {k}")

    # Scope handling (default Unchanged if not provided)
    S = metrics.get("S", "U")
    if S not in ("U", "C"):
        if str(S).lower() in ("unchanged", "u"):
            S = "U"
        elif str(S).lower() in ("changed", "c"):
            S = "C"
        else:
            raise ValueError(f"Invalid Scope (S) value: {S}")

    AV = EXPLOITABILITY_METRICS["AV"][metrics["AV"]]
    AC = EXPLOITABILITY_METRICS["AC"][metrics["AC"]]
    UI = EXPLOITABILITY_METRICS["UI"][metrics["UI"]]

    pr_value = metrics["PR"]
    if S == "U":
        PR = {"N": 0.85, "L": 0.62, "H": 0.27}[pr_value]
    else:
        PR = {"N": 0.85, "L": 0.68, "H": 0.50}[pr_value]

    C = IMPACT_METRICS["C"][metrics["C"]]
    I = IMPACT_METRICS["I"][metrics["I"]]
    A = IMPACT_METRICS["A"][metrics["A"]]

    ISS = 1 - ((1 - C) * (1 - I) * (1 - A))

    if S == "U":
        Impact = 6.42 * ISS
    else:
        Impact = 7.52 * (ISS - 0.029) - 3.25 * pow((ISS - 0.02), 15)

    Exploitability = 8.22 * AV * AC * PR * UI

    if ISS <= 0:
        base_score = 0.0
    else:
        base = Impact + Exploitability if S == "U" else 1.08 * (Impact + Exploitability)
        base_score = min(base, 10.0)

    return _round_up_one_decimal(base_score)
