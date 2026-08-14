# cvss_metrics.py
"""
Official CVSS v3.1 multipliers for Base Score calculation.
Compatible with compute_cvss_score() in cvss_loader.py.
"""

# Exploitability Metrics (multipliers)
EXPLOITABILITY_METRICS = {
    "AV": {  # Attack Vector
        "N": 0.85,  # Network
        "A": 0.62,  # Adjacent Network
        "L": 0.55,  # Local
        "P": 0.2    # Physical
    },
    "AC": {  # Attack Complexity
        "L": 0.77,  # Low
        "H": 0.44   # High
    },
    "PR": {  # Privileges Required (Scope dependent)
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "C": {"N": 0.85, "L": 0.68, "H": 0.50}
},

    "UI": {  # User Interaction
        "N": 0.85,  # None
        "R": 0.62   # Required
    }
}

# Impact Metrics (multipliers)
IMPACT_METRICS = {
    "C": {"N":0.0, "L":0.22, "M":0.39, "H":0.56},
    "I": {"N":0.0, "L":0.22, "M":0.39, "H":0.56},
    "A": {"N":0.0, "L":0.22, "M":0.39, "H":0.56},
}
