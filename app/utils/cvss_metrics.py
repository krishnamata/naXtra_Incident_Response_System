# cvss_metrics.py

# Exploitability Metrics (multipliers for Base Score calculation)
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
    "PR": {  # Privileges Required (assuming Scope unchanged)
        "N": 0.85,  # None
        "L": 0.62,  # Low
        "H": 0.27   # High
    },
    "UI": {  # User Interaction
        "N": 0.85,  # None
        "R": 0.62   # Required
    }
}

# Impact Metrics (multipliers for Confidentiality, Integrity, Availability)
IMPACT_METRICS = {
    "C": {  # Confidentiality
        "N": 0.0,   # None
        "L": 0.22,  # Low
        "H": 0.56   # High
    },
    "I": {  # Integrity
        "N": 0.0,
        "L": 0.22,
        "H": 0.56
    },
    "A": {  # Availability
        "N": 0.0,
        "L": 0.22,
        "H": 0.56
    }
}
