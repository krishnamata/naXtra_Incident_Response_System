def generate_alert_description(severity: int, mitre: dict, matched_keywords: list[str]) -> str:
    """
    Generates a human-readable description of the alert.
    """

    keyword_str = "; ".join(matched_keywords)
    technique_name = mitre.get("name", "Unknown Technique")
    tactic = mitre.get("tactic", "Unknown Tactic")
    impact = mitre.get("impact", "No impact information available.")
    technique_id = mitre.get("id", "Txxxx")

    # Map severity to human meaning
    if severity >= 13:
        severity_text = "Critical"
        recommendation = "Immediate containment and investigation is required."
    elif severity >= 9:
        severity_text = "High"
        recommendation = "Review and isolate affected systems. Conduct in-depth analysis."
    elif severity >= 5:
        severity_text = "Moderate"
        recommendation = "Monitor the system and investigate further."
    else:
        severity_text = "Low"
        recommendation = "Log and review periodically."

    description = (
        f"🔍 **Severity:** {severity} ({severity_text})\n"
        f"🧠 **Reason:** Log matched {len(matched_keywords)} keyword(s): {keyword_str}.\n"
        f"🎯 **MITRE Technique:** {technique_name} ({technique_id}) under {tactic} tactic.\n"
        f"🔥 **Impact:** {impact}\n"
        f"✅ **Recommended Action:** {recommendation}"
    )

    print(f"[generate_alert_description] Description generated:\n{description}\n")

    return description
