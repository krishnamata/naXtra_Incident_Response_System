import json
import csv
from datetime import datetime
from app.extensions import db
from app.models import Alert
from app.utils.cvss_loader import load_cvss_mappings, compute_alert_cvss
from app.utils.mitre_map import MITRE_KEYWORD_MAP
from app.utils.mitre import map_alert_to_mitre

# === Module 1: Prioritization ===
class AlertPrioritization:
    @staticmethod
    def prioritize(alerts):
        # Sort by severity (desc) then CVSS (desc)
        return sorted(alerts, key=lambda a: (-getattr(a, 'severity', 0), -getattr(a, 'cvss_score', 0)))


# === Module 2: Correlation Engine ===
class CorrelationEngine:
    @staticmethod
    def correlate(alerts):
        for alert in alerts:
            desc = (alert.description or "").lower()
            alert.correlated = False

            # 1️⃣ Keyword map
            for keyword, mapping in MITRE_KEYWORD_MAP.items():
                if keyword in desc:
                    alert.technique_id = mapping["id"] if isinstance(mapping, dict) else mapping
                    alert.correlated = True
                    break

            # 2️⃣ Full MITRE ATT&CK fallback
            if not alert.correlated:
                mitre_info = map_alert_to_mitre(alert.description)
                if mitre_info:
                    alert.technique_id = mitre_info["technique_id"]
                    alert.technique_name = mitre_info["technique_name"]
                    alert.correlated = True

        return alerts


# === Module 3: Threat Intel Enrichment ===
class ThreatIntelEnrichment:
    @staticmethod
    def enrich(alerts):
        for alert in alerts:
            alert.enriched = True
        return alerts


# === Module 4: Audit Reporting ===
class AuditReporting:
    actions = []

    @classmethod
    def log_action(cls, alert, action, user):
        cls.actions.append({
            "alert_id": alert.id,
            "action": action,
            "user": user,
            "timestamp": datetime.now().isoformat()
        })

    @classmethod
    def export_json(cls, base_filename="audit_log"):
        date_str = datetime.now().strftime("%Y-%m-%d")
        filepath = f"{base_filename}_{date_str}.json"
        with open(filepath, "w") as f:
            json.dump(cls.actions, f, indent=4)
        return filepath

    @classmethod
    def export_csv(cls, base_filename="audit_log"):
        if not cls.actions:
            return None
        date_str = datetime.now().strftime("%Y-%m-%d")
        filepath = f"{base_filename}_{date_str}.csv"
        keys = cls.actions[0].keys()
        with open(filepath, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(cls.actions)
        return filepath


# === Module 5: Automation ===
class AutomationEngine:
    @staticmethod
    def automate(alerts):
        for alert in alerts:
            if getattr(alert, "severity", 0) <= 3:
                AuditReporting.log_action(alert, "auto_closed", "system")
        return alerts


# === Module 6: Risk Scoring ===
class RiskScoring:
    @staticmethod
    def score(alerts):
        for alert in alerts:
            alert.risk_score = getattr(alert, "severity", 0) * getattr(alert, "cvss_score", 0)
        return alerts


# === Module 7: Executive Reporting ===
class ExecutiveReporting:
    @staticmethod
    def summary(alerts):
        high_priority = sum(1 for a in alerts if getattr(a, "severity", 0) >= 8)
        total = len(alerts)
        return {
            "total_alerts": total,
            "high_priority": high_priority,
            "audit_actions": len(AuditReporting.actions)
        }


# === Dataset Generation / Enrichment ===
def generate_dataset(session, n=100):
    """Fetch alerts from DB and populate CVSS, analyst, agent, MITRE info."""
    try:
        alerts = session.query(Alert).limit(n).all()
    except AttributeError:
        alerts = []

    cvss_mappings = load_cvss_mappings()

    for alert in alerts:
        # Analyst
        alert.analyst = getattr(getattr(alert, "assigned_to_user", None), "full_name", None) or "Not Assigned"

        # Agent
        if not getattr(alert, "agent_name", None):
            alert.agent_name = "Unknown Agent"

        # CVSS Score
        try:
            alert.cvss_score = compute_alert_cvss(alert.__dict__, cvss_mappings)
        except Exception:
            alert.cvss_score = 0.0

        # Severity mapping
        if alert.cvss_score >= 9:
            alert.severity = 10
        elif alert.cvss_score >= 7:
            alert.severity = 8
        elif alert.cvss_score >= 4:
            alert.severity = 5
        else:
            alert.severity = 2

        # Evidence defaults
        if not hasattr(alert, "evidence"):
            alert.evidence = []

    # Correlation & Enrichment
    alerts = CorrelationEngine.correlate(alerts)
    alerts = ThreatIntelEnrichment.enrich(alerts)

    return alerts


# === Execution Pipeline ===
if __name__ == "__main__":
    print("\n--- Running naXtra Pulse IR Demo ---\n")

    # Simulated DB session; replace with real SQLAlchemy session in production
    alerts = generate_dataset(session=None, n=1000)

    # 1️⃣ Prioritization
    prioritized = AlertPrioritization.prioritize(alerts)
    print("[Case 1] Top 3 prioritized alerts:")
    for a in prioritized[:3]:
        print(f"  Alert {a.id} | Sev {a.severity} | CVSS {a.cvss_score}")

    # 2️⃣ Correlation
    correlated = CorrelationEngine.correlate(prioritized)
    print(f"\n[Case 2] Correlated Alerts: {sum(a.correlated for a in correlated)}")

    # 3️⃣ Enrichment
    enriched = ThreatIntelEnrichment.enrich(correlated)
    print(f"\n[Case 3] Context Enriched Alerts: {sum(a.enriched for a in enriched)}")

    # 4️⃣ Audit (Evidence Submission Example)
    sample_alert = enriched[0]
    if not hasattr(sample_alert, "evidence"):
        sample_alert.evidence = []
    # Example evidence; in production, pull from AlertEvidence table
    sample_alert.evidence.append({"file": "example_file.eml", "uploaded_by": sample_alert.analyst})
    AuditReporting.log_action(sample_alert, "evidence_uploaded", sample_alert.analyst)
    print(f"\n[Case 4] Evidence uploaded for Alert {sample_alert.id} by {sample_alert.analyst}")

    # 5️⃣ Detection Gap Mitigation
    overlooked = [a for a in enriched if getattr(a, "severity", 0) == 2 and getattr(a, "correlated", False)]
    print(f"\n[Case 5] Overlooked threats found: {len(overlooked)}")

    # 6️⃣ Operational Efficiency
    automated = AutomationEngine.automate(enriched)
    print(f"\n[Case 6] Auto-closed alerts: {sum(1 for a in automated if getattr(a, 'severity', 0) <= 3)}")

    # 7️⃣ Leadership Oversight
    exec_summary = ExecutiveReporting.summary(enriched)
    print(f"\n[Case 7] Executive Summary: {exec_summary}")

    # 8️⃣ Business & Reputational Risk
    scored = RiskScoring.score(enriched)
    top_risk = sorted(scored, key=lambda a: -getattr(a, "risk_score", 0))[:3]
    print("\n[Case 8] Top 3 Risk Alerts:")
    for a in top_risk:
        print(f"  Alert {a.id} | Risk Score {a.risk_score}")
