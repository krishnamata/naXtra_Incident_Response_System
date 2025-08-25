# app/utils/endpoint_risk.py
import statistics
from collections import defaultdict
from datetime import datetime, timedelta
from app.utils.cvss_loader import load_cvss_mappings, compute_alert_cvss as loader_compute
from app.models import Alert
from app import db
from app.utils.cvss_metrics import EXPLOITABILITY_METRICS, IMPACT_METRICS
from app.utils.mitre import get_mitre_info

cvss_mappings = load_cvss_mappings()

# --- Heuristic fallback (only used if mapping is missing) ---
def estimate_metrics_from_description(description):
    """Fallback: estimate CVSS metrics from alert description."""
    desc = description.lower() if description else ""

    # Defaults
    AV = EXPLOITABILITY_METRICS["AV"]["L"]
    AC = EXPLOITABILITY_METRICS["AC"]["H"]
    PR = EXPLOITABILITY_METRICS["PR"]["L"]
    UI = EXPLOITABILITY_METRICS["UI"]["R"]
    C = IMPACT_METRICS["C"]["L"]
    I = IMPACT_METRICS["I"]["L"]
    A = IMPACT_METRICS["A"]["L"]

    if "network" in desc or "remote" in desc:
        AV = EXPLOITABILITY_METRICS["AV"]["N"]
    if "physical" in desc:
        AV = EXPLOITABILITY_METRICS["AV"]["P"]
    if "privilege escalation" in desc or "root" in desc:
        PR = EXPLOITABILITY_METRICS["PR"]["H"]
        C = IMPACT_METRICS["C"]["H"]
        I = IMPACT_METRICS["I"]["H"]
        A = IMPACT_METRICS["A"]["H"]
    if "malware" in desc or "ransomware" in desc:
        C = IMPACT_METRICS["C"]["H"]
        I = IMPACT_METRICS["I"]["H"]
        A = IMPACT_METRICS["A"]["H"]
    if "login failure" in desc or "brute force" in desc:
        PR = EXPLOITABILITY_METRICS["PR"]["L"]
        C = IMPACT_METRICS["C"]["L"]

    return AV, AC, PR, UI, C, I, A

# --- Core CVSS logic ---
def compute_alert_cvss(alert):
    """
    Compute CVSS for a single alert.
    Priority: JSON mapping → fallback heuristic.
    """
    if getattr(alert, "cvss_score", None) is not None:
        return alert.cvss_score

    # Try mapping first
    score = loader_compute(alert, cvss_mappings)

    # If mapping fails (returns None), fallback to heuristic
    if score is None:
        AV, AC, PR, UI, C, I, A = estimate_metrics_from_description(alert.description or "")
        # Use same scoring function as loader
        score = round(((AV + AC + PR + UI) / 4 + (C + I + A) / 3) / 2 * 10, 1)

    # Save in DB
    alert.cvss_score = score
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"[ERROR] Failed to write CVSS for alert {alert.id}: {e}")

    return score

def compute_alert_risk(alert):
    return calculate_risk(
        compute_alert_cvss(alert) or 0,
        alert.probability if alert.probability is not None else 0.5,
        alert.behavior_score if alert.behavior_score is not None else 0,
    )



def calculate_risk(cvss, probability, behavior_score=0):
    """
    Calculate overall endpoint risk score (0–100).
    cvss: CVSS base score (0-10)
    probability: likelihood (0-1)
    behavior_score: UEBA anomaly (0-100)
    """
    cvss_normalized = cvss * 10  # scale 0–100
    prob_factor = probability * 100

    # Weighted average (adjustable weights)
    risk = (0.4 * cvss_normalized) + (0.3 * prob_factor) + (0.3 * behavior_score)
    return round(risk, 2)


def risk_severity(score):
    """
    Map risk score (0–100) to severity levels.
    """
    if score < 20:
        return "Low"
    elif score < 40:
        return "Moderate"
    elif score < 70:
        return "High"
    else:
        return "Critical"


def compute_endpoint_risk(alerts):
    """
    Compute risk per endpoint from list of alerts.
    alerts: list of Alert objects (with .cvss_score, .agent, etc.)
    """
    endpoint_risks = {}

    for alert in alerts:
        agent = alert.agent_name
        cvss = alert.cvss_score or 0
        probability = getattr(alert, "probability", 0.5)  # default if missing
        behavior_score = getattr(alert, "behavior_score", 0)

        risk = calculate_risk(cvss, probability, behavior_score)

        if agent not in endpoint_risks:
            endpoint_risks[agent] = []
        endpoint_risks[agent].append(risk)

    # Average per endpoint + severity mapping
    return {
        agent: {
            "avg_risk": round(sum(scores) / len(scores), 2),
            "severity": risk_severity(round(sum(scores) / len(scores), 2)),
            "risks": scores
        }
        for agent, scores in endpoint_risks.items()
    }



def summarize_endpoint_behavior(alerts):
    """Summarize MITRE techniques and tactics per endpoint."""
    summary = {}
    for alert in alerts:
        agent = alert.agent_name or "unknown"
        mitre_info = get_mitre_info(alert.technique_id) if getattr(alert, "technique_id", None) not in (None, "NA") else {}
        techniques = set()
        tactics = set()
        if mitre_info:
            techniques.add(mitre_info.get("technique_id"))
            tactics.add(mitre_info.get("tactic_name"))

        if agent not in summary:
            summary[agent] = {"techniques": set(), "tactics": set()}
        summary[agent]["techniques"].update(techniques)
        summary[agent]["tactics"].update(tactics)
    return {
        agent: {
             "techniques": list(v["techniques"]),
             "tactics": list(v["tactics"]),
        }
        for agent, v in summary.items()
    }

def process_alerts(alerts, db):
    for alert in alerts:
        cvss = compute_alert_cvss(alert)
        risk = compute_alert_risk(alert)
        sev = risk_severity(risk)
        db.session.execute(
            """
            UPDATE alerts 
            SET cvss_score = :cvss, 
                risk_score = :risk,
                severity = :sev
            WHERE id = :id
            """,
            {"cvss": cvss, "risk": risk, "sev": sev, "id": alert.id}
        )
    db.session.commit()





def get_endpoint_risk_from_db(limit=100, days=30, window=3):
    """
    Query alerts from DB and compute:
      - endpoint risk + severity
      - MITRE behavior summary
      - rolling average trend (per endpoint)
      - global risk trend across all endpoints
    """
    time_threshold = datetime.utcnow() - timedelta(days=days)

    alerts = (
        Alert.query
        .filter(Alert.detected_time >= time_threshold)
        .order_by(Alert.detected_time.desc())
        .limit(limit)
        .all()
    )

    if not alerts:
        return {}

    endpoint_risk = compute_endpoint_risk(alerts)
    endpoint_behavior = summarize_endpoint_behavior(alerts)

    # --- Trend calculation ---
    daily_risks = defaultdict(lambda: defaultdict(list))  
    # {agent: {date: [scores]}}

    for alert in alerts:
        agent = alert.agent_name or "unknown"
        date_key = alert.detected_time.date()
        risk = calculate_risk(
            alert.cvss_score or 0,
            getattr(alert, "probability", 0.5),
            getattr(alert, "behavior_score", 0),
        )
        daily_risks[agent][date_key].append(risk)

    endpoint_trends = {}
    global_daily = defaultdict(list)  # {date: [scores from all endpoints]}

    for agent, day_map in daily_risks.items():
        sorted_days = sorted(day_map.keys())
        daily_avg = [round(statistics.mean(day_map[d]), 2) for d in sorted_days]

        # rolling average
        rolling = []
        for i in range(len(daily_avg)):
            window_vals = daily_avg[max(0, i-window+1):i+1]
            rolling.append(round(statistics.mean(window_vals), 2))

        endpoint_trends[agent] = {
            "dates": [str(d) for d in sorted_days],
            "daily_avg": daily_avg,
            "rolling_avg": rolling
        }

        # accumulate for global trend
        for d, score in zip(sorted_days, daily_avg):
            global_daily[d].append(score)

    # --- global trend ---
    sorted_global_days = sorted(global_daily.keys())
    global_daily_avg = [round(statistics.mean(global_daily[d]), 2) for d in sorted_global_days]
    global_rolling_avg = []
    for i in range(len(global_daily_avg)):
        window_vals = global_daily_avg[max(0, i-window+1):i+1]
        global_rolling_avg.append(round(statistics.mean(window_vals), 2))

    global_trend = {
        "dates": [str(d) for d in sorted_global_days],
        "daily_avg": global_daily_avg,
        "rolling_avg": global_rolling_avg
    }

    return {
        "endpoint_risk": endpoint_risk,
        "endpoint_behavior": endpoint_behavior,
        "endpoint_trends": endpoint_trends,
        "global_trend": global_trend,
    }


if __name__ == "__main__":
    from app import create_app, db 
    app = create_app()  # create your Flask app
    with app.app_context():  # push the app context
        results = get_endpoint_risk_from_db(limit=100, days=30)
        import json
        print(json.dumps(results, indent=2, default=str))
    
