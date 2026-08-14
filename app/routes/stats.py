from flask import jsonify, request, Blueprint, render_template
from datetime import datetime, timedelta
from collections import Counter
from app.models import Alert, FimEvent, LogEntry
from app.extensions import db
from sqlalchemy import func

stats_bp = Blueprint("stats", __name__, url_prefix="/stats")

# --- New Behavior Analysis / Trend Functions ---
def alerts_trend_over_time(unique_alerts, days=30):
    cutoff = datetime.utcnow() - timedelta(days=days)
    alerts_time = [(a.detected_time.date(), 1) for a in unique_alerts if a.detected_time and a.detected_time >= cutoff]
    counts_per_day = {}
    for date, count in alerts_time:
        counts_per_day[date] = counts_per_day.get(date, 0) + count
    dates = sorted(counts_per_day.keys())
    counts = [counts_per_day[d] for d in dates]
    return [str(d) for d in dates], counts

def alerts_by_agent(unique_alerts):
    counter = Counter(a.agent_name if a.agent_name else "Unknown" for a in unique_alerts)
    return dict(counter)

def alerts_by_rule(unique_alerts):
    counter = Counter(a.rule_title if a.rule_title else "Unknown" for a in unique_alerts)
    return dict(counter)

def severity_distribution(unique_alerts):
    high = sum(1 for a in unique_alerts if a.cvss_score and a.cvss_score >= 7)
    medium = sum(1 for a in unique_alerts if a.cvss_score and 4 <= a.cvss_score < 7)
    low = sum(1 for a in unique_alerts if a.cvss_score and a.cvss_score < 4)
    return {"High (7-10)": high, "Medium (4-6.9)": medium, "Low (<4)": low}

def hourly_alert_pattern(unique_alerts):
    counter = Counter(a.detected_time.strftime('%H') for a in unique_alerts if a.detected_time)
    return dict(sorted(counter.items()))

# Logs

# --- Logs Analysis / Trend Functions ---
def logs_trend_over_time(unique_logs, days=30):
    cutoff = datetime.utcnow() - timedelta(days=days)
    counts_per_day = Counter(l.timestamp.date() for l in unique_logs if l.timestamp and l.timestamp >= cutoff)
    dates = sorted(counts_per_day.keys())
    counts = [counts_per_day[d] for d in dates]
    return [str(d) for d in dates], counts

def logs_by_type(unique_logs):
    return dict(Counter(l.log_type if l.log_type else "Unknown" for l in unique_logs))

def logs_by_source(unique_logs):
    return dict(Counter(l.source if l.source else "Unknown" for l in unique_logs))





@stats_bp.route('/')
def stats_dashboard():
    # --- Deduplicate Alerts ---
    # Alerts with matched_log_id
    dedup_alerts_with_log = db.session.query(Alert).filter(Alert.matched_log_id.isnot(None)) \
        .distinct(Alert.matched_log_id).all()
    # --- Deduplicate logs ---
    subq_logs = db.session.query(
        func.min(LogEntry.id).label("id")
    ).group_by(LogEntry.source, LogEntry.log_type, LogEntry.message, LogEntry.timestamp).subquery()

    unique_logs = db.session.query(LogEntry).join(subq_logs, LogEntry.id == subq_logs.c.id).all()
    # --- Logs stats ---
    logs_type_stats = logs_by_type(unique_logs)
    logs_source_stats = logs_by_source(unique_logs)
    logs_dates, logs_counts = logs_trend_over_time(unique_logs)
    
    # Alerts without matched_log_id, deduplicate by rule_title, agent_name, detected_time
    subq = db.session.query(func.min(Alert.id).label("id")) \
        .filter(Alert.matched_log_id.is_(None)) \
        .group_by(Alert.rule_title, Alert.agent_name, Alert.detected_time) \
        .subquery()

    dedup_alerts_without_log = db.session.query(Alert).join(subq, Alert.id == subq.c.id).all()

    unique_alerts = dedup_alerts_with_log + dedup_alerts_without_log

    total_alerts = len(unique_alerts)
    high_cvss_alerts = sum(1 for a in unique_alerts if a.cvss_score and a.cvss_score >= 7)
    medium_cvss_alerts = sum(1 for a in unique_alerts if a.cvss_score and 4 <= a.cvss_score < 7)
    low_cvss_alerts = sum(1 for a in unique_alerts if a.cvss_score and a.cvss_score < 4)

    alert_types_dict = dict(Counter([a.rule_title if a.rule_title else "Unknown" for a in unique_alerts]))

    # --- Deduplicate FIM Events ---
    subq_fim = db.session.query(func.min(FimEvent.id).label("id")) \
        .group_by(FimEvent.file_path, FimEvent.change_type, FimEvent.detected_at) \
        .subquery()

    unique_fim_events = db.session.query(FimEvent).join(subq_fim, FimEvent.id == subq_fim.c.id).all()

    fim_by_type_dict = {}
    for event in unique_fim_events:
        key = event.change_type if event.change_type else "Unknown"
        fim_by_type_dict[key] = fim_by_type_dict.get(key, 0) + 1

    total_fim_events = sum(fim_by_type_dict.values())

    # --- Time series last 30 days ---
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)

    # Alerts time series
    alerts_time = [(a.detected_time.date(), 1) for a in unique_alerts if a.detected_time and a.detected_time >= thirty_days_ago]
    alert_counts_per_day = {}
    for date, count in alerts_time:
        alert_counts_per_day[date] = alert_counts_per_day.get(date, 0) + count
    alert_dates = sorted(alert_counts_per_day.keys())
    alert_counts = [alert_counts_per_day[d] for d in alert_dates]

    # FIM events time series
    fim_time_query = [e for e in unique_fim_events if e.detected_at and e.detected_at >= thirty_days_ago]
    fim_counts_per_day = {}
    for e in fim_time_query:
        d = e.detected_at.date()
        fim_counts_per_day[d] = fim_counts_per_day.get(d, 0) + 1
    fim_dates = sorted(fim_counts_per_day.keys())
    fim_counts = [fim_counts_per_day[d] for d in fim_dates]

    cvss_distribution = {
        "High (7-10)": high_cvss_alerts,
        "Medium (4-6.9)": medium_cvss_alerts,
        "Low (<4)": low_cvss_alerts
    }
    # --- Behavior Analysis / Trends ---
    alert_dates, alert_counts = alerts_trend_over_time(unique_alerts)
    agent_stats = alerts_by_agent(unique_alerts)
    rule_stats = alerts_by_rule(unique_alerts)
    cvss_stats = severity_distribution(unique_alerts)
    hourly_stats = hourly_alert_pattern(unique_alerts)

    return render_template(
        "stats_dashboard.html",
        total_alerts=total_alerts,
        high_cvss_alerts=high_cvss_alerts,
        medium_cvss_alerts=medium_cvss_alerts,
        low_cvss_alerts=low_cvss_alerts,
        total_fim_events=total_fim_events,
        fim_by_type=fim_by_type_dict,
        alert_dates=alert_dates,
        alert_counts=alert_counts,
        fim_dates=[str(d) for d in fim_dates],
        fim_counts=fim_counts,
        cvss_distribution=cvss_distribution,
        alert_types=rule_stats,
        by_agent=agent_stats,
        hourly_pattern=hourly_stats,
        logs_type=logs_type_stats,
        logs_source=logs_source_stats,
        logs_dates=logs_dates,
        logs_counts=logs_counts
    )


@stats_bp.route('/ajax_data', methods=['GET'])
def stats_ajax_data():
    # Deduplicate at query time
    dedup_alerts_with_log = db.session.query(Alert).filter(Alert.matched_log_id.isnot(None)) \
        .distinct(Alert.matched_log_id)

    subq = db.session.query(func.min(Alert.id).label("id")) \
        .filter(Alert.matched_log_id.is_(None)) \
        .group_by(Alert.rule_title, Alert.agent_name, Alert.detected_time) \
        .subquery()

    dedup_alerts_without_log = db.session.query(Alert).join(subq, Alert.id == subq.c.id)
    unique_alerts = dedup_alerts_with_log.union_all(dedup_alerts_without_log).all()

    # --- Filters ---
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    alert_type_filter = request.args.get('alert_type')
    cvss_filter = request.args.get('cvss_level')

    filtered_alerts = [
        a for a in unique_alerts
        if (not start_date or a.detected_time and a.detected_time >= datetime.fromisoformat(start_date)) and
           (not end_date or a.detected_time and a.detected_time <= datetime.fromisoformat(end_date)) and
           (not alert_type_filter or a.rule_title == alert_type_filter) and
           (not cvss_filter or
            (cvss_filter == 'High' and a.cvss_score and a.cvss_score >= 7) or
            (cvss_filter == 'Medium' and a.cvss_score and 4 <= a.cvss_score < 7) or
            (cvss_filter == 'Low' and a.cvss_score and a.cvss_score < 4))
    ]

    cvss_distribution = {
        "High (7-10)": sum(1 for a in filtered_alerts if a.cvss_score and a.cvss_score >= 7),
        "Medium (4-6.9)": sum(1 for a in filtered_alerts if a.cvss_score and 4 <= a.cvss_score < 7),
        "Low (<4)": sum(1 for a in filtered_alerts if a.cvss_score and a.cvss_score < 4)
    }

    alert_types = dict(Counter([a.rule_title if a.rule_title else "Unknown" for a in filtered_alerts]))

    return jsonify({
        "cvss_distribution": cvss_distribution,
        "alert_types": alert_types
    })


@stats_bp.route('/table_data')
def table_data():
    # Deduplicate alerts
    dedup_alerts_with_log = db.session.query(Alert).filter(Alert.matched_log_id.isnot(None)) \
        .distinct(Alert.matched_log_id)

    subq = db.session.query(func.min(Alert.id).label("id")) \
        .filter(Alert.matched_log_id.is_(None)) \
        .group_by(Alert.rule_title, Alert.agent_name, Alert.detected_time) \
        .subquery()

    dedup_alerts_without_log = db.session.query(Alert).join(subq, Alert.id == subq.c.id)
    unique_alerts = dedup_alerts_with_log.union_all(dedup_alerts_without_log).all()

    # --- Filtering and pagination ---
    alert_type = request.args.get('alert_type')
    cvss_min = float(request.args.get('cvss_min', 0))
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    page = int(request.args.get('page', 1))
    page_size = int(request.args.get('page_size', 25))

    filtered_alerts = [
        a for a in unique_alerts
        if (not alert_type or a.rule_title == alert_type) and
           (not start_date or a.detected_time and a.detected_time >= datetime.fromisoformat(start_date)) and
           (not end_date or a.detected_time and a.detected_time <= datetime.fromisoformat(end_date)) and
           (not cvss_min or (a.cvss_score and a.cvss_score >= cvss_min))
    ]

    total_count = len(filtered_alerts)
    total_pages = (total_count + page_size - 1) // page_size

    paginated_alerts = filtered_alerts[(page - 1) * page_size: page * page_size]

    alerts_list = [
        {
            'id': a.id,
            'alert_type': a.rule_title if a.rule_title else "Unknown",
            'cvss': a.cvss_score if a.cvss_score is not None else 0,
            'source': a.agent_name if a.agent_name else "Unknown",
            'timestamp': a.detected_time.strftime('%Y-%m-%d %H:%M:%S') if a.detected_time else ""
        } for a in paginated_alerts
    ]

    return jsonify({
        'alerts': alerts_list,
        'page': page,
        'total_pages': total_pages
    })
