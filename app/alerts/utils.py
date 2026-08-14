# app/alerts/utils.py
from app.dlp import fetch_logs_by_type, LOG_AGENT_RULE_MAP, generate_alert, post_process_enrichment, extract_log_types

# Now these functions just reference the real ones in dlp.py

# Optional: if you want to override or wrap for logging/debug
def fetch_logs_by_type_wrapper(log_type, limit=None, after_timestamp=None):
    return fetch_logs_by_type(log_type, limit=limit, after_timestamp=after_timestamp)

def generate_alert_wrapper(log, match, commit_batch=True):
    return generate_alert(log, match, commit_batch=commit_batch)

def post_process_enrichment_wrapper(alerts):
    post_process_enrichment(alerts)

def extract_log_types_wrapper(log_map):
    return extract_log_types(log_map)

