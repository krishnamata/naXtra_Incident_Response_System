import time
import json
from flask import Blueprint, Response, stream_with_context
from app.dlp import LOG_AGENT_RULE_MAP, fetch_logs_by_type, generate_alert
from app.rules.rules_engine import RuleEngine
from app.extensions import db

detection_bp = Blueprint("detection_bp", __name__)

@detection_bp.route("/run_detection_realtime", methods=["GET"])
def run_detection_realtime():
    """
    Real-time alert detection via SSE.
    Continuously polls for new logs and generates alerts.
    """
    def generate():
        yield "data: Starting real-time detection...\n\n"
        processed_log_ids = set()
        total_alerts = 0

        try:
            while True:
                any_logs = False
                for log_type, agents_map in LOG_AGENT_RULE_MAP.items():
                    for agent_type, rules in agents_map.items():
                        if not rules:
                            continue

                        logs = fetch_logs_by_type(log_type)
                        if logs:
                            any_logs = True

                        for log in logs:
                            log_id = log.get("id")
                            if log_id in processed_log_ids:
                                continue

                            processed_log_ids.add(log_id)
                            temp_engine = RuleEngine(rules)
                            matches = temp_engine.match_log(log)
                            if not matches:
                                continue

                            for match in matches:
                                alert = generate_alert(log, match, commit_batch=True)
                                if alert:
                                    total_alerts += 1
                                    # Send JSON for JS progress bar
                                    yield f"data: {json.dumps({'agent': log.get('agent_name'), 'received': total_alerts, 'total': len(processed_log_ids)})}\n\n"

                if not any_logs:
                    # No logs yet; yield idle message every few seconds
                    yield f"data: {json.dumps({'agent': None, 'received': total_alerts, 'total': len(processed_log_ids)})}\n\n"

                time.sleep(3)

        except GeneratorExit:
            yield "data: SSE client disconnected.\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"

        yield f"event: done\ndata: {json.dumps({'total_alerts': total_alerts})}\n\n"

    return Response(stream_with_context(generate()), mimetype='text/event-stream')
