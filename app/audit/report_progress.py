# app/audit/report_progress.py
import os
import threading
import pandas as pd
from collections import defaultdict
from flask import url_for

# Thread-safe progress storage
_report_progress = defaultdict(lambda: {"percent": 0, "status": "pending", "filepath": None})
_progress_lock = threading.Lock()


def init_task(task_id):
    with _progress_lock:
        _report_progress[task_id] = {"percent": 0, "status": "running", "filepath": None, "download_url": None}


def set_progress(task_id, percent, status="running", filepath=None):
    with _progress_lock:
        _report_progress[task_id]["percent"] = percent
        _report_progress[task_id]["status"] = status
        if filepath:
            _report_progress[task_id]["filepath"] = filepath


def finalize_task(task_id, filepath, download_url=None):
    with _progress_lock:
        _report_progress[task_id].update({
            "percent": 100,
            "status": "completed",
            "filepath": filepath,
            "download_url": download_url
        })


def get_progress(task_id):
    with _progress_lock:
        info = _report_progress.get(task_id)
        if not info:
            return {"percent": 0, "status": "unknown", "download_url": None}

        percent = info["percent"]
        status = info["status"]
        filepath = info.get("filepath")

        download_url = info.get("download_url")
        if status == "completed" and not download_url and filepath and os.path.exists(filepath):
            prefix = os.path.basename(filepath).split("_")[0]  # logs_report / alerts_report
            from flask import current_app
            with current_app.test_request_context():
                download_url = url_for("audit.download_report", task_id=task_id, prefix=prefix, _external=True)

        return {"percent": percent, "status": status, "download_url": download_url}


def run_report_task(app, task_id, build_query_fn, columns, filepath, prefix="report"):
    """Threaded report generation."""
    with app.app_context():
        init_task(task_id)

        query = build_query_fn()  # call the function
        rows = query.all()  # now this works
        total = len(rows) or 1
        data = []

        for i, row in enumerate(rows, start=1):
            row_dict = {col: getattr(row, col, None) for col in columns}
            data.append(row_dict)
            if i % max(1, total // 100) == 0:
                set_progress(task_id, int(i / total * 100))

        # Save Excel
        df = pd.DataFrame(data)
        df.to_excel(filepath, index=False)

        # Build download URL
        from flask import current_app
        with app.test_request_context():
            download_url = url_for("audit.download_report", task_id=task_id, prefix=prefix, _external=True)

        # Finalize task
        finalize_task(task_id, filepath, download_url)
