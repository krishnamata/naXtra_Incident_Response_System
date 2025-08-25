# File: read_logs_debug.py
from app import create_app
from app.models import LogEntry
from app.extensions import db

def main():
    app = create_app()
    with app.app_context():
        logs = LogEntry.query.order_by(LogEntry.timestamp.desc()).limit(20).all()
        print(f"[+] Total logs fetched: {len(logs)}")

        for i, log in enumerate(logs):
            print(f"Log #{i+1} | ID={log.id}, Agent={log.source}, Type={log.log_type}, Timestamp={log.timestamp}")
            print(f"Message: {log.message[:100] if log.message else 'None'}")
            print("-" * 80)

if __name__ == "__main__":
    main()
