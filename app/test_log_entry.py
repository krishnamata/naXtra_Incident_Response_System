# app/test_log_entry.py
import sys
import argparse
from app import create_app  # your Flask app instance
from app.dlp import detect_logs_and_generate_alerts

app = create_app()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--type', required=True, help='Log type')
    args = parser.parse_args()

    log_input = sys.stdin.read().strip()
    if not log_input:
        print("No log input received.")
        return

    logs = [{'message': log_input}]

    with app.app_context():
        detect_logs_and_generate_alerts(logs)  # call without params as your function expects

if __name__ == '__main__':
    main()
