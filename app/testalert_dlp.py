from app import create_app
from app.dlp import fetch_logs_by_type, detect_logs_and_generate_alerts_for_selected_logs

BATCH_SIZE = 500  # Adjust depending on your DB size and memory

def process_all_logs():
    app = create_app()
    with app.app_context():
        log_types = ["journal", "system", "summary", "kernlog", "other_linux", "authlog"]
        total_alerts = 0

        for lt in log_types:
            offset = 0
            while True:
                logs = fetch_logs_by_type(lt, normalize=False)  # fetch all logs of this type
                if not logs:
                    break

                alerts = detect_logs_and_generate_alerts_for_selected_logs(logs)
                total_alerts += len(alerts)
                print(f"[{lt}] Processed {len(logs)} logs, generated {len(alerts)} alerts.")

                if len(logs) < BATCH_SIZE:
                    break
                offset += BATCH_SIZE

        print(f"Completed processing all logs. Total alerts generated: {total_alerts}")

if __name__ == "__main__":
    process_all_logs()
