import subprocess
import time
import requests
import platform
import configparser
import hashlib
import json
import os
import socket
from multiprocessing import Process
import signal
import sys

# ==========================
# --- Agent Configuration ---
# ==========================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.ini")

config = configparser.ConfigParser()
if not config.read(CONFIG_PATH):
    raise RuntimeError("config.ini not found or unreadable")


AGENT_NAME = socket.gethostname().lower()
AGENT_TYPE = platform.system().lower()

SERVER_URL_LOGS = config.get("SERVER", "logs_url")
SERVER_URL_FIM  = config.get("SERVER", "fim_url")
API_KEY = config.get("SERVER", "api_key")
AGENT_INTERVAL = config.getint("AGENT", "interval", fallback=60)

# --- Log files to monitor ---
LOG_FILES = dict(config.items("LOGS"))
completed_flags = {}

# --- File Integrity Monitoring (FIM) Settings ---
MONITORED_DIRS = [
    d.strip() for d in config.get("FIM", "dirs").split(",")
]

IGNORE_PATTERNS = [
    p.strip() for p in config.get("FIM", "ignore").split(",")
]


# =======================
# --- Helper Functions ---
# =======================
def md5_hash(data: str) -> str:
    return hashlib.md5(data.encode()).hexdigest()

def get_ip_address() -> str:
    try:
        return socket.gethostbyname(socket.gethostname())
    except:
        return "0.0.0.0"

def send_payload(url, payload: dict):
    """Send JSON payload to server with API key authentication."""
    headers = {"Authorization": f"Bearer naxtraSOAR-key", "Content-Type": "application/json"}
    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=5)
        if resp.status_code != 201:
            print(f"[WARN] Server responded: {resp.status_code} {resp.text}")
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Failed to send payload: {e}")
        time.sleep(5)
        send_payload(url, payload)

# ==============================
# --- Log Summary / Tailing ---
# ==============================
def send_summary():
    total_logs, total_size = 0, 0
    for path in LOG_FILES.values():
        if os.path.exists(path) and os.path.isfile(path):
            try:
                with open(path, "r", errors="ignore") as f:
                    lines = f.readlines()
                    total_logs += len(lines)
                total_size += os.path.getsize(path)
            except Exception:
                continue

    payload = {
        "agent_name": AGENT_NAME,
        "agent_type": AGENT_TYPE,
        "log": f"Summary: {total_logs} logs, {total_size/1024:.2f} KB",
        "log_type": "summary",
        "md5_hash": md5_hash(f"{AGENT_NAME}{total_logs}{total_size}"),
        "raw_log": {
            "event": "summary",
            "total_logs": total_logs,
            "total_size_bytes": total_size,
            "total_size_kb": round(total_size / 1024, 2),
            "start_time": time.strftime("%Y-%m-%d %H:%M:%S")
        },
        "ip_address": get_ip_address()
    }
    send_payload(SERVER_URL_LOGS, payload)
    print(f"[INFO] Sent summary: {total_logs} logs, {total_size/1024:.2f} KB")

def tail_file(path, log_type):
    if not os.path.exists(path) or not os.path.isfile(path):
        print(f"[WARN] Log file not found or not a file: {path}")
        return

    with open(path, "r", errors="ignore") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                if not completed_flags.get(path, False):
                    payload = {
                        "agent_name": AGENT_NAME,
                        "agent_type": AGENT_TYPE,
                        "log": f"All logs submitted successfully for {log_type}",
                        "log_type": "status",
                        "md5_hash": md5_hash(f"{AGENT_NAME}{log_type}completed"),
                        "raw_log": {
                            "event": "all_logs_submitted",
                            "log_type": log_type,
                            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                        },
                        "ip_address": get_ip_address()
                    }
                    send_payload(SERVER_URL_LOGS, payload)
                    print(f"[INFO] ✅ All logs submitted successfully for {log_type}")
                    completed_flags[path] = True
                time.sleep(0.5)
                continue

            completed_flags[path] = False
            payload = {
                "agent_name": AGENT_NAME,
                "agent_type": AGENT_TYPE,
                "log": str(line).strip(),
                "log_type": log_type,
                "md5_hash": md5_hash(str(line).strip()),
                "raw_log": {"event": str(line).strip()},
                "ip_address": get_ip_address()
            }
            send_payload(SERVER_URL_LOGS, payload)

# =======================
# --- FIM Monitoring ---
# =======================
def should_monitor(file_path):
    return os.path.isfile(file_path) and not any(pat in file_path for pat in IGNORE_PATTERNS)

def discover_files():
    files = []
    for directory in MONITORED_DIRS:
        if not os.path.exists(directory):
            continue
        if os.path.isfile(directory):
            if should_monitor(directory):
                files.append(directory)
            continue
        for root, _, filenames in os.walk(directory):
            for fname in filenames:
                filepath = os.path.join(root, fname)
                if should_monitor(filepath):
                    files.append(filepath)
    return files

def fim_monitor_loop():
    previous_hashes = {}
    previous_stats = {}

    MONITORED_FILES = discover_files()

    # Initial scan
    for file in MONITORED_FILES:
        try:
            stat = os.stat(file)
            previous_stats[file] = (stat.st_size, stat.st_mtime)
            with open(file, "rb") as f:
                previous_hashes[file] = hashlib.md5(f.read()).hexdigest()
        except Exception:
            continue

    while True:
        current_files = discover_files()

        # Deleted files
        deleted_files = set(previous_hashes.keys()) - set(current_files)
        for file in deleted_files:
            payload = {
                "agent_name": AGENT_NAME,
                "agent_type": AGENT_TYPE,
                "log": f"FIM alert: {file} deleted",
                "log_type": "fim",
                "md5_hash": "",
                "raw_log": {
                    "event": "fim_event_deleted",
                    "file_path": file,
                    "baseline_hash": previous_hashes[file],
                    "current_hash": None,
                    "signature_status": "unknown"
                },
                "ip_address": get_ip_address()
            }
            send_payload(SERVER_URL_FIM, payload)
            previous_hashes.pop(file, None)
            previous_stats.pop(file, None)

        # New or modified files
        for file in current_files:
            try:
                stat = os.stat(file)
                current_size, current_mtime = stat.st_size, stat.st_mtime
            except Exception:
                continue

            old_stat = previous_stats.get(file)
            if old_stat is None or old_stat != (current_size, current_mtime):
                try:
                    with open(file, "rb") as f:
                        current_hash = hashlib.md5(f.read()).hexdigest()
                except Exception:
                    continue

                old_hash = previous_hashes.get(file)
                change_type = "created" if old_hash is None else "modified"

                payload = {
                    "agent_name": AGENT_NAME,
                    "agent_type": AGENT_TYPE,
                    "log": f"FIM alert: {file} {change_type}",
                    "log_type": "fim",
                    "md5_hash": current_hash,
                    "raw_log": {
                        "event": f"fim_event_{change_type}",
                        "file_path": file,
                        "baseline_hash": old_hash,
                        "current_hash": current_hash,
                        "signature_status": "unknown"
                    },
                    "ip_address": get_ip_address()
                }
                send_payload(SERVER_URL_FIM, payload)
                previous_hashes[file] = current_hash
                previous_stats[file] = (current_size, current_mtime)

        time.sleep(AGENT_INTERVAL)

# ==================
# --- Main Logic ---
# ==================
def signal_handler(sig, frame):
    print("\n[INFO] Agent shutting down gracefully...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def start_tail_file(path, log_type):
    process = Process(target=tail_file, args=(path, log_type))
    process.start()
    return process

def main():
    print(f"[INFO] Linux Agent started as {AGENT_NAME} ({AGENT_TYPE})")
    send_summary()

    for log_type, path in LOG_FILES.items():
        if os.path.exists(path):
            start_tail_file(path, log_type)

    fim_process = Process(target=fim_monitor_loop)
    fim_process.start()
    print("[INFO] ✅ FIM monitoring started in background.")

if __name__ == '__main__':
    try:
        main()
        while True:
            time.sleep(AGENT_INTERVAL)
    except KeyboardInterrupt:
        print("\n[+] Agent stopped by user.")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
