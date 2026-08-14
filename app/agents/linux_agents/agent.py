#!/usr/bin/env python3
import os
import time
import socket
import platform
import hashlib
import requests
import configparser
import signal
import sys
from multiprocessing import Process

# ==========================
# --- Agent Configuration ---
# ==========================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.ini")

config = configparser.ConfigParser()
if not config.read(CONFIG_PATH):
    raise RuntimeError("config.ini not found")

AGENT_NAME = socket.gethostname().lower()        # e.g. kali
AGENT_TYPE = platform.system().lower()           # linux

SERVER_URL_LOGS = config.get("SERVER", "logs_url")
SERVER_URL_FIM  = config.get("SERVER", "fim_url")
API_KEY = config.get("SERVER", "api_key")
INTERVAL = config.getint("AGENT", "interval", fallback=60)

LOG_FILES = dict(config.items("LOGS"))

MONITORED_DIRS = [d.strip() for d in config.get("FIM", "dirs").split(",")]
IGNORE_PATTERNS = [p.strip() for p in config.get("FIM", "ignore").split(",")]

completed_flags = {}

# =======================
# --- Helper Functions ---
# =======================

def md5_hash(data: str) -> str:
    return hashlib.md5(data.encode(errors="ignore")).hexdigest()

def get_ip_address():
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception:
        return "0.0.0.0"

def send_payload(url, payload):
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }
    try:
        r = requests.post(url, json=payload, headers=headers, timeout=5)
        if r.status_code not in (200, 201):
            print(f"[WARN] Server responded {r.status_code}: {r.text}")
    except Exception as e:
        print(f"[ERROR] Failed to send payload: {e}")

# ==============================
# --- Log Summary / Tailing ---
# ==============================

def send_summary():
    total_lines = 0
    total_size = 0

    for path in LOG_FILES.values():
        if os.path.isfile(path):
            try:
                total_lines += sum(1 for _ in open(path, errors="ignore"))
                total_size += os.path.getsize(path)
            except Exception:
                pass

    payload = {
        "agent_name": AGENT_NAME,
        "agent_type": AGENT_TYPE,
        "log_type": "summary",
        "log": f"Summary: {total_lines} logs, {total_size/1024:.2f} KB",
        "md5_hash": md5_hash(f"{AGENT_NAME}{total_lines}{total_size}"),
        "raw_log": {
            "event": "summary",
            "total_logs": total_lines,
            "total_size_kb": round(total_size / 1024, 2)
        },
        "ip_address": get_ip_address()
    }
    send_payload(SERVER_URL_LOGS, payload)

def tail_file(path, log_type):
    if not os.path.isfile(path):
        return

    with open(path, "r", errors="ignore") as f:
        f.seek(0, os.SEEK_END)

        while True:
            line = f.readline()
            if not line:
                if not completed_flags.get(path):
                    payload = {
                        "agent_name": AGENT_NAME,
                        "agent_type": AGENT_TYPE,
                        "log_type": "status",
                        "log": f"All logs submitted successfully for {log_type}",
                        "md5_hash": md5_hash(f"{AGENT_NAME}{log_type}done"),
                        "raw_log": {"event": "completed"},
                        "ip_address": get_ip_address()
                    }
                    send_payload(SERVER_URL_LOGS, payload)
                    completed_flags[path] = True
                time.sleep(0.5)
                continue

            completed_flags[path] = False

            payload = {
                "agent_name": AGENT_NAME,
                "agent_type": AGENT_TYPE,
                "log_type": log_type,
                "log": line.strip(),
                "md5_hash": md5_hash(line),
                "raw_log": {"event": line.strip()},
                "ip_address": get_ip_address()
            }
            send_payload(SERVER_URL_LOGS, payload)

# =======================
# --- FIM Monitoring ---
# =======================

def should_monitor(path):
    return os.path.isfile(path) and not any(p in path for p in IGNORE_PATTERNS)

def discover_files():
    files = []
    for d in MONITORED_DIRS:
        if not os.path.exists(d):
            continue
        for root, _, names in os.walk(d):
            for name in names:
                full = os.path.join(root, name)
                if should_monitor(full):
                    files.append(full)
    return files

def fim_loop():
    prev_hash = {}

    for f in discover_files():
        try:
            with open(f, "rb") as fh:
                prev_hash[f] = hashlib.md5(fh.read()).hexdigest()
        except Exception:
            pass

    while True:
        current = discover_files()

        # Deleted files
        for f in list(prev_hash):
            if f not in current:
                payload = {
                    "agent_name": AGENT_NAME,
                    "agent_type": AGENT_TYPE,
                    "log_type": "fim",
                    "log": f"FIM alert: {f} deleted",
                    "md5_hash": "",
                    "raw_log": {
                        "event": "deleted",
                        "file_path": f,
                        "baseline_hash": prev_hash[f]
                    },
                    "ip_address": get_ip_address()
                }
                send_payload(SERVER_URL_FIM, payload)
                prev_hash.pop(f, None)

        # New / modified files
        for f in current:
            try:
                with open(f, "rb") as fh:
                    h = hashlib.md5(fh.read()).hexdigest()
            except Exception:
                continue

            if f not in prev_hash:
                change = "created"
            elif prev_hash[f] != h:
                change = "modified"
            else:
                continue

            payload = {
                "agent_name": AGENT_NAME,
                "agent_type": AGENT_TYPE,
                "log_type": "fim",
                "log": f"FIM alert: {f} {change}",
                "md5_hash": h,
                "raw_log": {
                    "event": change,
                    "file_path": f,
                    "baseline_hash": prev_hash.get(f),
                    "current_hash": h
                },
                "ip_address": get_ip_address()
            }
            send_payload(SERVER_URL_FIM, payload)
            prev_hash[f] = h

        time.sleep(INTERVAL)

# ==================
# --- Main Logic ---
# ==================

def shutdown(sig, frame):
    print("[INFO] Agent stopped")
    sys.exit(0)

signal.signal(signal.SIGINT, shutdown)
signal.signal(signal.SIGTERM, shutdown)

def main():
    print(f"[INFO] Linux Agent started: {AGENT_NAME} ({AGENT_TYPE})")
    send_summary()

    for log_type, path in LOG_FILES.items():
        Process(target=tail_file, args=(path, log_type), daemon=True).start()

    Process(target=fim_loop, daemon=True).start()

    while True:
        time.sleep(INTERVAL)

if __name__ == "__main__":
    main()
