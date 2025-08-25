import subprocess
import time
import requests
import platform
import hashlib
import json
import os
import socket  # ➕ Import to get IP address

SERVER_URL = "http://192.168.18.162:5001/api/logs/upload"  # Change to your server IP
INTERVAL = 1  # seconds between log reads
CURSOR_FILE = "journal_cursor.txt"  # file to save last cursor

sent_logs = set()

def get_local_ip():
    try:
        # Use UDP trick to get outbound IP address (does not actually connect)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "0.0.0.0"

def is_duplicate(line):
    hash_val = hashlib.md5(line.encode()).hexdigest()
    if hash_val in sent_logs:
        return True
    sent_logs.add(hash_val)
    if len(sent_logs) > 5000:
        sent_logs.pop()
    return False

def send_log(log_type, line, raw_log=None):
    md5 = hashlib.md5(line.encode()).hexdigest()
    agent = platform.node().lower()
    ip_address = get_local_ip()  # ➕ Get IP address

    if raw_log is None:
        raw_log = {
            "event": line,
            "log_type": log_type,
            "agent_name": agent,
            "ip_address": ip_address
        }
    else:
        raw_log.setdefault("event", line)
        raw_log.setdefault("log_type", log_type)
        raw_log.setdefault("agent_name", agent)
        raw_log.setdefault("ip_address", ip_address)  # ➕ Add IP address if not present

    payload = {
        'agent_name': agent,
        'log': line,
        'log_type': log_type,
        'md5_hash': md5,
        'raw_log': raw_log,
    }

    headers = {'Content-Type': 'application/json'}
    try:
        response = requests.post(SERVER_URL, json=payload, headers=headers, timeout=5)
        if response.status_code != 200:
            print(f"Warning: Server responded with status {response.status_code}")
    except Exception as e:
        print(f"Error sending {log_type} log: {e}")

def load_cursor():
    if os.path.exists(CURSOR_FILE):
        with open(CURSOR_FILE, 'r') as f:
            cursor = f.read().strip()
            if cursor:
                return cursor
    return None

def save_cursor(cursor):
    with open(CURSOR_FILE, 'w') as f:
        f.write(cursor)

def follow_journal():
    cursor = load_cursor()
    cmd = ['journalctl', '-f', '-o', 'json']
    if cursor:
        cmd.insert(1, f'--after-cursor={cursor}')
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        universal_newlines=True
    )
    while True:
        line = proc.stdout.readline()
        if not line:
            time.sleep(INTERVAL)
            continue
        line = line.strip()
        if line and not is_duplicate(line):
            try:
                raw_log = json.loads(line)
                message = raw_log.get('MESSAGE', '') or raw_log.get('__REALTIME_TIMESTAMP', '')
                cursor_val = raw_log.get('__CURSOR')
                if cursor_val:
                    save_cursor(cursor_val)
            except Exception:
                raw_log = {"unparsed": line}
                message = line
            send_log("journal", message, raw_log)

if __name__ == '__main__':
    print("Linux Agent started (journalctl JSON mode)...")
    try:
        follow_journal()
    except KeyboardInterrupt:
        print("\n[+] Agent stopped by user.")
    except Exception as e:
        print(f"Unexpected error: {e}")
