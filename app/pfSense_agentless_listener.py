# pfSense_agentless_listener_with_fim.py
import socket
import json
import hashlib
import requests
import time
import os

# =========================
# --- Configuration ---
# =========================
LISTEN_IP = "192.168.56.1"       
LISTEN_PORT = 514
ALLOWED_SOURCE_IP = "192.168.56.101"  
SERVER_URL_LOGS = "http://192.168.18.162:5001/api/logs/upload"
API_KEY = "naxtraSOAR-key"
AGENT_NAME = "pfSense"           
AGENT_TYPE = "network"           

# Critical pfSense files to monitor
FIM_FILES = [
    "/cf/conf/config.xml"
]

# =========================
# --- Helper Functions ---
# =========================
def md5_hash(data: str) -> str:
    return hashlib.md5(data.encode()).hexdigest()

def send_log_to_server(log_message: str, log_type: str, file_path: str = None, baseline_hash: str = None, current_hash: str = None):
    payload = {
        "agent_name": AGENT_NAME,
        "agent_type": AGENT_TYPE,
        "log": log_message,
        "log_type": log_type,
        "md5_hash": md5_hash(log_message),
        "ip_address": ALLOWED_SOURCE_IP
    }
    if file_path:
        payload["raw_log"] = {
            "event": "fim_event",
            "file_path": file_path,
            "baseline_hash": baseline_hash,
            "current_hash": current_hash
        }
    headers = {"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"}
    try:
        resp = requests.post(SERVER_URL_LOGS, json=payload, headers=headers, timeout=5)
        if resp.status_code != 201:
            print(f"[WARN] Server responded: {resp.status_code} {resp.text}")
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Failed to send payload: {e}")
        time.sleep(5)
        send_log_to_server(log_message, log_type, file_path, baseline_hash, current_hash)

# FIM monitoring
def fim_monitor(previous_hashes: dict):
    for file_path in FIM_FILES:
        if not os.path.exists(file_path):
            continue
        try:
            with open(file_path, "rb") as f:
                current_hash = hashlib.md5(f.read()).hexdigest()
            old_hash = previous_hashes.get(file_path)
            if old_hash is None:
                previous_hashes[file_path] = current_hash
            elif old_hash != current_hash:
                msg = f"FIM alert: {file_path} modified"
                send_log_to_server(msg, "fim", file_path, old_hash, current_hash)
                print(f"[ALERT] {msg}")
                previous_hashes[file_path] = current_hash
        except Exception as e:
            print(f"[ERROR] FIM monitoring failed for {file_path}: {e}")

# UDP Listener
def udp_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((LISTEN_IP, LISTEN_PORT))
    print(f"[INFO] Listening for UDP logs on {LISTEN_IP}:{LISTEN_PORT} from {ALLOWED_SOURCE_IP}")
    
    while True:
        try:
            data, addr = sock.recvfrom(65535)
            source_ip = addr[0]
            if source_ip != ALLOWED_SOURCE_IP:
                print(f"[SECURITY] Ignored packet from unauthorized IP: {source_ip}")
                continue

            log_message = data.decode(errors="ignore").strip()
            if not log_message:
                continue

            # Simple log type detection
            log_type = "syslog"
            if "filterlog" in log_message:
                log_type = "firewall"
            elif "dhcpd" in log_message:
                log_type = "dhcp"
            elif "openvpn" in log_message or "vpn" in log_message:
                log_type = "vpn"
            elif "ntpd" in log_message:
                log_type = "ntp"

            send_log_to_server(log_message, log_type)
            print(f"[INFO] [{log_type}] {log_message}")

        except KeyboardInterrupt:
            print("\n[INFO] Listener shutting down...")
            break
        except Exception as e:
            print(f"[ERROR] Listener exception: {e}")
            time.sleep(1)

def main():
    # Initialize FIM hashes
    previous_hashes = {}
    for file_path in FIM_FILES:
        if os.path.exists(file_path):
            with open(file_path, "rb") as f:
                previous_hashes[file_path] = hashlib.md5(f.read()).hexdigest()

    print("[INFO] FIM monitoring initialized.")

    # Start UDP listener in background
    import threading
    listener_thread = threading.Thread(target=udp_listener, daemon=True)
    listener_thread.start()

    # Periodically check for config changes
    try:
        while True:
            fim_monitor(previous_hashes)
            time.sleep(60)
    except KeyboardInterrupt:
        print("\n[INFO] Agentless listener stopped.")

if __name__ == "__main__":
    main()
