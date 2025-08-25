import time
import requests
import platform
import hashlib
import os
import win32evtlog  # pip install pywin32

SERVER_URL = "http://127.0.0.1:5001/api/logs"
INTERVAL = 5  # seconds
sent_logs = set()  # Track sent log entries (hashed)

def is_duplicate(line):
    hash_val = hashlib.md5(line.encode()).hexdigest()
    if hash_val in sent_logs:
        return True
    sent_logs.add(hash_val)
    if len(sent_logs) > 5000:
        sent_logs.pop()
    return False

def send_log(log_type, line):
    payload = {
        'source': 'windows',
        'log_type': log_type,
        'message': line,
        'agent_name': platform.node().lower()
    }
    try:
        requests.post(SERVER_URL, json=payload)
    except Exception as e:
        print(f"Error sending {log_type} log: {e}")

def read_windows_event_logs(log_type='Security'):
    server = 'localhost'
    hand = win32evtlog.OpenEventLog(server, log_type)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    while True:
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        if not events:
            break
        for ev_obj in events:
            msg = win32evtlog.FormatMessage(ev_obj)
            if msg and not is_duplicate(msg):
                send_log(log_type, msg)
        time.sleep(INTERVAL)

if __name__ == '__main__':
    print("Windows Agent started...")
    try:
        requests.post(SERVER_URL, json={"log": "Windows Agent Connected", "os": "Windows", "log_type": "agent"})
    except:
        pass

    read_windows_event_logs('Security')  # You can loop through ["Security", "System", "Application"]
