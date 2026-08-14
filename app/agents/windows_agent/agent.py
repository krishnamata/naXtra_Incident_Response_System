#!/usr/bin/env python3
"""
windows_agent.py - Production-ready Windows Event Log shipper for naXtra Pulse IR

Requirements:
    pip install requests pywin32

Usage:
    python windows_agent.py
Service:
    Install with NSSM or run via Windows Service wrapper.
"""

import os
import sys
import time
import json
import gzip
import queue
import socket
import hashlib
import logging
import threading
import traceback
from datetime import datetime, timezone
from typing import Dict, List, Optional

import requests

# pywin32 imports (Windows only)
try:
    import win32evtlog
    import win32evtlogutil
    import win32con
except Exception as e:
    if os.name == "nt":
        raise
    else:
        # Allow import failure on non-Windows for testing
        win32evtlog = None

### ---------- Configuration (edit or use env vars) ----------
SERVER_URL = os.environ.get("NP_SERVER_URL", "https://your-server.example.com/logs/upload")
AGENT_NAME = os.environ.get("NP_AGENT_NAME", socket.gethostname())
AGENT_TYPE = "windows"
LOG_POLL_INTERVAL = int(os.environ.get("NP_POLL_INTERVAL", "5"))  # seconds
BATCH_SIZE = int(os.environ.get("NP_BATCH_SIZE", "50"))
BATCH_INTERVAL = int(os.environ.get("NP_BATCH_INTERVAL", "10"))  # seconds
MAX_RETRIES = int(os.environ.get("NP_MAX_RETRIES", "6"))
MAX_QUEUE_SIZE = int(os.environ.get("NP_MAX_QUEUE_SIZE", "10000"))
VERIFY_TLS = os.environ.get("NP_VERIFY_TLS", "true").lower() in ("1", "true", "yes")
CLIENT_CERT = os.environ.get("NP_CLIENT_CERT", None)  # path to cert file or "cert.pem,key.pem"
JOURNAL_FILE = os.environ.get("NP_JOURNAL_FILE", "windows_agent_journal.jsonl")
LOG_FILE = os.environ.get("NP_AGENT_LOG", "windows_agent.log")
EVENT_LOGS = os.environ.get("NP_EVENT_LOGS", "Application,System,Security,Setup").split(",")  # which event logs to read
# Map windows channel to normalized log_type
WINDOWS_LOGTYPE_MAP = {
    "application": "application",
    "system": "system",
    "security": "security",
    "setup": "setup"
}

# ----------------------------------------------------------------

# logger
logger = logging.getLogger("windows_agent")
logger.setLevel(logging.INFO)
fh = logging.FileHandler(LOG_FILE)
fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
sh = logging.StreamHandler(sys.stdout)
sh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(fh)
logger.addHandler(sh)

# in-memory queue and lock
send_queue = queue.Queue(maxsize=MAX_QUEUE_SIZE)
queue_lock = threading.Lock()
stop_event = threading.Event()


### ---------- Utilities ----------

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def compute_hashes(text: str) -> Dict[str,str]:
    b = text.encode("utf-8", errors="replace")
    md5 = hashlib.md5(b).hexdigest()
    sha256 = hashlib.sha256(b).hexdigest()
    return {"md5": md5, "sha256": sha256}

def gzip_bytes(b: bytes) -> bytes:
    return gzip.compress(b)

def journal_append(record: dict):
    """Append record to local journal for persistence (jsonl)."""
    try:
        with open(JOURNAL_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, default=str) + "\n")
    except Exception:
        logger.exception("Failed to append to journal")

def journal_load() -> List[dict]:
    """Load unprocessed records from journal. Caller may want to clear file after load."""
    records = []
    if not os.path.exists(JOURNAL_FILE):
        return records
    try:
        with open(JOURNAL_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except Exception:
                    logger.exception("Skipping malformed journal line")
        # truncate after load (we keep processed items in memory)
        open(JOURNAL_FILE, "w").close()
    except Exception:
        logger.exception("Failed to load/truncate journal")
    return records

### ---------- Windows Event Reading ----------

def read_events_since(server="localhost", log_type="Application", bookmark=None, max_records=500):
    """
    Read events from Windows Event Log using win32evtlog.
    Returns list of event dicts.
    """
    if win32evtlog is None:
        return []

    events = []
    handle = None
    try:
        hand = win32evtlog.OpenEventLog(server, log_type)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        total = win32evtlog.GetNumberOfEventLogRecords(hand)
        read_count = 0
        while True:
            events_chunk = win32evtlog.ReadEventLog(hand, flags, 0)
            if not events_chunk:
                break
            for ev in events_chunk:
                try:
                    evt_time = ev.TimeGenerated.Format() if hasattr(ev, "TimeGenerated") else now_iso()
                    record = {
                        "record_number": getattr(ev, "RecordNumber", None),
                        "source_name": getattr(ev, "SourceName", None),
                        "event_id": getattr(ev, "EventID", None) & 0xFFFF,
                        "category": getattr(ev, "EventCategory", None),
                        "time_generated": evt_time,
                        "computer_name": getattr(ev, "ComputerName", None),
                        "message": win32evtlogutil.SafeFormatMessage(ev, log_type) if hasattr(win32evtlogutil, "SafeFormatMessage") else str(ev),
                        "raw": {
                            "event_type": getattr(ev, "EventType", None),
                            "event_type_str": _win_event_type_to_str(getattr(ev, "EventType", None))
                        }
                    }
                    events.append(record)
                    read_count += 1
                    if read_count >= max_records:
                        break
                except Exception:
                    logger.exception("Error formatting event")
            if read_count >= max_records:
                break
        win32evtlog.CloseEventLog(hand)
    except Exception:
        logger.exception("Error reading event log %s", log_type)
    return events

def _win_event_type_to_str(t):
    if t == win32con.EVENTLOG_AUDIT_FAILURE:
        return "AUDIT_FAILURE"
    if t == win32con.EVENTLOG_AUDIT_SUCCESS:
        return "AUDIT_SUCCESS"
    if t == win32con.EVENTLOG_INFORMATION_TYPE:
        return "INFORMATION"
    if t == win32con.EVENTLOG_WARNING_TYPE:
        return "WARNING"
    if t == win32con.EVENTLOG_ERROR_TYPE:
        return "ERROR"
    return str(t)

### ---------- Payload formatting ----------

def build_event_payload(events: List[dict], agent_name: str, agent_type: str, channel: str, is_summary: bool = False) -> dict:
    """
    Build the JSON structure expected by server /logs/upload.
    We include:
      - agent_name, agent_type
      - log_type (normalized): application/system/security/setup
      - message / log (string) for single events; when batch, message is a JSON list
      - md5/sha256 for the payload message
      - ip_address (local)
      - total_logs for summary
    """
    if not events:
        return {}

    # When batching, include list; server code reads `log` or `message`
    messages = []
    for ev in events:
        messages.append({
            "record_number": ev.get("record_number"),
            "source_name": ev.get("source_name"),
            "event_id": ev.get("event_id"),
            "category": ev.get("category"),
            "time_generated": ev.get("time_generated"),
            "message": ev.get("message"),
            "raw": ev.get("raw")
        })

    payload_message = json.dumps(messages, ensure_ascii=False)
    hashes = compute_hashes(payload_message)
    local_ip = _get_local_ip()

    payload = {
        "agent_name": agent_name,
        "agent_type": agent_type,
        "source": channel,
        "log_type": WINDOWS_LOGTYPE_MAP.get(channel.lower(), "application"),
        "log": payload_message,
        "message": payload_message,
        "md5_hash": hashes["md5"],
        "sha256_hash": hashes["sha256"],
        "ip_address": local_ip,
        "total_logs": len(events),
        "timestamp": now_iso(),
    }
    # For summary messages:
    if is_summary:
        payload["log_type"] = "summary"
    return payload

def _get_local_ip():
    try:
        # Try to get outbound IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        # connect to public DNS but do not send packets
        s.connect(("8.8.8.8", 53))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

### ---------- Sender worker ----------

def send_payload(payload: dict) -> bool:
    """
    Send payload to server with retries and backoff.
    Returns True on success, False otherwise.
    """
    if not payload:
        return True

    data_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    compressed = gzip_bytes(data_bytes)

    headers = {
        "Content-Type": "application/json",
        "Content-Encoding": "gzip",
        "User-Agent": f"naXtra-Windows-Agent/1.0",
    }

    verify = VERIFY_TLS
    cert = CLIENT_CERT if CLIENT_CERT else None

    backoff = 1
    attempt = 0
    while attempt <= MAX_RETRIES and not stop_event.is_set():
        try:
            resp = requests.post(SERVER_URL, data=compressed, headers=headers, timeout=20, verify=verify, cert=cert)
            if resp.status_code in (200, 201):
                logger.info("Sent payload: %d events -> %s", payload.get("total_logs", 1), SERVER_URL)
                return True
            else:
                logger.warning("Server responded %s: %s", resp.status_code, resp.text[:200])
        except Exception as e:
            logger.warning("Send attempt failed (%s). backoff=%ds", str(e), backoff)
        attempt += 1
        time.sleep(backoff)
        backoff = min(backoff * 2, 60)

    logger.error("Failed to send payload after %d attempts; will journal locally", MAX_RETRIES)
    try:
        journal_append({"payload": payload, "failed_at": now_iso()})
    except Exception:
        logger.exception("Failed to journal failed payload")
    return False

def sender_worker():
    """Continuously consume from send_queue and send payloads."""
    logger.info("Sender worker started")
    # First, load journaled items
    for rec in journal_load():
        try:
            payload = rec.get("payload")
            if payload:
                # put at front by sending immediately
                send_payload(payload)
        except Exception:
            logger.exception("Error resending journaled item")

    while not stop_event.is_set():
        try:
            payload = send_queue.get(timeout=1)
        except queue.Empty:
            continue
        try:
            sent = send_payload(payload)
            if not sent:
                # already journaled by send_payload
                pass
        except Exception:
            logger.exception("Error in sender worker")
        finally:
            send_queue.task_done()

### ---------- Polling + batching ----------

def poll_events_loop():
    """
    Poll windows event logs periodically and batch them.
    """
    last_seen = {}  # per-channel highest record_number seen, optional
    batch_buffers = {ch: [] for ch in EVENT_LOGS}

    while not stop_event.is_set():
        try:
            for channel in EVENT_LOGS:
                channel = channel.strip()
                if not channel:
                    continue
                events = read_events_since(server="localhost", log_type=channel, max_records=BATCH_SIZE)
                # naive dedupe: only add events not previously in buffer (based on record_number + time)
                for ev in reversed(events):  # read backwards -> reverse to chronological
                    rec_id = ev.get("record_number")
                    last = last_seen.get(channel)
                    if last and rec_id and last >= rec_id:
                        continue
                    batch_buffers[channel].append(ev)
                    if rec_id:
                        last_seen[channel] = rec_id

                # if batch size reached or enough time, flush
                if len(batch_buffers[channel]) >= BATCH_SIZE:
                    flush_batch(channel, batch_buffers)
            # periodic flush by interval
            time.sleep(LOG_POLL_INTERVAL)
            # flush by time: simple implementation flush every BATCH_INTERVAL seconds
            # (we rely on batch size primarily; for strict timing, track timestamps)
            for channel in list(batch_buffers.keys()):
                if batch_buffers[channel]:
                    # build payload
                    payload = build_event_payload(batch_buffers[channel], AGENT_NAME, AGENT_TYPE, channel)
                    enqueue_payload(payload)
                    batch_buffers[channel] = []
        except Exception:
            logger.exception("Exception in poll_events_loop")
            time.sleep(2)

def flush_batch(channel: str, buffers: dict):
    try:
        items = buffers[channel]
        if not items:
            return
        payload = build_event_payload(items, AGENT_NAME, AGENT_TYPE, channel)
        enqueue_payload(payload)
        buffers[channel] = []
    except Exception:
        logger.exception("flush_batch error for %s", channel)

def enqueue_payload(payload: dict):
    """Put payload into send_queue, or journal if queue is full."""
    if not payload:
        return
    try:
        send_queue.put_nowait(payload)
    except queue.Full:
        logger.warning("Send queue full; journaling payload")
        journal_append({"payload": payload, "queued_at": now_iso()})

### ---------- Heartbeat / Summary ----------

def send_summary():
    """
    Sends a periodic summary/heartbeat. Minimal content: agent_name, agent_type, total_logs=0, log_type='summary'.
    """
    payload = {
        "agent_name": AGENT_NAME,
        "agent_type": AGENT_TYPE,
        "log_type": "summary",
        "source": "agent-summary",
        "message": f"heartbeat from {AGENT_NAME}",
        "log": f"heartbeat {now_iso()}",
        "md5_hash": compute_hashes(AGENT_NAME + now_iso())["md5"],
        "sha256_hash": compute_hashes(AGENT_NAME + now_iso())["sha256"],
        "ip_address": _get_local_ip(),
        "total_logs": 0,
        "timestamp": now_iso()
    }
    enqueue_payload(payload)

def summary_loop(interval_seconds=60):
    while not stop_event.is_set():
        try:
            send_summary()
        except Exception:
            logger.exception("Summary loop error")
        stop_event.wait(interval_seconds)

### ---------- Lifecycle ----------

def start_agent():
    logger.info("Starting windows agent: %s -> %s", AGENT_NAME, SERVER_URL)
    # sender thread
    sender = threading.Thread(target=sender_worker, name="sender", daemon=True)
    sender.start()
    # poller thread
    poller = threading.Thread(target=poll_events_loop, name="poller", daemon=True)
    poller.start()
    # summary thread
    summaryer = threading.Thread(target=summary_loop, args=(60,), name="summary", daemon=True)
    summaryer.start()
    return [sender, poller, summaryer]

def stop_agent():
    logger.info("Stopping windows agent")
    stop_event.set()

### ---------- Signal handlers for graceful shutdown on Windows ----------
# Windows: use SetConsoleCtrlHandler - but simplest: catch KeyboardInterrupt
if __name__ == "__main__":
    try:
        threads = start_agent()
        # main thread waits
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt received, shutting down")
        stop_agent()
        # give threads time
        time.sleep(2)
    except Exception:
        logger.exception("Fatal error in agent main")
        stop_agent()
        time.sleep(2)
