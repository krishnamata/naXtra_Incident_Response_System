import requests
import os
import logging

THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"
THREATFOX_AUTH_KEY = os.environ.get("ABUSE_AUTH_KEY")

def search_threatfox_by_hash(ioc_hash):
    if not THREATFOX_AUTH_KEY:
        logging.error("ThreatFox Auth-Key not set in environment variable ABUSE_AUTH_KEY")
        return None

    headers = {
        "Auth-Key": THREATFOX_AUTH_KEY,
        "Content-Type": "application/json"
    }

    payload = {
        "query": "search_hash",
        "hash": ioc_hash
    }

    try:
        response = requests.post(THREATFOX_API_URL, json=payload, headers=headers, timeout=10)

        logging.debug(f"Response status: {response.status_code}")
        logging.debug(f"Response text: {response.text}")

        if response.status_code == 200:
            data = response.json()
            if data.get("query_status") == "ok" and data.get("data"):
                return data["data"]
            else:
                logging.warning(f"ThreatFox response: {data.get('query_status')} — No data for hash: {ioc_hash}")
        else:
            logging.warning(f"ThreatFox returned status {response.status_code} for hash: {ioc_hash}")

    except Exception as e:
        logging.error(f"Error querying ThreatFox: {e}")

    return None
