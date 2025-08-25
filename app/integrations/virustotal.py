import requests

VIRUSTOTAL_API_KEY = "YOUR_API_KEY_HERE"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/files/{}"

def query_virustotal(file_hash: str) -> dict | None:
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    url = VIRUSTOTAL_URL.format(file_hash)
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            return response.json()
        else:
            logger.warning(f"VirusTotal API error: {response.status_code} {response.text}")
    except Exception as e:
        logger.error(f"VirusTotal API exception: {e}")
    return None
