import requests
import os


HYBRID_API_KEY = os.environ.get("HYBRID_ANALYSIS_API_KEY")
BASE_URL = "https://www.hybrid-analysis.com/api/v2"


def search_by_hash(sha256):
    if not HYBRID_API_KEY:
        raise ValueError("Hybrid Analysis API key not set")

    url = f"https://www.hybrid-analysis.com/api/v2/search/hash?hash={sha256}"
    headers = {
        "api-key": HYBRID_API_KEY,
        "User-Agent": "Falcon Sandbox"
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"[HybridAnalysis] Failed: {response.status_code} — {response.text}")
            return None
    except Exception as e:
        print(f"[HybridAnalysis] Exception: {e}")
        return None
