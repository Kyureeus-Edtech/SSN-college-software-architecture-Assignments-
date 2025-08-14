import os
import requests
from dotenv import load_dotenv

# Load API key from .env
load_dotenv()
API_KEY = os.getenv("ABUSEIPDB_API_KEY")
BASE_URL = "https://api.abuseipdb.com/api/v2/check"

def check_ip(ip_address, max_age_days=90):
    """
    Query AbuseIPDB for an IP address.

    Args:
        ip_address (str): IP to check.
        max_age_days (int): Lookback window in days (default 90).
    Returns:
        dict: Parsed JSON from AbuseIPDB.
    Raises:
        requests.HTTPError: If the API returns an error status.
        RuntimeError: If API key is missing.
    """
    if not API_KEY:
        raise RuntimeError("ABUSEIPDB_API_KEY is not set in the environment.")

    headers = {
        "Accept": "application/json",
        "Key": API_KEY
    }
    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": str(max_age_days)
    }
    resp = requests.get(BASE_URL, headers=headers, params=params, timeout=30)
    resp.raise_for_status()
    return resp.json()
