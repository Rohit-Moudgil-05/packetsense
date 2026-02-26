import requests
import time
import json
import pandas as pd
from pathlib import Path

CACHE_FILE = Path("cache/threat_cache.json")
CACHE_FILE.parent.mkdir(exist_ok=True)

ABUSEIPDB_KEY = None  # put in environment variable
VT_KEY = None          # put in environment variable


def load_cache():
    if CACHE_FILE.exists():
        try:
            return json.loads(CACHE_FILE.read_text())
        except:
            return {}
    return {}


def save_cache(obj):
    try:
        CACHE_FILE.write_text(json.dumps(obj))
    except:
        pass


def threat_lookup(ip_list):
    cache = load_cache()
    now = int(time.time())
    results = []

    for ip in ip_list:
        # cached
        if ip in cache and (now - cache[ip]["ts"] < 48 * 3600):
            results.append(cache[ip]["entry"])
            continue

        entry = {"ip": ip, "risk": "Low", "abuse": 0}

        # Geo lookup
        try:
            geo = requests.get(f"http://ip-api.com/json/{ip}", timeout=3).json()
            entry["country"] = geo.get("country", "-")
            entry["isp"] = geo.get("isp", "-")
        except:
            entry["country"] = "-"
            entry["isp"] = "-"

        entry["risk"] = "Low"
        entry["abuse"] = 0

        cache[ip] = {"ts": now, "entry": entry}
        results.append(entry)

    save_cache(cache)
    return pd.DataFrame(results)
