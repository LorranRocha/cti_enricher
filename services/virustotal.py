import requests


def check_virustotal(ioc, api_key):
    url = f"https://www.virustotal.com/api/v3/search?query={ioc}"
    headers = {"x-apikey": api_key}

    try:
        r = requests.get(url, headers=headers, timeout=10)
        data = r.json()

        if "data" not in data or not data["data"]:
            return None

        stats = data["data"][0]["attributes"]["last_analysis_stats"]
        malicious_count = stats.get("malicious", 0)

        return {
            "source": "VirusTotal",
            "malicious": malicious_count > 0,
            "confidence": malicious_count,
            "tags": data["data"][0]["attributes"].get("tags", [])
        }

    except Exception:
        return None
