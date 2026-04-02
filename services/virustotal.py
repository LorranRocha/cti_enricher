import requests


def check_virustotal(ioc, ioc_type, api_key):
    url = f"https://www.virustotal.com/api/v3/search?query={ioc}"
    headers = {"x-apikey": api_key}

    try:
        r = requests.get(url, headers=headers, timeout=10)
        data = r.json()

        if "data" not in data or not data["data"]:
            return None

        attr = data["data"][0]["attributes"]
        stats = attr.get("last_analysis_stats", {})

        return {
            "source": "VirusTotal",
            "malicious": stats.get("malicious", 0) > 0,
            "confidence": stats.get("malicious", 0),
            "tags": attr.get("tags", []),
            "names": attr.get("names", []),
        }

    except Exception:
        return None
