import requests


def check_otx(ioc, api_key):
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ioc}/general"
    headers = {"X-OTX-API-KEY": api_key}

    try:
        r = requests.get(url, headers=headers, timeout=10)
        data = r.json()

        pulse_count = data.get("pulse_info", {}).get("count", 0)

        if pulse_count == 0:
            return None

        pulses = data["pulse_info"]["pulses"]
        campaigns = [p.get("name") for p in pulses if p.get("name")]

        return {
            "source": "OTX",
            "malicious": True,
            "confidence": pulse_count,
            "campaign": campaigns[:3]
        }

    except Exception:
        return None
