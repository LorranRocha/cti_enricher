import requests


def check_otx(ioc, ioc_type, api_key):
    base_url = "https://otx.alienvault.com/api/v1/indicators"

    endpoint_map = {
        "ip": "IPv4",
        "url": "url",
        "md5": "file",
        "sha1": "file",
        "sha256": "file",
    }

    endpoint = endpoint_map.get(ioc_type)

    if not endpoint:
        return None

    url = f"{base_url}/{endpoint}/{ioc}/general"
    headers = {"X-OTX-API-KEY": api_key}

    try:
        r = requests.get(url, headers=headers, timeout=10)
        data = r.json()

        pulse_info = data.get("pulse_info", {})
        pulses = pulse_info.get("pulses", [])

        if not pulses:
            return None

        return {
            "source": "OTX",
            "malicious": True,
            "confidence": pulse_info.get("count", 0),
            "campaigns": [p.get("name") for p in pulses if p.get("name")],
            "tags": [t for p in pulses for t in p.get("tags", [])],
            "references": [p.get("reference") for p in pulses if p.get("reference")],
        }

    except Exception:
        return None
