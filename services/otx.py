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
        response = requests.get(url, headers=headers, timeout=10)
        data = response.json()

        pulse_info = data.get("pulse_info", {})
        pulses = pulse_info.get("pulses", [])

        if not pulses:
            return None

        campaigns = []
        tags = []
        references = []

        for pulse in pulses:
            name = pulse.get("name")
            if name and name not in campaigns:
                campaigns.append(name)

            for tag in pulse.get("tags", []):
                if tag and tag not in tags:
                    tags.append(tag)

            reference = pulse.get("reference")
            if reference and reference not in references:
                references.append(reference)

        return {
            "source": "OTX",
            "malicious": True,
            "confidence": pulse_info.get("count", 0),
            "campaigns": campaigns[:5],
            "tags": tags[:10],
            "references": references[:5],
        }

    except Exception:
        return None
