import requests


def check_abusech(ioc, ioc_type):
    if ioc_type not in ["md5", "sha1", "sha256"]:
        return None

    url = "https://mb-api.abuse.ch/api/v1/"
    data = {"query": "get_info", "hash": ioc}

    try:
        r = requests.post(url, data=data, timeout=10)
        res = r.json()

        if res.get("query_status") != "ok":
            return None

        entry = res["data"][0]

        return {
            "source": "Abuse.ch",
            "malicious": True,
            "campaigns": [entry.get("signature")],
            "tags": [entry.get("file_type"), entry.get("signature")],
        }

    except Exception:
        return None
