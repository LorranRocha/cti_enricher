import requests


def check_abusech(ioc, ioc_type, api_key=None):
    if ioc_type not in ["md5", "sha1", "sha256"]:
        return None

    url = "https://mb-api.abuse.ch/api/v1/"
    data = {
        "query": "get_info",
        "hash": ioc
    }

    headers = {}
    if api_key:
        headers["Auth-Key"] = api_key

    try:
        response = requests.post(url, data=data, headers=headers, timeout=15)

        if response.status_code == 401:
            return {
                "source": "Abuse.ch",
                "malicious": None,
                "error": "Unauthorized (401) from Abuse.ch API"
            }

        if response.status_code != 200:
            return {
                "source": "Abuse.ch",
                "malicious": None,
                "error": f"HTTP {response.status_code} from Abuse.ch API"
            }

        result = response.json()

        if result.get("query_status") != "ok":
            return None

        entries = result.get("data", [])
        if not entries:
            return None

        entry = entries[0]

        tags = []
        if entry.get("file_type"):
            tags.append(entry["file_type"])
        if entry.get("signature"):
            tags.append(entry["signature"])

        extra_tags = entry.get("tags", [])
        if isinstance(extra_tags, list):
            for tag in extra_tags:
                if tag and tag not in tags:
                    tags.append(tag)

        campaigns = []
        if entry.get("signature"):
            campaigns.append(entry["signature"])

        references = []
        if entry.get("sha256_hash"):
            references.append(entry["sha256_hash"])

        return {
            "source": "Abuse.ch",
            "malicious": True,
            "confidence": 100,
            "campaigns": campaigns,
            "tags": tags,
            "references": references,
        }

    except Exception as error:
        return {
            "source": "Abuse.ch",
            "malicious": None,
            "error": str(error)
        }
