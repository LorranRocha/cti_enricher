import re


def detect_ioc_type(ioc):
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ioc):
        return "ip"

    if ioc.startswith("http://") or ioc.startswith("https://"):
        return "url"

    if re.match(r"^[a-fA-F0-9]{32}$", ioc):
        return "md5"

    if re.match(r"^[a-fA-F0-9]{40}$", ioc):
        return "sha1"

    if re.match(r"^[a-fA-F0-9]{64}$", ioc):
        return "sha256"

    return "unknown"


def summarize_source_hits(sources):
    return [source["source"] for source in sources]


def calculate_score(sources):
    if not sources:
        return {"value": 0, "severity": "None"}

    score = 0

    for source in sources:
        if source.get("malicious"):
            score += 30

        confidence = source.get("confidence")
        if confidence:
            score += min(int(confidence), 20)

    score = min(score, 100)

    if score > 75:
        severity = "High"
    elif score > 40:
        severity = "Medium"
    else:
        severity = "Low"

    return {"value": score, "severity": severity}
