import yaml
from services.virustotal import check_virustotal
from services.otx import check_otx
from services.abusech import check_abusech


def load_config():
    with open("config.yml", "r") as f:
        return yaml.safe_load(f)


def get_iocs():
    print("Enter IOCs (IPs, URLs, hashes). Type 'done' to finish:\n")
    iocs = []
    while True:
        ioc = input("IOC: ").strip()
        if ioc.lower() == "done":
            break
        if ioc:
            iocs.append(ioc)
    return iocs


def analyze_ioc(ioc, config):
    print(f"\n[+] Analyzing IOC: {ioc}")

    results = {
        "ioc": ioc,
        "sources": []
    }

    vt = check_virustotal(ioc, config["virustotal"]["api_key"])
    if vt:
        results["sources"].append(vt)

    otx = check_otx(ioc, config["otx"]["api_key"])
    if otx:
        results["sources"].append(otx)

    abuse = check_abusech(ioc)
    if abuse:
        results["sources"].append(abuse)

    return results


def summarize(results):
    print("\n========== SUMMARY ==========\n")
    for r in results:
        print(f"IOC: {r['ioc']}")

        if not r["sources"]:
            print("  -> No relevant data found\n")
            continue

        for source in r["sources"]:
            print(f"  Source: {source['source']}")
            print(f"    Malicious: {source['malicious']}")

            if source.get("confidence"):
                print(f"    Confidence: {source['confidence']}")

            if source.get("campaign"):
                print(f"    Campaign: {source['campaign']}")

            if source.get("tags"):
                print(f"    Tags: {', '.join(source['tags'])}")

        print()


def main():
    config = load_config()
    iocs = get_iocs()

    results = []
    for ioc in iocs:
        results.append(analyze_ioc(ioc, config))

    summarize(results)


if __name__ == "__main__":
    main()
