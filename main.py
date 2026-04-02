import argparse
import json
import sys

import yaml

from services.abusech import check_abusech
from services.otx import check_otx
from services.virustotal import check_virustotal
from utils import calculate_score, detect_ioc_type, summarize_source_hits


def load_config():
    with open("config.yml", "r", encoding="utf-8") as file:
        return yaml.safe_load(file)


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="CTI Enricher - enrich IOCs using multiple threat intelligence sources"
    )
    parser.add_argument(
        "iocs",
        nargs="+",
        help="One or more IOCs to analyse (IPs, URLs, hashes)"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Print results as JSON"
    )
    parser.add_argument(
        "--score",
        action="store_true",
        help="Display a unified IOC score"
    )
    return parser.parse_args()


def analyse_ioc(ioc, config):
    ioc_type = detect_ioc_type(ioc)
    sources = []

    vt_result = check_virustotal(ioc, ioc_type, config["virustotal"]["api_key"])
    if vt_result:
        sources.append(vt_result)

    otx_result = check_otx(ioc, ioc_type, config["otx"]["api_key"])
    if otx_result:
        sources.append(otx_result)

    abusech_result = check_abusech(ioc, ioc_type)
    if abusech_result:
        sources.append(abusech_result)

    result = {
        "ioc": ioc,
        "ioc_type": ioc_type,
        "sources": sources,
        "source_hits": summarize_source_hits(sources),
        "score": calculate_score(sources),
    }

    return result


def print_human_summary(results, show_score=False):
    print("\n========== SUMMARY ==========\n")

    for result in results:
        print(f"IOC: {result['ioc']}")
        print(f"  Type: {result['ioc_type']}")

        if show_score:
            score = result["score"]
            print(f"  Score: {score['value']}/100 ({score['severity']})")

        if not result["sources"]:
            print("  -> No relevant data found\n")
            continue

        print(f"  Found in: {', '.join(result['source_hits'])}")

        for source in result["sources"]:
            print(f"  Source: {source['source']}")
            print(f"    Malicious: {source['malicious']}")

            if source.get("confidence") is not None:
                print(f"    Confidence: {source['confidence']}")

            if source.get("campaigns"):
                print(f"    Campaigns: {', '.join(source['campaigns'])}")

            if source.get("names"):
                print(f"    Related names: {', '.join(source['names'])}")

            tags = [tag for tag in source.get("tags", []) if tag]
            if tags:
                print(f"    Tags: {', '.join(tags)}")

            references = [ref for ref in source.get("references", []) if ref]
            if references:
                print(f"    References: {', '.join(references)}")

        print()


def main():
    args = parse_arguments()

    if not args.iocs:
        print("[!] Please provide at least one IOC.")
        sys.exit(1)

    config = load_config()
    results = [analyse_ioc(ioc, config) for ioc in args.iocs]

    if args.json_output:
        print(json.dumps(results, indent=2))
        return

    print_human_summary(results, show_score=args.score)


if __name__ == "__main__":
    main()
