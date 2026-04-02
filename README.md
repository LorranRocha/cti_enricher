# CTI Enricher

A Python-based IOC enrichment tool for CTI and SOC workflows.

## Description

CTI Enricher collects Indicators of Compromise (IOCs) passed as command-line arguments and queries multiple intelligence sources to return only the most relevant information, such as maliciousness, source correlation, campaign association, tags, and contextual details.

The tool is designed to support:

- Detection enrichment
- Threat hunting support
- IOC triage
- Analyst validation workflows

## Features

- Accepts multiple IOCs in a single execution
- Supports IPs, URLs, and file hashes
- Automatically detects IOC type
- Queries multiple external intelligence providers:
  - Abuse.ch
  - AlienVault OTX
  - VirusTotal
- Reads API keys from `config.yml`
- Consolidates relevant findings per IOC
- Calculates a unified IOC score
- Supports JSON output
- Keeps output concise and operationally useful

## Project Structure

```bash
cti_enricher/
├── main.py
├── utils.py
├── config.yml.example
├── requirements.txt
├── README.md
└── services/
    ├── __init__.py
    ├── abusech.py
    ├── otx.py
    └── virustotal.py
```

## Installation

```bash
git clone https://github.com/LorranRocha/cti_enricher.git
cd cti_enricher
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Configuration

Add your API keys on config.yml:

Example:

```yaml
virustotal:
  api_key: "YOUR_API_KEY"

otx:
  api_key: "YOUR_API_KEY"

abusech:
  api_key: ""
```

## Usage

Run the tool by passing one or more IOCs as arguments:

```bash
python main.py <ioc1> <ioc2> <ioc3>
```

### Examples

```bash
python main.py 8.8.8.8
python main.py https://example.com d41d8cd98f00b204e9800998ecf8427e
python main.py 8.8.8.8 d41d8cd98f00b204e9800998ecf8427e
```

### JSON Output

```bash
python main.py 8.8.8.8 --json
```

### IOC Scoring

```bash
python main.py 8.8.8.8 --score
```

## Example Output

```text
========== SUMMARY ==========

IOC: d41d8cd98f00b204e9800998ecf8427e
  Type: md5
  Score: 80/100 (High)
  Found in: VirusTotal, OTX, Abuse.ch
  Source: VirusTotal
    Malicious: True
    Confidence: 12
    Tags: malware, trojan
  Source: OTX
    Malicious: True
    Confidence: 5
    Campaigns: Emotet Activity
  Source: Abuse.ch
    Malicious: True
    Campaigns: Emotet
    Tags: exe, Emotet
```

## Notes

- Abuse.ch support is focused on file hashes.
- OTX and VirusTotal rate limits depend on the API plan in use.
- Some source coverage varies depending on IOC type.
- This project is intended as a lightweight enrichment utility and can be expanded for production-grade CTI pipelines.

## Future Improvements

- JSON export to file
- Response normalisation to a STIX-like schema
- Async requests for better performance
- Caching to reduce duplicate lookups
- Integration with OpenCTI or SIEM platforms

## License

MIT
