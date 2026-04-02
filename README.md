# CTI Enricher

A Python-based IOC enrichment tool for CTI and SOC workflows.

## Description

CTI Enricher collects Indicators of Compromise (IOCs) provided by the user and queries multiple intelligence sources to return only the most relevant information, such as maliciousness, source correlation, campaign association, tags, and basic context.

The tool is designed to support:

- Detection enrichment
- Threat hunting support
- IOC triage
- Analyst validation workflows

## Features

- Accepts multiple IOCs in a single execution
- Supports IPs, URLs, and file hashes
- Queries multiple external intelligence providers:
  - Abuse.ch
  - AlienVault OTX
  - VirusTotal
- Reads API keys from `config.yml`
- Consolidates relevant findings per IOC
- Keeps output concise and operationally useful

## Project Structure

```bash
cti_enricher/
├── main.py
├── config.yml.example
├── requirements.txt
├── services/
│   ├── __init__.py
│   ├── abusech.py
│   ├── otx.py
│   └── virustotal.py
└── utils.py
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

Copy the example config file and add your API keys:

```bash
cp config.yml.example config.yml
```

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

```bash
python main.py
```

Then provide as many IOCs as needed. Type `done` to finish input.

## Example Output

```text
IOC: 8.8.8.8
  Source: VirusTotal
    Malicious: False

IOC: d41d8cd98f00b204e9800998ecf8427e
  Source: Abuse.ch
    Malicious: True
    Campaign: Emotet
    Tags: exe, Emotet
```

## Notes

- Abuse.ch endpoint coverage may vary depending on IOC type.
- OTX and VirusTotal rate limits depend on the API plan in use.
- This project is intended as a lightweight enrichment utility and can be expanded for production-grade CTI pipelines.

## Future Improvements

- Automatic IOC type detection
- Unified scoring model
- JSON/CSV export
- Async requests for better performance
- Integration with OpenCTI or SIEM platforms

## License

MIT
