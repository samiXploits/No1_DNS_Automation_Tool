# DNS Automation Tool

## Overview
The DNS Automation Tool is a multi-threaded DNS lookup and reverse lookup tool designed for security professionals and network engineers. It provides comprehensive DNS record analysis, subdomain enumeration, reverse IP lookups, WHOIS queries, and more.

## Features
- Multi-threaded DNS record lookup
- Reverse DNS lookup (PTR records)
- Reverse IP lookup
- Subdomain enumeration
- Brute-force subdomain discovery
- WHOIS information retrieval
- DNSSEC support check
- SPF record verification
- Zone transfer vulnerability check
- Generates HTML and JSON reports
- Proxy support for anonymity
- API integration for enhanced lookup capabilities

## Installation
### Prerequisites
Ensure you have Python installed along with the required dependencies. You can install them using:
```bash
pip install -r requirements.txt
```

### Required Python Packages
- `dnspython`
- `requests`
- `colorama`
- `tabulate`
- `python-whois`

## API Configuration
Some features require an API key for external services. To use these, add your API key in the script:
```python
API_KEY = "your_api_key_here"
```
Make sure to obtain API keys from the respective services before running the tool.

## Usage
### Basic Usage
Run the tool with a single target domain:
```bash
python dns_automation.py -t example.com
```

### Multiple Domains
Analyze multiple domains by separating them with commas:
```bash
python dns_automation.py -m example1.com,example2.com,example3.com
```

### Using Proxies
To use a proxy file:
```bash
python dns_automation.py -t example.com -p proxies.txt
```

## Output
Reports are generated in the `dns_reports/` directory:
- HTML Report: `example.com_dns_report.html`
- JSON Report: `example.com_dns_report.json`
- Login Protected Report: `dns_reports/login.html`

## License
This tool is created by Mr. Sami. Use it responsibly for security research and testing.

## Disclaimer
This tool is intended for educational and ethical security testing purposes only. Unauthorized use against systems you do not own is illegal.

