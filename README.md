# footprint

OSINT footprint aggregator for pentesters, red teamers, and OSINT investigators.

One command → unified digital footprint from 5 free sources.

## Why

Recon means opening 10 browser tabs, running 6 tools, and stitching output by hand. **footprint** does it in one command and gives you clean JSON or a terminal report.

## Features

- **Subdomains** via crt.sh certificate transparency
- **DNS** records (A, AAAA, MX, NS, TXT, CNAME)
- **WHOIS** registrar, dates, name servers
- **Shodan InternetDB** open ports, tags, CVEs (no API key)
- **Wayback Machine** historical URLs
- **Risk score** heuristic (0–10)
- JSON output for pipelines and reporting

## Install

```bash
git clone https://github.com/PacianChigo/footprint.git
cd footprint
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
