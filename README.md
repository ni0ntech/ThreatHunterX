# ThreatHunterX 🕵️‍♂️
A Python-based IOC enrichment tool for threat hunters and SOC analysts.

## Features
- Classifies and scores IPs, domains, and file hashes
- Uses VirusTotal API for real-time enrichment
- Modular and extensible structure
- Designed with InfoSec workflows in mind

## Getting Started
```bash
git clone https://github.com/yourusername/ThreatHunterX.git
cd ThreatHunterX
pip install -r requirements.txt
python threathunterx.py

## Future Roadmap
- Add Rich CLI output (colorized tables and scores)
- Implement risk tier scoring (Low / Medium / High)
- Export enrichment results to Markdown and CSV
- Add SQLite-based caching to avoid duplicate API calls
- Build web-based front-end (React or static HTML)
- Deploy full-stack version via AWS Amplify
