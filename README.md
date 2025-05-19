# 🕵️‍♂️ ThreatHunterX

**ThreatHunterX** is a Python-powered IOC enrichment and risk analysis tool built for SOC analysts, threat hunters, and cyber pros who want clean, local, real-time threat intelligence.  
It uses **VirusTotal** to score IPs, domains, and file hashes — and caches results locally using **SQLite** for lightning-fast performance and API conservation.

---

## 🚀 Features

- 🧠 **Classifies IPs, domains, and hashes**
- 🔍 **Real-time enrichment** using the VirusTotal API
- 💾 **SQLite caching** to avoid duplicate API calls
- ⏳ **IOC expiration policy** with automatic re-checks (7-day TTL)
- 🖥️ **Rich-powered CLI dashboard** (color-coded, tabular)
- 🧯 **Force refresh flag** (`--force-refresh`) to override cache
- 🧪 **IOC age tracking** with warning for expired intel

---

## 🧰 Tech Stack

- Python 3.10+
- `rich` (CLI formatting)
- `requests` (API calls)
- `PyYAML` (config)
- `sqlite3` (local caching)

---

## 🛠️ Installation

```bash
git clone https://github.com/yourusername/ThreatHunterX.git
cd ThreatHunterX
pip install -r requirements.txt
```


## 📊 Sample Output

╭────────────────────────────── ThreatHunterX Results ──────────────────────────────────────────╮
│ IOC           │ Type   │ Score │ Severity │ Details                        │ Age              │
│---------------│--------│-------│----------│--------------------------------│------------------│
│ 8.8.8.8       │ IP     │ 0     │ Clean    │ Detected by 0 of 94 • CACHED   │ 5 days           │
│ malicious.com │ Domain │ 2     │ Low      │ Detected by 2 of 94 • LIVE     │ New              │
│ 44d88...      │ Hash   │ 64    │ High     │ Detected by 64 of 75 • CACHED  │ 9 days – EXPIRED │
╰───────────────────────────────────────────────────────────────────────────────────────────────╯


## 🗃️ Local Cache

All enriched IOCs are stored in:
- threathunterx.db

Stored fields:
- IOC value
- Type (IP/Domain/Hash)
- Risk score
- Enrichment summary
- Timestamp (UTC)


## 📍 Roadmap
- IOC classification + enrichment
- SQLite caching with expiration logic
- Rich CLI formatting + age warnings
- Markdown & CSV report exports
- Flask API version
- Web-based front-end (React or static HTML)
- AWS Amplify deployment


## 🧑‍💻 Dev Tips
- Delete or edit threathunterx.db to reset the cache
- Use --force-refresh to recheck even recent entries
- Hashes can be MD5, SHA1, or SHA256

