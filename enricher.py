# enricher.py

import requests
import yaml

with open("config.yaml", "r") as file:
    CONFIG = yaml.safe_load(file)

VT_API_KEY = CONFIG.get("virustotal_api_key")

def vt_lookup_hash(ioc):
    url = f"https://www.virustotal.com/api/v3/files/{ioc}"
    headers = {
        "x-apikey": VT_API_KEY
    }
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        return {
            "vt_positives": stats.get("malicious", 0),
            "total_engines": sum(stats.values())
        }
    else:
        return {"error": f"VT response: {response.status_code}"}

def vt_lookup_domain(ioc):
    url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
    headers = {
        "x-apikey": VT_API_KEY
    }
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        return {
            "vt_positives": stats.get("malicious", 0),
            "total_engines": sum(stats.values())
        }
    else:
        return {"error": f"VT response: {response.status_code}"}

def vt_lookup_ip(ioc):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
    headers = {
        "x-apikey": VT_API_KEY
    }
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        return {
            "vt_positives": stats.get("malicious", 0),
            "total_engines": sum(stats.values())
        }
    else:
        return {"error": f"VT response: {response.status_code}"}
