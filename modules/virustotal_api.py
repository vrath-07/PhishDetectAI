# modules/virustotal_api.py

import requests
import time

API_KEY = "19e2b4b3a45ff1a68f4b941cc6fc77ca9a354dd814244400485e95671e3d7ec5"

def check_url_virustotal(url):
    headers = {
        "x-apikey": API_KEY
    }

    scan_url = "https://www.virustotal.com/api/v3/urls"
    response = requests.post(scan_url, headers=headers, data={"url": url})
    if response.status_code != 200:
        return {"status": "error", "message": "Submission failed"}
    
    analysis_id = response.json()["data"]["id"]

    # Wait a bit before fetching result
    time.sleep(15)

    result_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    result_response = requests.get(result_url, headers=headers)
    if result_response.status_code != 200:
        return {"status": "error", "message": "Result fetch failed"}

    stats = result_response.json()["data"]["attributes"]["stats"]
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)

    return {
        "status": "success",
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless
    }
