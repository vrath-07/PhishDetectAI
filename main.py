from modules.header_analyzer import parse_email_headers, detect_header_anomalies
from modules.url_analyzer import extract_urls_from_email, analyze_urls
from modules.virustotal_api import check_url_virustotal
from modules.openphish_checker import fetch_openphish_feed, is_url_in_openphish
from modules.report_generator import save_report_as_json, save_report_as_html

from datetime import datetime
import os

if __name__ == "__main__":
    email_file = "sample_emails/sample1.eml"

    print("=== Starting PhishDetectAI Analysis ===")
    print(f"[*] Target Email: {email_file}")

    # === Step 1: Header Analysis ===
    headers = parse_email_headers(email_file)
    print("\n=== Extracted Headers ===")
    for key, value in headers.items():
        print(f"{key}: {value}")

    issues = detect_header_anomalies(headers)
    print("\n=== Detected Anomalies ===")
    if not issues:
        print("No anomalies detected.")
    else:
        for issue in issues:
            print("- " + issue)

    # === Step 2: URL Extraction ===
    print("\n=== Extracted URLs ===")
    urls = extract_urls_from_email(email_file)
    if not urls:
        print("No URLs found.")
    else:
        for u in urls:
            print(u)

    # === Step 3: OpenPhish Feed ===
    print("\n[+] Fetching OpenPhish threat feed...")
    openphish_set = fetch_openphish_feed()

    # === Step 4: URL Risk Analysis ===
    print("\n=== URL Risk Analysis ===")
    url_report = []
    for entry in analyze_urls(urls):
        url = entry['url']
        risk_level = entry['risk_level']
        risk_score = entry['risk_score']
        print(f"{url} | Risk: {risk_level} (Score: {risk_score})")

        vt_result = check_url_virustotal(url)
        if vt_result["status"] == "success":
            vt_summary = (
                f"{vt_result['malicious']} malicious, "
                f"{vt_result['suspicious']} suspicious, "
                f"{vt_result['harmless']} harmless"
            )
            print(f" → VirusTotal: {vt_summary}")
        else:
            vt_summary = "Scan failed"
            print(" → VirusTotal scan failed.")

        in_openphish = is_url_in_openphish(url, openphish_set)
        print(f" → OpenPhish: {'URL found in phishing database!' if in_openphish else 'URL not found.'}")

        url_report.append({
            "url": url,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "virustotal": vt_summary,
            "openphish_flag": in_openphish
        })

    # === Step 5: Generate Reports ===
    report_data = {
        "timestamp": datetime.now().isoformat(),
        "header_anomalies": issues,
        "url_analysis": url_report
    }

    os.makedirs("reports", exist_ok=True)
    save_report_as_json(report_data, "reports/report.json")
    save_report_as_html(report_data, "reports/report.html")

    print("\n[✓] Reports successfully generated in 'reports/' folder.")
