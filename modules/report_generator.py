import json
from datetime import datetime
import os

def save_report_as_json(report_data, output_path):
    with open(output_path, 'w') as f:
        json.dump(report_data, f, indent=4)

def save_report_as_html(report_data, output_path):
    html = f"""<html>
<head><title>Phishing Analysis Report</title></head>
<body>
    <h2>PhishDetectAI Report</h2>
    <p><strong>Scan Time:</strong> {report_data['timestamp']}</p>
    <h3>Header Anomalies</h3>
    <ul>
        {"".join([f"<li>{issue}</li>" for issue in report_data['header_anomalies']]) or "<li>No issues found.</li>"}
    </ul>
    <h3>URLs and Risk Analysis</h3>
    <ul>
"""

    for url_entry in report_data['url_analysis']:
        html += f"""
        <li><strong>{url_entry['url']}</strong><br/>
        Risk Level: {url_entry['risk_level']} (Score: {url_entry['risk_score']})<br/>
        VirusTotal: {url_entry['virustotal']}<br/>
        OpenPhish: {"Found" if url_entry['openphish_flag'] else "Not Found"}</li><br/>
        """

    html += "</ul></body></html>"

    with open(output_path, 'w') as f:
        f.write(html)
