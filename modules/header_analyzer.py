# modules/header_analyzer.py

from email import policy
from email.parser import BytesParser

def parse_email_headers(file_path):
    with open(file_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)

    headers = {
        "From": msg.get("From"),
        "To": msg.get("To"),
        "Subject": msg.get("Subject"),
        "Return-Path": msg.get("Return-Path"),
        "Reply-To": msg.get("Reply-To"),
        "Received": msg.get_all("Received"),
        "X-Mailer": msg.get("X-Mailer")
    }

    return headers

def detect_header_anomalies(headers):
    issues = []

    from_addr = headers.get("From", "")
    return_path = headers.get("Return-Path", "")
    reply_to = headers.get("Reply-To", "")

    if return_path and from_addr and return_path not in from_addr:
        issues.append("Return-Path mismatch with From")

    if reply_to and reply_to != from_addr:
        issues.append("Reply-To differs from From (may be phishing)")

    if not headers.get("Received"):
        issues.append("Missing Received headers (may be suspicious relay)")

    return issues
