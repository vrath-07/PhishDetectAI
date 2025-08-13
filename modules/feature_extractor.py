# modules/feature_extractor.py
import re
from modules.header_analyzer import detect_header_anomalies, parse_email_headers
from modules.url_analyzer import extract_urls_from_email
from modules.openphish_checker import is_url_in_openphish
from modules.virustotal_api import check_url_virustotal

def extract_features(email_file, openphish_set):
    features = {
        "from_domain_mismatch": 0,
        "reply_to_differs": 0,
        "has_received_path": 0,
        "x_mailer_missing": 0,
        "subject_keywords": 0,
        "num_urls": 0,
        "url_contains_ip": 0,
        "url_shortened": 0,
        "openphish_hit": 0,
        "virustotal_score": 0,
    }

    headers = parse_email_headers(email_file)
    anomalies = detect_header_anomalies(headers)

    if "Return-Path mismatch with From" in anomalies:
        features["from_domain_mismatch"] = 1
    if "Reply-To differs from From (may be phishing)" in anomalies:
        features["reply_to_differs"] = 1
    if headers.get("Received"):
        features["has_received_path"] = 1
    if not headers.get("X-Mailer"):
        features["x_mailer_missing"] = 1
    if re.search(r"(urgent|verify|locked|password)", headers.get("Subject", "").lower()):
        features["subject_keywords"] = 1

    urls = extract_urls_from_email(email_file)
    features["num_urls"] = len(urls)

    for url in urls:
        if re.match(r"http[s]?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url):
            features["url_contains_ip"] = 1
        if re.search(r"bit\.ly|tinyurl\.com|t\.co", url):
            features["url_shortened"] = 1
        if is_url_in_openphish(url, openphish_set):
            features["openphish_hit"] = 1
        vt = check_url_virustotal(url)
        if vt["status"] == "success":
            features["virustotal_score"] += vt["malicious"] + vt["suspicious"]

    return features
