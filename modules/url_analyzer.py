# modules/url_analyzer.py

import re
import requests
from urllib.parse import urlparse

def extract_urls_from_email(file_path):
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    url_regex = r'https?://[^\s"]+'
    urls = re.findall(url_regex, content)
    return list(set(urls))  # remove duplicates

def get_domain_risk_score(domain):
    # Basic heuristic: suspicious if domain has numbers or odd TLDs
    suspicious_tlds = ['.xyz', '.ru', '.tk', '.ml', '.ga', '.cf']
    risk_score = 0

    if any(tld in domain for tld in suspicious_tlds):
        risk_score += 1
    if re.search(r'\d', domain):
        risk_score += 1
    if '-' in domain:
        risk_score += 1

    return risk_score

def analyze_urls(urls):
    results = []
    for url in urls:
        domain = urlparse(url).netloc
        risk = get_domain_risk_score(domain)
        results.append({
            "url": url,
            "domain": domain,
            "risk_score": risk,
            "risk_level": "High" if risk >= 2 else "Medium" if risk == 1 else "Low"
        })
    return results
