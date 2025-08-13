import os
import re
import csv
import tldextract
from bs4 import BeautifulSoup
from email import policy
from email.parser import BytesParser

# Suspicious patterns
SUSPICIOUS_KEYWORDS = ['verify', 'update', 'login', 'urgent', 'click', 'account', 'password']
SHORTENERS = ['bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co', 'buff.ly']

def extract_features_from_eml(file_path):
    try:
        with open(file_path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)
    except Exception as e:
        print(f"[!] Failed to parse {file_path}: {e}")
        return None

    # === HEADER FEATURES ===
    from_header = msg.get('From', '')
    reply_to = msg.get('Reply-To', '')
    return_path = msg.get('Return-Path', '')
    x_mailer = msg.get('X-Mailer', None)
    received_headers = msg.get_all('Received', [])

    from_domain = tldextract.extract(from_header).registered_domain or ""
    reply_to_domain = tldextract.extract(reply_to).registered_domain or ""
    return_path_domain = tldextract.extract(return_path).registered_domain or ""

    features = {
        "from_domain": from_domain,
        "reply_to_differs": int(reply_to_domain != from_domain and reply_to_domain != ""),
        "return_path_differs": int(return_path_domain != from_domain and return_path_domain != ""),
        "x_mailer_missing": int(x_mailer is None),
        "received_count": len(received_headers),
        "spoofed_display_name": int(
            any(brand in from_header.lower() for brand in ['apple', 'yesbank', 'paypal', 'netflix']) and
            from_domain not in ['apple.com', 'yesbank.in', 'paypal.com', 'netflix.com']
        ),
    }

    # === BODY/CONTENT FEATURES ===
    payload = msg.get_body(preferencelist=('html', 'plain'))
    content = payload.get_content() if payload else ""
    soup = BeautifulSoup(content, 'html.parser')
    html_text = str(soup)

    urls = re.findall(r'https?://[^\s"\'>]+', content)
    url_domains = [tldextract.extract(u).registered_domain for u in urls]

    features.update({
        "url_count": len(urls),
        "has_ip_url": int(any(re.match(r'https?://\d{1,3}(\.\d{1,3}){3}', u) for u in urls)),
        "has_shortener": int(any(short in u for u in urls for short in SHORTENERS)),
        "url_length_avg": sum(len(u) for u in urls) / len(urls) if urls else 0,
        "has_https": int(any(u.startswith("https://") for u in urls)),
        "https_token": int(any("https" in u.split('//')[-1] for u in urls)),
        "has_at_in_url": int(any('@' in u for u in urls)),
        "suspicious_keywords": sum(1 for word in SUSPICIOUS_KEYWORDS if word in content.lower()),
        "mouse_over": int('onmouseover' in html_text.lower()),
        "popup_window": int('window.open' in html_text.lower()),
        "right_click_disabled": int('contextmenu' in html_text.lower()),
        "iframe": int('<iframe' in html_text.lower()),
        "submit_to_email": int(bool(re.search(r'<form[^>]+action=["\']mailto:', html_text, re.I))),
    })

    return features

def process_folder(folder_path, label, output_csv):
    all_rows = []
    processed_count = 0
    failed_count = 0

    for root, _, files in os.walk(folder_path):
        for file in files:
            if file.lower().endswith(".eml"):
                file_path = os.path.join(root, file)
                features = extract_features_from_eml(file_path)
                if features:
                    features["label"] = label
                    all_rows.append(features)
                    processed_count += 1
                else:
                    failed_count += 1

    if not all_rows:
        print(f"[!] No valid emails processed from {folder_path}")
        return

    # Write or append to CSV
    file_exists = os.path.isfile(output_csv)
    with open(output_csv, "a" if file_exists else "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=all_rows[0].keys())
        if not file_exists:
            writer.writeheader()
        writer.writerows(all_rows)

    print(f"[✓] Processed {processed_count} emails from {folder_path} (Failed: {failed_count})")
    print(f"[💾] Saved to {output_csv}")

if __name__ == "__main__":
    # Example usage:
    process_folder("sample_emails/legitimate", 0, "model/phishing_dataset.csv")
    process_folder("sample_emails/phishing", 1, "model/phishing_dataset.csv")
