import requests

url = "http://127.0.0.1:5000/predict_email"
path = r"sample_emails\phishing\phishing-2021.mbox_email_1.eml"  # change to any .eml

with open(path, "rb") as f:
    r = requests.post(url, files={"file": f})
print(r.status_code, r.json())
