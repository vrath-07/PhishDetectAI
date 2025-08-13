import mailbox
import os
from email import policy

def extract_emails_from_mbox(mbox_file, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    mbox = mailbox.mbox(mbox_file)
    for i, msg in enumerate(mbox):
        try:
            eml_bytes = msg.as_bytes(policy=policy.default)
            with open(os.path.join(output_dir, f"{os.path.basename(mbox_file)}_email_{i}.eml"), "wb") as f:
                f.write(eml_bytes)
        except Exception as e:
            print(f"Error extracting email {i}: {e}")

# ✅ List all your `.mbox` files here
mbox_files = [
    "phishing-2021.mbox",
    "phishing-2022.mbox",
    "phishing-2023.mbox",
    "phishing-2024.mbox"
]

for file in mbox_files:
    extract_emails_from_mbox(file, "sample_emails/phishing/")
