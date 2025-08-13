import os
import shutil
import re
from collections import defaultdict

# === CONFIG ===
SOURCE_DIR = "enron_mail_20150507/maildir"
DEST_DIR = "sample_emails/legitimate"
MAX_EMAILS = 700
ALLOWED_FOLDERS = {"inbox", "sent", "_sent_mail", "sent_items"}

# Track reasons for rejection
rejection_reasons = defaultdict(int)

def is_valid_email_file(file_path):
    """Validate if a file is a proper email."""
    try:
        size = os.path.getsize(file_path)
        if size == 0:
            return False, "Empty file (0 bytes)"

        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

    except Exception as e:
        reason = f"Unreadable file: {type(e).__name__}"
        print(f"[✘] Error reading file: {file_path} — {e}")
        return False, reason

    if not content.strip():
        return False, "Empty after read()"

    # Normalize line endings
    content = content.replace('\r\n', '\n').replace('\r', '\n')

    # Split headers/body
    parts = content.split('\n\n', 1)
    if len(parts) != 2:
        return False, "No header-body separator"

    headers_raw, body = parts
    headers = headers_raw.lower()
    body = body.strip()

    # Header checks
    if not (re.search(r'^from:\s?.+', headers, re.MULTILINE) or re.search(r'^x-from:\s?.+', headers, re.MULTILINE)):
        return False, "Missing From/X-From header"
    if not (re.search(r'^to:\s?.+', headers, re.MULTILINE) or re.search(r'^x-to:\s?.+', headers, re.MULTILINE)):
        return False, "Missing To/X-To header"
    if not re.search(r'^subject:\s?.+', headers, re.MULTILINE):
        return False, "Missing Subject header"

    # Body checks
    if len(body) < 20:
        return False, f"Body too short ({len(body)} chars)"
    if any(x in headers for x in ["calendar", "outlook", "appointment"]):
        return False, "Likely calendar/system message"
    if any(x in body.lower() for x in ["unsubscribe", "click here"]):
        return False, "Likely spam/marketing"
    if not re.search(r'[.!?]\s', body):
        return False, "No sentence structure in body"

    return True, "Valid email"

def collect_enron_emails():
    if not os.path.exists(DEST_DIR):
        os.makedirs(DEST_DIR)

    count = 0
    print(f"\n🔍 Scanning Enron users in: {SOURCE_DIR}\n")

    for user in os.listdir(SOURCE_DIR):
        user_path = os.path.join(SOURCE_DIR, user)
        if not os.path.isdir(user_path):
            continue

        print(f"\n📂 User: {user}")
        valid_count = 0

        for root, dirs, files in os.walk(user_path):
            folder_name = os.path.basename(root).lower()

            # Skip folders not in our allowed set
            if folder_name not in ALLOWED_FOLDERS:
                continue

            print(f"  ├── Folder: {root} | Files: {len(files)}")

            for email_file in files:
                src_path = os.path.join(root, email_file)

                if count >= MAX_EMAILS:
                    print(f"\n✅ Done: {count} emails copied to {DEST_DIR}")
                    print_summary()
                    return

                is_valid, reason = is_valid_email_file(src_path)
                if is_valid:
                    safe_name = f"{user}_{count}.eml"
                    dest_path = os.path.join(DEST_DIR, safe_name)
                    try:
                        shutil.copyfile(src_path, dest_path)
                        count += 1
                        valid_count += 1
                        print(f"[{count:03}] ✅ Copied: {safe_name}")
                    except Exception as e:
                        print(f"[!] Copy error: {src_path} → {e}")
                        rejection_reasons["Copy error"] += 1
                else:
                    rejection_reasons[reason] += 1
                    print(f"[✘] Rejected ({reason}): {src_path}")

        print(f"  ↳ ✅ {valid_count} valid emails copied from user: {user}")

    print(f"\n⚠️ Loop completed. Total collected: {count}/{MAX_EMAILS} requested")
    print_summary()

def print_summary():
    print("\n📊 Rejection Summary:")
    if not rejection_reasons:
        print("  - No rejections logged.")
    else:
        for reason, count in sorted(rejection_reasons.items(), key=lambda x: -x[1]):
            print(f"  - {reason}: {count}")

if __name__ == "__main__":
    collect_enron_emails()
