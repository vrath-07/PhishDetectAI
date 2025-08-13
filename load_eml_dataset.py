import os
import pandas as pd
from modules.extract_features_from_eml import extract_features_from_eml

def load_dataset_from_folder(folder_path, label):
    rows = []
    if not os.path.exists(folder_path):
        print(f"[!] Folder not found: {folder_path}")
        return pd.DataFrame()

    total_files = sum(1 for f in os.listdir(folder_path) if f.lower().endswith(".eml"))
    processed = 0
    failed = 0

    print(f"[+] Extracting from: {folder_path} (Label: {label}, {total_files} files)")

    for file in os.listdir(folder_path):
        if file.lower().endswith(".eml"):
            file_path = os.path.join(folder_path, file)
            try:
                features = extract_features_from_eml(file_path)
                if not features:
                    failed += 1
                    continue
                features["label"] = label
                rows.append(features)
                processed += 1
            except Exception as e:
                failed += 1
                print(f"[!] Skipped {file}: {e}")

    print(f"[✓] Processed: {processed}, Failed: {failed}")
    return pd.DataFrame(rows)

# === Paths ===
phishing_path = "sample_emails/phishing"
legit_path = "sample_emails/legitimate"
output_csv = "model/phishing_dataset.csv"

# === Run ===
phish_df = load_dataset_from_folder(phishing_path, label=1)
legit_df = load_dataset_from_folder(legit_path, label=0)

df = pd.concat([phish_df, legit_df], ignore_index=True)

# Shuffle dataset for training
df = df.sample(frac=1, random_state=42).reset_index(drop=True)

# Ensure output directory exists
os.makedirs(os.path.dirname(output_csv), exist_ok=True)
df.to_csv(output_csv, index=False)

print(f"\n✅ Final dataset saved to {output_csv}")
print(f"   Phishing samples:   {len(phish_df)}")
print(f"   Legitimate samples: {len(legit_df)}")
print(f"   Total: {len(df)} rows")
