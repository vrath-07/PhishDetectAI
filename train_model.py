import os
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns

# === CONFIG ===
DATASET_PATH = "model/email_dataset.csv"
MODEL_PATH = "model/phishdetect_eml_model.pkl"
REPORTS_DIR = "reports"

# Ensure reports folder exists
os.makedirs(REPORTS_DIR, exist_ok=True)

# === LOAD DATASET ===
print(f"[+] Loading dataset from {DATASET_PATH}")
df = pd.read_csv(DATASET_PATH)

# Keep only numeric columns + label
numeric_cols = df.select_dtypes(include=["number"]).columns.tolist()
if "label" not in numeric_cols:
    raise ValueError("Dataset must contain 'label' column.")

X = df[numeric_cols].drop(columns=["label"])
y = df["label"]

# === SPLIT DATA ===
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print(f"[i] Training samples: {len(X_train)}, Testing samples: {len(X_test)}")

# === TRAIN MODEL ===
model = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    n_jobs=-1
)
model.fit(X_train, y_train)

# === PREDICT & EVALUATE ===
y_pred = model.predict(X_test)

print("\n=== Classification Report ===")
print(classification_report(y_test, y_pred, digits=4))
print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")

# Confusion matrix
cm = confusion_matrix(y_test, y_pred)
plt.figure(figsize=(5, 4))
sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", xticklabels=["Legit", "Phish"], yticklabels=["Legit", "Phish"])
plt.title("Confusion Matrix")
plt.xlabel("Predicted")
plt.ylabel("Actual")
plt.tight_layout()
plt.savefig(os.path.join(REPORTS_DIR, "confusion_matrix.png"))
print(f"[+] Confusion matrix saved to {REPORTS_DIR}/confusion_matrix.png")

# === FEATURE IMPORTANCE ===
importances = model.feature_importances_
feature_data = sorted(zip(importances, X.columns), reverse=True)
sorted_importances, sorted_features = zip(*feature_data)

plt.figure(figsize=(10, 6))
sns.barplot(x=sorted_importances, y=sorted_features, palette="viridis")
plt.title("Top Feature Importances")
plt.xlabel("Importance")
plt.ylabel("Feature")
plt.tight_layout()
plt.savefig(os.path.join(REPORTS_DIR, "feature_importance.png"))
print(f"[+] Feature importance plot saved to {REPORTS_DIR}/feature_importance.png")

# === SAVE MODEL ===
joblib.dump(model, MODEL_PATH)
print(f"[+] Model saved to {MODEL_PATH}")
