import joblib
import pandas as pd
from modules.extract_features_from_eml import extract_features_from_eml

MODEL_PATH = "model/phishdetect_eml_model.pkl"
FEATURES_CSV = "model/email_dataset.csv"

# Mapping of features to human-readable descriptions
REASON_MAP = {
    "reply_to_differs": "Reply-To domain is different from From domain",
    "return_path_differs": "Return-Path domain is different from From domain",
    "x_mailer_missing": "Missing X-Mailer header",
    "received_count": "Unusual number of Received headers",
    "spoofed_display_name": "Display name contains brand but domain doesn't match official",
    "url_count": "Email contains multiple URLs",
    "has_ip_url": "URL uses a raw IP address",
    "has_shortener": "URL uses a known link shortener",
    "url_length_avg": "Average URL length is unusually long",
    "has_https": "Contains HTTPS links",
    "https_token": "URL contains misleading 'https' token",
    "has_at_in_url": "URL contains '@' symbol",
    "suspicious_keywords": "Email contains phishing-related keywords",
    "mouse_over": "Mouse-over JavaScript event detected",
    "popup_window": "Popup window JavaScript detected",
    "right_click_disabled": "Right-click is disabled in email",
    "iframe": "Email contains iframe",
    "submit_to_email": "Form submission sends data to email address"
}

def explain_email(file_path, top_n=5):
    # Load model
    model = joblib.load(MODEL_PATH)

    # Get training feature order
    df = pd.read_csv(FEATURES_CSV)
    feature_cols = [col for col in df.columns if col not in ["label", "from_domain"]]

    # Extract features from email
    features = extract_features_from_eml(file_path)

    # Ensure missing features are set to 0
    for col in feature_cols:
        features.setdefault(col, 0)

    # Convert to DataFrame
    X_email = pd.DataFrame([features])[feature_cols]

    # Predict
    pred = model.predict(X_email)[0]
    pred_proba = float(model.predict_proba(X_email)[0][pred])

    # Get feature importances
    importances = model.feature_importances_
    feature_importance_map = dict(zip(feature_cols, importances))

    # Calculate contributions, filter zero-value features
    contrib_scores = {
        f: features[f] * feature_importance_map[f]
        for f in feature_cols if features[f] != 0
    }

    # Sort by absolute contribution
    top_reasons = sorted(contrib_scores.items(), key=lambda x: abs(x[1]), reverse=True)[:top_n]

    # Build structured JSON-friendly output
    result = {
        "file": file_path,
        "prediction": "PHISHING" if pred == 1 else "LEGITIMATE",
        "confidence": pred_proba,
        "top_reasons": [
            {
                "feature": feat,
                "description": REASON_MAP.get(feat, feat),
                "value": features[feat],
                "weight": float(feature_importance_map[feat])
            }
            for feat, _ in top_reasons
        ]
    }

    # === Print (debug/CLI use) ===
    print(f"\n📄 File: {result['file']}")
    print(f"🔍 Prediction: {result['prediction']}")
    print(f"Confidence: {result['confidence']:.2f}\n")
    print("Top reasons for decision:")
    for reason in result["top_reasons"]:
        print(f"  - {reason['description']} (value={reason['value']}, weight={reason['weight']:.4f})")

    return result

if __name__ == "__main__":
    test_email = "sample_emails/phishing/phishing-2021.mbox_email_1.eml"
    output = explain_email(test_email)
    # Debug: show JSON
    print("\n[JSON Output] =>", output)
