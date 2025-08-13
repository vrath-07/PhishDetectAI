from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import pandas as pd
import traceback
import os
from modules.extract_features_from_eml import extract_features_from_eml

MODEL_PATH = "model/phishdetect_eml_model.pkl"
FEATURES_CSV = "model/email_dataset.csv"

app = Flask(__name__)
CORS(app)  # allow calls from Chrome extension

# --- Health routes ---
@app.route("/", methods=["GET"])
def root():
    return jsonify({"message": "PhishDetectAI API is running"})

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})

# --- Load once on startup ---
model = joblib.load(MODEL_PATH)
df = pd.read_csv(FEATURES_CSV)
FEATURE_COLS = [c for c in df.columns if c not in ["label", "from_domain"]]
IMP_MAP = dict(zip(FEATURE_COLS, getattr(model, "feature_importances_", [0] * len(FEATURE_COLS))))

def top_reasons(feature_row):
    """Return top contributing features for a prediction."""
    scores = {f: float(feature_row.get(f, 0)) * float(IMP_MAP.get(f, 0)) for f in FEATURE_COLS}
    top = sorted(scores.items(), key=lambda x: abs(x[1]), reverse=True)[:5]
    return [
        {"feature": k, "value": feature_row.get(k, 0), "weight": IMP_MAP.get(k, 0)}
        for k, _ in top
    ]

@app.route("/predict_email", methods=["POST"])
def predict_email():
    try:
        # Check file input
        if "file" not in request.files:
            return jsonify({"error": "No file provided. Send multipart/form-data with key 'file'."}), 400

        file = request.files["file"]

        # Save temporarily to handle binary parsing
        temp_path = "temp_upload.eml"
        file.save(temp_path)

        # Extract features
        features = extract_features_from_eml(temp_path)
        if not features or not isinstance(features, dict):
            return jsonify({"error": "Failed to extract features from email"}), 400

        # Ensure all training features exist
        feature_row = {col: features.get(col, 0) for col in FEATURE_COLS}
        X = pd.DataFrame([feature_row])[FEATURE_COLS]

        # Predict
        pred = int(model.predict(X)[0])
        proba = float(model.predict_proba(X)[0][pred])

        # Remove temp file
        if os.path.exists(temp_path):
            os.remove(temp_path)

        return jsonify({
            "prediction": "PHISHING" if pred == 1 else "LEGITIMATE",
            "label": pred,
            "confidence": round(proba, 4),
            "reasons": top_reasons(feature_row),
        })

    except Exception as e:
        return jsonify({
            "error": str(e),
            "trace": traceback.format_exc()
        }), 500

if __name__ == "__main__":
    app.run(debug=True)
