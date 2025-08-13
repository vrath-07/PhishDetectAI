# streamlit_app.py
import streamlit as st
import pandas as pd
import joblib
import os

# Set up absolute model path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "model", "phish_rf_model.pkl")

# Load trained model
model = joblib.load(MODEL_PATH)

# Define expected features (adjust this list based on your model training)
EXPECTED_FEATURES = [
    'has_ip', 'has_at', 'url_length', 'domain_length', 'count_dots', 
    'count_hyphens', 'count_subdomains', 'https_token', 'prefix_suffix', 
    'dns_record', 'web_traffic', 'domain_age', 'iframe', 'mouse_over', 
    'right_click', 'popup_window', 'submit_to_email', 'sfh', 'abnormal_url'
]

# Streamlit UI
st.set_page_config(page_title="PhishDetectAI", layout="centered")
st.title("🔐 PhishDetectAI — Email/URL Phishing Detector")

uploaded_file = st.file_uploader("📎 Upload a CSV file with extracted features", type="csv")

if uploaded_file:
    df = pd.read_csv(uploaded_file)

    # Clean input by keeping only expected columns
    input_df = df.copy()
    missing_features = [col for col in EXPECTED_FEATURES if col not in input_df.columns]
    
    if missing_features:
        st.error(f"Missing expected features: {missing_features}")
        st.info("Ensure your CSV contains the correct columns.")
        st.stop()

    input_df = input_df[EXPECTED_FEATURES]  # Keep only required features
    
    try:
        pred = model.predict(input_df)
        df['Prediction'] = pred
        st.success("✅ Prediction complete.")
        st.dataframe(df)
    except Exception as e:
        st.error("❌ Error during prediction.")
        st.exception(e)
