import re
import joblib
from urllib.parse import urlparse


# ---------- URL FEATURE EXTRACTION ----------
def extract_url_features(url: str):
    """
    Extract numerical features from URL for ML prediction
    """
    features = {}

    features["url_length"] = len(url)
    features["num_dots"] = url.count(".")
    features["num_hyphens"] = url.count("-")
    features["num_at"] = url.count("@")
    features["num_question"] = url.count("?")
    features["num_slash"] = url.count("/")
    features["num_digits"] = sum(c.isdigit() for c in url)

    # Check if IP address is used
    features["has_ip"] = 1 if re.search(r"\d+\.\d+\.\d+\.\d+", url) else 0

    # HTTPS usage
    features["https"] = 1 if url.startswith("https") else 0

    # Domain length
    parsed = urlparse(url)
    features["domain_length"] = len(parsed.netloc)

    return list(features.values())


# ---------- LOAD MODEL ----------
def load_url_model():
    model = joblib.load("models/url_ml_model.pkl")
    return model


# ---------- PREDICTION ----------
def predict_url(url: str):
    model = load_url_model()
    features = extract_url_features(url)

    prediction = model.predict([features])[0]
    probability = model.predict_proba([features])[0][1]

    return {
        "prediction": "phishing" if prediction == 1 else "legit",
        "confidence": round(probability, 3)
    }
