import logging
import re
from pathlib import Path

import joblib
from urllib.parse import urlparse


logger = logging.getLogger(__name__)
BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_PATH = BASE_DIR / "models" / "url_ml_model.pkl"
_model = None
FEATURE_NAMES = [
    "url_length",
    "num_dots",
    "num_hyphens",
    "num_at",
    "num_question",
    "num_slash",
    "num_digits",
    "has_ip",
    "https",
    "domain_length",
]

def extract_url_features(url: str):
    """
    Extract numerical features from URL for ML prediction
    """
    parsed = urlparse(url)
    features = {
        "url_length": len(url),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_at": url.count("@"),
        "num_question": url.count("?"),
        "num_slash": url.count("/"),
        "num_digits": sum(c.isdigit() for c in url),
        "has_ip": 1 if re.search(r"\d+\.\d+\.\d+\.\d+", url) else 0,
        "https": 1 if url.lower().startswith("https") else 0,
        "domain_length": len(parsed.netloc),
    }

    return [features[name] for name in FEATURE_NAMES]


def load_url_model():
    global _model
    if _model is None:
        logger.info("Loading URL ML model from %s", MODEL_PATH)
        bundle = joblib.load(MODEL_PATH)
        if isinstance(bundle, dict) and "model" in bundle:
            _model = bundle
        else:
            _model = {
                "model": bundle,
                "model_name": "Legacy URL Model",
                "feature_names": FEATURE_NAMES,
                "metrics": {},
            }
        logger.info("URL ML model loaded successfully")
    return _model


def predict_url(url: str):
    logger.info("URL ML prediction started for %s", url)
    bundle = load_url_model()
    model = bundle["model"]
    features = extract_url_features(url)
    logger.info("URL feature extraction complete: %s", features)

    raw_prediction = int(model.predict([features])[0])
    phishing_probability = float(model.predict_proba([features])[0][1])
    prediction = "Phishing" if raw_prediction == 1 else "Safe"
    confidence = phishing_probability if raw_prediction == 1 else 1 - phishing_probability
    reasons = [
        f"{bundle.get('model_name', 'URL model')} evaluated lexical and structural URL features",
        f"Phishing probability: {phishing_probability:.2f}",
    ]
    logger.info(
        "URL ML prediction complete: prediction=%s risk_score=%.3f confidence=%.3f",
        prediction,
        phishing_probability,
        confidence,
    )

    return {
        "prediction": prediction,
        "risk_score": round(phishing_probability, 3),
        "confidence": round(confidence * 100, 2),
        "features": features,
        "model": bundle.get("model_name", "URL model"),
        "metrics": bundle.get("metrics", {}),
        "reasons": reasons,
    }
