import logging
import joblib
from pathlib import Path

import numpy as np

logger = logging.getLogger(__name__)

# ---------------- PATHS ----------------
BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_PATH = BASE_DIR / "models" / "ocr_model.pkl"
VEC_PATH = BASE_DIR / "models" / "ocr_vectorizer.pkl"

# ---------------- LOAD MODEL ----------------
model = None
vectorizer = None
tokenizer = None
encoder = None
torch = None


def _load_transformer_dependencies():
    global torch
    try:
        import torch as torch_module
        from transformers import AutoModel, AutoTokenizer
    except ImportError as exc:
        raise RuntimeError("DistilBERT OCR model requires transformers and torch") from exc

    torch = torch_module
    return AutoTokenizer, AutoModel


def load_ocr_model():
    global model, vectorizer, tokenizer, encoder
    if model is None:
        logger.info("Loading OCR ML model from %s", MODEL_PATH)
        bundle = joblib.load(MODEL_PATH)
        if isinstance(bundle, dict) and "model" in bundle:
            model = bundle
            if bundle.get("model_type") == "legacy_vectorizer" and VEC_PATH.exists():
                vectorizer = joblib.load(VEC_PATH)
            if bundle.get("model_type") == "distilbert_embeddings":
                AutoTokenizer, AutoModel = _load_transformer_dependencies()
                model_name = bundle.get("encoder_name", "distilbert-base-uncased")
                tokenizer = AutoTokenizer.from_pretrained(model_name, local_files_only=True)
                encoder = AutoModel.from_pretrained(model_name, local_files_only=True)
                encoder.eval()
        else:
            vectorizer = joblib.load(VEC_PATH)
            model = {
                "model": bundle,
                "model_name": "Legacy TF-IDF OCR Model",
                "model_type": "legacy_vectorizer",
                "metrics": {},
            }
        logger.info("OCR ML model and vectorizer loaded successfully")
    return model


def _mean_pool(last_hidden_state, attention_mask):
    mask = attention_mask.unsqueeze(-1).expand(last_hidden_state.size()).float()
    masked = last_hidden_state * mask
    return masked.sum(1) / mask.sum(1).clamp(min=1e-9)


def _distilbert_features(text):
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    encoder.to(device)
    encoded = tokenizer(
        [text],
        padding=True,
        truncation=True,
        max_length=256,
        return_tensors="pt",
    )
    encoded = {key: value.to(device) for key, value in encoded.items()}
    with torch.no_grad():
        output = encoder(**encoded)
        pooled = _mean_pool(output.last_hidden_state, encoded["attention_mask"])
    return np.asarray(pooled.cpu().numpy())


def _predict_phishing_probability(text):
    bundle = load_ocr_model()
    loaded_model = bundle["model"]
    model_type = bundle.get("model_type", "legacy_vectorizer")

    if model_type == "pipeline":
        return float(loaded_model.predict_proba([text])[0][1]), bundle

    if model_type == "distilbert_embeddings":
        features = _distilbert_features(text)
        return float(loaded_model.predict_proba(features)[0][1]), bundle

    X = vectorizer.transform([text])
    return float(loaded_model.predict_proba(X)[0][1]), bundle

# ---------------- CONTEXT WORD SETS ----------------
SAFE_CONTEXT_WORDS = {
    "university", "college", "institute", "education",
    "admission", "faculty", "department", "syllabus",
    "curriculum", "research", "campus", "academic",
    "students", "examination", "results", "library",
    "placements", "engineering", "vtU", "ugc"
}

GAMBLING_WORDS = {
    "rummy", "casino", "bet", "betting", "jackpot",
    "lottery", "spin", "play now", "win cash",
    "online gaming", "real money", "withdraw"
}

DECEPTIVE_ACTION_WORDS = {
    "register now", "sign up", "instant bonus",
    "limited offer", "act now", "withdraw now",
    "claim reward", "verify to withdraw",
    "bonus", "instant", "claim", "deposit"
}


# ---------------- OCR NLP PREDICTION ----------------
def predict_ocr_text(text: str):
    """
    ML-based phishing detection using OCR-extracted webpage text
    """

    logger.info("OCR ML prediction started with %d characters", len(text or ""))

    if not text or len(text.strip()) < 20:
        logger.warning("OCR ML prediction skipped: insufficient text")
        return {
            "prediction": "Suspicious",
            "verdict": "Suspicious",
            "risk_score": 0.5,
            "confidence": 50.0,
            "reasons": ["Insufficient visible text for confident analysis"]
        }

    text_lower = text.lower()

    # -------- VECTORIZE --------
    phishing_prob, bundle = _predict_phishing_probability(text)

    reasons = [f"{bundle.get('model_name', 'OCR model')} text classification"]

    # -------- SAFE CONTEXT BIAS (college / govt sites) --------
    if any(word in text_lower for word in SAFE_CONTEXT_WORDS):
        phishing_prob -= 0.20
        reasons.append("Academic / institutional context detected")

    # -------- GAMBLING + DECEPTION BOOST --------
    has_gambling = any(word in text_lower for word in GAMBLING_WORDS)
    has_deception = any(word in text_lower for word in DECEPTIVE_ACTION_WORDS)

    if has_gambling:
        phishing_prob += 0.25
        reasons.append("Real-money gaming indicators detected")

    if has_deception:
        phishing_prob += 0.20
        reasons.append("High-pressure action phrases detected")

    # -------- CLAMP PROBABILITY --------
    phishing_prob = min(max(phishing_prob, 0.0), 1.0)

    # 🔑 ROUND FIRST, THEN DECIDE (CRITICAL FIX)
    final_score = round(phishing_prob, 2)

    # -------- FINAL VERDICT --------
    if final_score >= 0.70:
        verdict = "Phishing"
    elif final_score >= 0.50:
        verdict = "Suspicious"
    else:
        verdict = "Safe"

    confidence = final_score if verdict in {"Phishing", "Suspicious"} else 1 - final_score
    logger.info(
        "OCR ML prediction complete: prediction=%s risk_score=%.2f confidence=%.2f",
        verdict,
        final_score,
        confidence,
    )

    return {
        "prediction": verdict,
        "verdict": verdict,
        "risk_score": final_score,
        "confidence": round(confidence * 100, 2),
        "model": bundle.get("model_name", "OCR model"),
        "metrics": bundle.get("metrics", {}),
        "reasons": reasons
    }
