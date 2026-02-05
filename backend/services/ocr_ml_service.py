import joblib
from pathlib import Path

# ---------------- PATHS ----------------
BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_PATH = BASE_DIR / "models" / "ocr_model.pkl"
VEC_PATH = BASE_DIR / "models" / "ocr_vectorizer.pkl"

# ---------------- LOAD MODEL ----------------
model = joblib.load(MODEL_PATH)
vectorizer = joblib.load(VEC_PATH)

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

    if not text or len(text.strip()) < 20:
        return {
            "verdict": "CHECK",
            "risk_score": 0.5,
            "reasons": ["Insufficient visible text for confident analysis"]
        }

    text_lower = text.lower()

    # -------- VECTORIZE --------
    X = vectorizer.transform([text])
    phishing_prob = float(model.predict_proba(X)[0][1])

    reasons = ["NLP text classification"]

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
        verdict = "PHISHING"
    elif final_score >= 0.50:
        verdict = "CHECK"
    else:
        verdict = "SAFE"

    return {
        "verdict": verdict,
        "risk_score": final_score,
        "reasons": reasons
    }
