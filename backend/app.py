from flask import Flask, request, jsonify
from flask_cors import CORS
import re, math, requests
from bs4 import BeautifulSoup
from PIL import Image
import pytesseract
from io import BytesIO

app = Flask(__name__)
CORS(app)

# ---------------- HELPERS ----------------

def entropy(s):
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)

def has_ip(url):
    return bool(re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", url))

PHISH_KEYWORDS = [
    "login", "verify", "update", "secure", "account",
    "bank", "confirm", "signin", "payment", "reset"
]

# ---------------- OCR + PAGE TEXT ----------------

def extract_text_from_url(url):
    text = ""
    try:
        res = requests.get(url, timeout=4, headers={"User-Agent": "Mozilla/5.0"})
        soup = BeautifulSoup(res.text, "html.parser")
        text += soup.get_text(" ")

        for img in soup.find_all("img")[:3]:
            src = img.get("src")
            if not src:
                continue
            if src.startswith("//"):
                src = "https:" + src
            if src.startswith("/"):
                src = url.rstrip("/") + src

            try:
                img_res = requests.get(src, timeout=3)
                image = Image.open(BytesIO(img_res.content))
                text += " " + pytesseract.image_to_string(image)
            except:
                pass
    except:
        pass

    return text.lower()

# ---------------- FEATURE EXTRACTION ----------------

def extract_features(url):
    page_text = extract_text_from_url(url)
    keywords = [k for k in PHISH_KEYWORDS if k in url.lower() or k in page_text]

    return {
        "length": len(url),
        "dots": url.count("."),
        "hyphens": url.count("-"),
        "entropy": entropy(url),
        "has_ip": has_ip(url),
        "https": url.startswith("https"),
        "keywords": keywords
    }

# ---------------- PREDICTION LOGIC ----------------

def predict_with_reasons(url):
    f = extract_features(url)
    score = 0
    reasons = []

    if f["length"] > 75:
        score += 15
        reasons.append("URL is unusually long")

    if f["dots"] > 3:
        score += 10
        reasons.append("Too many dots in URL")

    if f["hyphens"] > 2:
        score += 10
        reasons.append("Multiple hyphens detected")

    if f["has_ip"]:
        score += 20
        reasons.append("IP address used instead of domain")

    if f["entropy"] > 4:
        score += 15
        reasons.append("URL looks random")

    if f["keywords"]:
        score += 10 * len(f["keywords"])
        reasons.append(f"Suspicious words detected: {', '.join(f['keywords'])}")

    if not f["https"]:
        score += 10
        reasons.append("Website does not use HTTPS")

    score = min(score, 100)

    if score >= 60:
        return "Phishing", score, reasons

    if score >= 25:
        return "Suspicious", score, reasons

    return "Safe", max(90, 100 - score), [
        "No suspicious patterns detected",
        "Page content appears normal"
    ]

# ---------------- API ----------------

@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json(force=True)
    url = data.get("url", "").strip()

    if not url:
        return jsonify({
            "prediction": "Invalid",
            "confidence": 0,
            "reasons": ["No URL provided"]
        }), 400

    prediction, confidence, reasons = predict_with_reasons(url)

    return jsonify({
        "prediction": prediction,
        "confidence": round(confidence, 2),
        "reasons": reasons
    })

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
