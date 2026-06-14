import logging
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse


logger = logging.getLogger(__name__)

# ---------------- SAFE HTML FETCH ----------------
def fetch_html(url: str, timeout=8):
    """
    Fetch HTML safely without executing JavaScript.
    Only static content is retrieved.
    """
    headers = {
        "User-Agent": "Mozilla/5.0 (KingPhisher Analyzer)"
    }

    logger.info("HTML fetch started for %s", url)
    response = requests.get(
        url,
        headers=headers,
        timeout=timeout,
        allow_redirects=True
    )
    response.raise_for_status()
    logger.info("HTML fetch complete for %s with %d characters", url, len(response.text))

    return response.text


# ---------------- HTML FEATURE ANALYSIS ----------------
def analyze_html(url: str):
    """
    Analyze webpage HTML to estimate phishing risk.
    Uses rule-based scoring.
    """

    logger.info("HTML analysis started for %s", url)

    try:
        html = fetch_html(url)
    except Exception as e:
        logger.exception("HTML analysis failed while fetching %s", url)
        return {
            "prediction": "Suspicious",
            "risk_score": 0.5,
            "confidence": 50.0,
            "reasons": ["Insufficient page data for detailed analysis"],
            "error": str(e)
        }

    soup = BeautifulSoup(html, "html.parser")

    score = 0
    reasons = []

    # ---------- 1. Password input detection ----------
    password_inputs = soup.find_all("input", {"type": "password"})
    if password_inputs:
        score += 0.25
        reasons.append(
            "+0.25 Page contains password input fields"
        )

    # ---------- 2. External form submission ----------
    forms = soup.find_all("form")
    current_domain = urlparse(url).netloc

    for form in forms:
        action = form.get("action", "")

        if action.startswith("http"):
            action_domain = urlparse(action).netloc

            if action_domain and action_domain != current_domain:
                score += 0.2
                reasons.append(
                    "+0.20 Login or data form sends information to another website"
                )
                break

    # ---------- 3. Login / phishing keywords ----------
    text = soup.get_text().lower()

    phishing_words = [
        "verify your account",
        "login immediately",
        "confirm password",
        "account suspended",
        "security alert",
        "update your account",
        "enter credentials",
    ]

    for word in phishing_words:
        if word in text:
            score += 0.1
            reasons.append(
                "+0.10 Page requests login or account information"
            )
            break

    # ---------- 4. External redirects ----------
    links = soup.find_all("a", href=True)

    for link in links:
        href = link["href"]

        if href.startswith("http"):
            link_domain = urlparse(href).netloc

            if link_domain and link_domain != current_domain:
                score += 0.1
                reasons.append(
                    "+0.10 Page contains links redirecting to different websites"
                )
                break

    # ---------- 5. No HTTPS ----------
    if not url.lower().startswith("https"):
        score += 0.1
        reasons.append(
            "+0.10 Website does not use HTTPS encryption"
        )

    # ---------- Clamp final score ----------
    score = min(score, 1.0)

    if score >= 0.6:
        prediction = "Phishing"
    elif score >= 0.3:
        prediction = "Suspicious"
    else:
        prediction = "Safe"

    confidence = score if prediction in {"Phishing", "Suspicious"} else 1 - score
    logger.info(
        "HTML analysis complete: prediction=%s risk_score=%.2f confidence=%.2f",
        prediction,
        score,
        confidence,
    )

    if not reasons:
        reasons.append("No suspicious HTML patterns detected")

    return {
        "prediction": prediction,
        "risk_score": round(score, 2),
        "confidence": round(confidence * 100, 2),
        "reasons": reasons
    }
