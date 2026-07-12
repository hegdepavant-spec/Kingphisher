import logging
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse


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
    current_domain = urlparse(url).netloc.lower()

    def is_external(candidate):
        parsed = urlparse(urljoin(url, candidate or ""))
        return bool(parsed.netloc and parsed.netloc.lower() != current_domain)

    # ---------- 1. Forms and form actions ----------
    forms = soup.find_all("form")
    password_inputs = soup.find_all("input", {"type": "password"})
    if password_inputs:
        score += 0.20
        reasons.append("+0.20 Page contains password input fields")

    hidden_inputs = soup.find_all("input", {"type": "hidden"})
    if len(hidden_inputs) >= 3:
        score += 0.08
        reasons.append("+0.08 Multiple hidden input fields detected")

    for form in forms:
        action = form.get("action", "")
        if not action:
            score += 0.05
            reasons.append("+0.05 Form has a missing or empty action")
            break
        if is_external(action):
            score += 0.20
            reasons.append("+0.20 Form sends submitted data to an external domain")
            break

    # ---------- 2. Iframes ----------
    iframes = soup.find_all("iframe", src=True)
    external_iframes = [iframe for iframe in iframes if is_external(iframe.get("src"))]
    if external_iframes:
        score += 0.12
        reasons.append("+0.12 External iframe content detected")

    # ---------- 3. Meta refresh redirects ----------
    for meta in soup.find_all("meta"):
        http_equiv = (meta.get("http-equiv") or "").lower()
        content = meta.get("content") or ""
        if http_equiv == "refresh":
            score += 0.14
            reasons.append("+0.14 Meta refresh redirect detected")
            if "url=" in content.lower() and is_external(content.split("=", 1)[-1].strip()):
                score += 0.08
                reasons.append("+0.08 Meta refresh points to an external domain")
            break

    # ---------- 4. JavaScript redirects and suspicious scripts ----------
    inline_scripts = " ".join(script.get_text(" ", strip=True) for script in soup.find_all("script"))
    script_lower = inline_scripts.lower()
    redirect_patterns = [
        "window.location",
        "location.href",
        "location.replace",
        "document.location",
    ]
    if any(pattern in script_lower for pattern in redirect_patterns):
        score += 0.14
        reasons.append("+0.14 JavaScript redirect behavior detected")

    suspicious_script_patterns = [
        "eval(",
        "atob(",
        "fromcharcode",
        "document.write",
        "settimeout(",
    ]
    if any(pattern in script_lower for pattern in suspicious_script_patterns):
        score += 0.12
        reasons.append("+0.12 Obfuscated or dynamically-written script behavior detected")

    external_scripts = [script for script in soup.find_all("script", src=True) if is_external(script.get("src"))]
    if len(external_scripts) >= 3:
        score += 0.08
        reasons.append("+0.08 Multiple external scripts loaded")

    # ---------- 5. External resources ----------
    resource_tags = [
        ("link", "href"),
        ("script", "src"),
        ("img", "src"),
        ("iframe", "src"),
    ]
    external_resources = []
    for tag_name, attr in resource_tags:
        external_resources.extend(
            tag for tag in soup.find_all(tag_name) if tag.get(attr) and is_external(tag.get(attr))
        )
    if len(external_resources) >= 8:
        score += 0.08
        reasons.append("+0.08 Page loads many external resources")

    # ---------- 6. Login / phishing keywords ----------
    text = soup.get_text(" ", strip=True).lower()
    phishing_words = [
        "verify your account",
        "login immediately",
        "confirm password",
        "account suspended",
        "security alert",
        "update your account",
        "enter credentials",
    ]
    if any(word in text for word in phishing_words):
        score += 0.10
        reasons.append("+0.10 Page requests login or account information")

    # ---------- 7. External links and HTTPS ----------
    links = soup.find_all("a", href=True)
    if any(is_external(link.get("href")) for link in links):
        score += 0.06
        reasons.append("+0.06 Page contains links to different domains")

    if not url.lower().startswith("https"):
        score += 0.1
        reasons.append("+0.10 Website does not use HTTPS encryption")

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
