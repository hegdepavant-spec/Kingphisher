import logging

from services.url_ml_service import predict_url
from services.ocr_ml_service import predict_ocr_text
from services.html_analyzer import analyze_html


logger = logging.getLogger(__name__)
ENSEMBLE_WEIGHTS = {
    "url": 0.40,
    "ocr": 0.35,
    "html": 0.25,
}


def weighted_ensemble_score(url_score, ocr_score=None, html_score=None):
    weighted_total = ENSEMBLE_WEIGHTS["url"] * float(url_score)
    weight_sum = ENSEMBLE_WEIGHTS["url"]

    if ocr_score is not None:
        weighted_total += ENSEMBLE_WEIGHTS["ocr"] * float(ocr_score)
        weight_sum += ENSEMBLE_WEIGHTS["ocr"]

    if html_score is not None:
        weighted_total += ENSEMBLE_WEIGHTS["html"] * float(html_score)
        weight_sum += ENSEMBLE_WEIGHTS["html"]

    return weighted_total / weight_sum if weight_sum else 0.5


def verdict_from_score(score):
    if score >= 0.6:
        return "Phishing"
    if score >= 0.35:
        return "Suspicious"
    return "Safe"


def ensemble_decision(
    url: str,
    ocr_text: str | None = None,
    use_html: bool = True
):
    """
    Combines URL ML, OCR NLP ML, and HTML Analyzer
    """

    logger.info("Ensemble analysis started for %s", url)
    results = []
    ocr_score = None
    html_score = None
    reasons = []

    # ---------------- URL ML ----------------
    url_result = predict_url(url)
    url_score = float(url_result["risk_score"])
    results.append({"module": "URL ML", "weight": ENSEMBLE_WEIGHTS["url"], "result": url_result})
    reasons.append(f"URL analysis: {url_result['prediction']}")
    logger.info("Ensemble URL contribution: %.3f", url_score)

    # ---------------- OCR NLP ML ----------------
    if ocr_text:
        ocr_result = predict_ocr_text(ocr_text)
        ocr_score = float(ocr_result["risk_score"])
        results.append({"module": "OCR NLP", "weight": ENSEMBLE_WEIGHTS["ocr"], "result": ocr_result})
        reasons.append(f"OCR text analysis: {ocr_result['prediction']}")
        logger.info("Ensemble OCR contribution: %.3f", ocr_score)

    # ---------------- HTML ANALYZER ----------------
    if use_html:
        html_result = analyze_html(url)
        html_score = html_result.get("risk_score", 0.5)

        results.append({"module": "HTML Analyzer", "weight": ENSEMBLE_WEIGHTS["html"], "result": html_result})
        reasons.extend(html_result.get("reasons", []))
        logger.info("Ensemble HTML contribution: %.3f", html_score)

    # ---------------- FINAL DECISION ----------------
    final_score = weighted_ensemble_score(url_score, ocr_score, html_score)
    verdict = verdict_from_score(final_score)

    confidence = final_score if verdict in {"Phishing", "Suspicious"} else 1 - final_score
    logger.info(
        "Ensemble analysis complete: prediction=%s risk_score=%.3f confidence=%.3f",
        verdict,
        final_score,
        confidence,
    )

    return {
        "prediction": verdict,
        "verdict": verdict,
        "risk_score": round(final_score, 3),
        "confidence": round(confidence * 100, 2),
        "details": results,
        "reasons": reasons
    }
