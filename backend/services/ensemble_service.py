from services.url_ml_service import predict_url
from services.ocr_ml_service import predict_ocr_text
from services.html_analyzer import analyze_html


def ensemble_decision(
    url: str,
    ocr_text: str | None = None,
    use_html: bool = True
):
    """
    Combines URL ML, OCR NLP ML, and HTML Analyzer
    """

    results = []
    total_score = 0.0
    weight_sum = 0.0
    reasons = []

    # ---------------- URL ML ----------------
    url_result = predict_url(url)
    url_score = url_result["confidence"]
    if url_result["prediction"] == "phishing":
        total_score += 0.4 * url_score
    else:
        total_score += 0.4 * (1 - url_score)

    weight_sum += 0.4
    results.append(("URL ML", url_result))
    reasons.append(f"URL analysis: {url_result['prediction']}")

    # ---------------- OCR NLP ML ----------------
    if ocr_text:
        ocr_result = predict_ocr_text(ocr_text)
        ocr_score = ocr_result["confidence"]

        if ocr_result["prediction"] == "phishing":
            total_score += 0.35 * ocr_score
        else:
            total_score += 0.35 * (1 - ocr_score)

        weight_sum += 0.35
        results.append(("OCR NLP", ocr_result))
        reasons.append(f"OCR text analysis: {ocr_result['prediction']}")

    # ---------------- HTML ANALYZER ----------------
    if use_html:
        html_result = analyze_html(url)
        html_score = html_result.get("risk_score", 0.5)

        total_score += 0.25 * html_score
        weight_sum += 0.25

        results.append(("HTML Analyzer", html_result))
        reasons.extend(html_result.get("reasons", []))

    # ---------------- FINAL DECISION ----------------
    final_score = total_score / weight_sum if weight_sum else 0.5

    verdict = "PHISHING" if final_score >= 0.5 else "SAFE"

    return {
        "verdict": verdict,
        "confidence": round(final_score, 3),
        "details": results,
        "reasons": reasons
    }
