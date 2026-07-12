import logging


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


def _score_from_result(result):
    if not result:
        return None
    score = result.get("risk_score")
    if score is None:
        return None
    return float(score)


def _detail(module, weight_key, result):
    if not result:
        return None
    return {
        "module": module,
        "weight": ENSEMBLE_WEIGHTS[weight_key],
        "result": result,
    }


def ensemble_decision(
    url_result: dict,
    ocr_result: dict | None = None,
    html_result: dict | None = None,
):
    """
    Combine already-computed module results into a final detection decision.
    """
    logger.info("Ensemble score combination started")
    reasons = []

    url_score = _score_from_result(url_result)
    if url_score is None:
        raise ValueError("URL ML result with risk_score is required")

    ocr_score = _score_from_result(ocr_result)
    html_score = _score_from_result(html_result)

    results = [
        detail for detail in [
            _detail("URL ML", "url", url_result),
            _detail("OCR NLP", "ocr", ocr_result),
            _detail("HTML Analyzer", "html", html_result),
        ]
        if detail
    ]

    reasons.append(f"URL analysis: {url_result['prediction']}")
    logger.info("Ensemble URL contribution: %.3f", url_score)

    if ocr_result:
        reasons.append(f"OCR text analysis: {ocr_result['prediction']}")
        reasons.extend(ocr_result.get("reasons", []))
        logger.info("Ensemble OCR contribution: %.3f", ocr_score)

    if html_result:
        reasons.append(f"HTML analysis: {html_result['prediction']}")
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
        "url_score": round(url_score * 100, 2),
        "ocr_score": round(ocr_score * 100, 2) if ocr_score is not None else None,
        "html_score": round(html_score * 100, 2) if html_score is not None else None,
        "details": results,
        "reasons": reasons
    }
