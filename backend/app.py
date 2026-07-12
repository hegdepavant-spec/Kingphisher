import logging
import json
import traceback
import uuid
from pathlib import Path

from flask import Flask, jsonify, request
from flask_cors import CORS

from services.db import get_database_status
from services.ensemble_service import ensemble_decision
from services.history_store import (
    _insert_record,
    batch_id,
    epoch_millis_to_iso,
    list_scan_records,
    save_scan_record,
)
from services.html_analyzer import analyze_html
from services.ocr_ml_service import predict_ocr_text
from services.ocr_service import extract_text_from_upload
from services.qr_service import decode_qr_image
from services.url_ml_service import predict_url


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger(__name__)
BASE_DIR = Path(__file__).resolve().parent
REPORT_FILES = {
    "url": BASE_DIR / "models" / "url_accuracy_report.json",
    "ocr": BASE_DIR / "models" / "ocr_accuracy_report.json",
    "ensemble": BASE_DIR / "models" / "ensemble_accuracy_report.json",
}

app = Flask(__name__)
CORS(app)


def _log_database_startup_status():
    try:
        status = get_database_status()
        logger.info(
            "PostgreSQL connected successfully on startup database=%s table=%s count=%d",
            status["database"],
            status["table"],
            status["table_count"],
        )
    except Exception as exc:
        logger.exception("PostgreSQL startup check failed: %s", exc)


_log_database_startup_status()


def _json_error(message, status_code=400, details=None):
    payload = {
        "prediction": "Invalid",
        "confidence": 0,
        "risk_score": 0,
        "reasons": [message],
    }
    if details:
        payload["error"] = details
    logger.warning("API error: %s", message)
    return jsonify(payload), status_code


def _get_json_payload():
    return request.get_json(silent=True) or {}


def _get_url_from_json():
    url = str(_get_json_payload().get("url", "")).strip()
    if not url:
        return None
    return url


def _load_report(path):
    if not path.exists():
        return {
            "available": False,
            "message": "Run the training/evaluation scripts to generate this report.",
        }
    return {
        "available": True,
        **json.loads(path.read_text(encoding="utf-8")),
    }


def _append_reason(result, reason):
    result.setdefault("reasons", []).append(reason)
    return result


@app.route("/", methods=["GET"])
@app.route("/api/health", methods=["GET"])
def health_check():
    return jsonify({
        "name": "KingPhisher backend",
        "status": "ok",
        "message": "Backend is running. Use the React frontend at http://127.0.0.1:5173.",
        "endpoints": {
            "url": "POST /api/url",
            "ocr": "POST /api/ocr",
            "qr": "POST /api/qr",
            "html": "POST /api/html",
            "ensemble": "POST /api/ensemble",
            "history": "GET /api/history",
            "reports": "GET /api/reports",
        },
    })


@app.route("/api/db-test", methods=["GET"])
def db_test():
    test_id = f"db-test-{uuid.uuid4().hex[:12]}"
    record = {
        "id": test_id,
        "url": "https://kingphisher.local/db-test",
        "timestamp": None,
        "status": "Safe",
        "prediction": "Safe",
        "risk_score": 0.0,
        "confidence": 1.0,
        "source": "db-test",
        "scan_type": "db-test",
        "extracted_text": "",
        "decoded_url": "",
        "recommendation": "Database write test row.",
        "blocked": False,
    }
    try:
        _insert_record(record)
        status = get_database_status()
        return jsonify({
            "success": True,
            "inserted_id": test_id,
            "database": status["database"],
            "table": status["table"],
            "table_count": status["table_count"],
        })
    except Exception as exc:
        logger.exception("Database test route failed")
        return jsonify({
            "success": False,
            "error": str(exc),
            "traceback": traceback.format_exc(),
        }), 500


def _url_only_scan(url):
    url_result = predict_url(url)
    result = ensemble_decision(url_result=url_result)
    result["scan_mode"] = "url_ml_only"
    return result


def _manual_url_scan(url):
    logger.info("Manual URL scan workflow started for %s", url)
    url_result = predict_url(url)
    html_result = None
    fallback_reasons = []

    try:
        candidate_html_result = analyze_html(url)
        if candidate_html_result.get("error"):
            fallback_reasons.append(
                f"HTML fetch failed; final result uses URL ML only: {candidate_html_result['error']}"
            )
        else:
            html_result = candidate_html_result
    except Exception as exc:
        logger.exception("HTML analyzer failed for %s", url)
        fallback_reasons.append(f"HTML analysis failed; final result uses URL ML only: {exc}")

    result = ensemble_decision(url_result=url_result, html_result=html_result)
    result["scan_mode"] = "manual_url"
    result["html_score"] = result.get("html_score")
    for reason in fallback_reasons:
        _append_reason(result, reason)
    logger.info("Manual URL scan workflow complete for %s", url)
    return result


def _chrome_extension_scan(url, image_file):
    logger.info("Chrome extension scan workflow started for %s", url)
    url_result = predict_url(url)
    ocr_result = None
    extracted_text = ""
    fallback_reasons = []

    if image_file is None:
        fallback_reasons.append("Screenshot was not provided; final result uses URL ML only")
    else:
        try:
            extracted_text = extract_text_from_upload(image_file)
            ocr_result = predict_ocr_text(extracted_text)
        except Exception as exc:
            logger.exception("OCR workflow failed for extension scan %s", url)
            fallback_reasons.append(f"OCR failed; final result uses URL ML only: {exc}")

    result = ensemble_decision(url_result=url_result, ocr_result=ocr_result)
    result["scan_mode"] = "chrome_extension"
    if extracted_text:
        result["extracted_text"] = extracted_text
    for reason in fallback_reasons:
        _append_reason(result, reason)
    logger.info("Chrome extension scan workflow complete for %s", url)
    return result


@app.route("/predict", methods=["POST"])
@app.route("/api/url", methods=["POST"])
def url_detection():
    logger.info("URL detection API request started")
    url = _get_url_from_json()
    if not url:
        return _json_error("No URL provided", 400)

    try:
        result = predict_url(url)
    except Exception as exc:
        logger.exception("URL detection failed for %s", url)
        return _json_error("URL detection failed", 500, str(exc))

    save_scan_record(result, url=url, scan_type="url", source="api")
    logger.info("URL detection API request complete for %s", url)
    return jsonify(result)


@app.route("/api/ocr", methods=["POST"])
def ocr_detection():
    logger.info("OCR detection API request started")
    image_file = request.files.get("image") or request.files.get("file")
    if image_file is None:
        return _json_error("No image file provided", 400)

    try:
        extracted_text = extract_text_from_upload(image_file)
        ocr_result = predict_ocr_text(extracted_text)
    except Exception as exc:
        logger.exception("OCR detection failed")
        return _json_error("OCR detection failed", 500, str(exc))

    response = {
        **ocr_result,
        "extracted_text": extracted_text,
    }
    save_scan_record(response, scan_type="ocr", source="api")
    logger.info("OCR detection API request complete")
    return jsonify(response)


@app.route("/api/qr", methods=["POST"])
def qr_detection():
    logger.info("QR phishing detection API request started")
    image_file = request.files.get("image") or request.files.get("file")
    if image_file is None:
        return _json_error("No QR image file provided", 400)

    try:
        decoded_url = decode_qr_image(image_file)
        detection = _manual_url_scan(decoded_url)
    except Exception as exc:
        logger.exception("QR phishing detection failed")
        return _json_error("QR phishing detection failed", 500, str(exc))

    reasons = [
        f"Decoded QR URL: {decoded_url}",
        *detection.get("reasons", []),
    ]
    result = {
        **detection,
        "decoded_url": decoded_url,
        "explanation": reasons,
        "reasons": reasons,
        "scan_mode": "qr_manual_url",
    }
    save_scan_record(result, url=result.get("decoded_url"), scan_type="qr", source="api")
    logger.info("QR phishing detection API request complete")
    return jsonify(result)


@app.route("/api/html", methods=["POST"])
def html_analysis():
    logger.info("HTML analysis API request started")
    url = _get_url_from_json()
    if not url:
        return _json_error("No URL provided", 400)

    result = analyze_html(url)
    save_scan_record(result, url=url, scan_type="html", source="api")
    logger.info("HTML analysis API request complete for %s", url)
    return jsonify(result)


@app.route("/api/ensemble", methods=["POST"])
def ensemble_detection():
    logger.info("Ensemble API request started")

    if request.content_type and request.content_type.startswith("multipart/form-data"):
        url = str(request.form.get("url", "")).strip()
        image_file = request.files.get("image") or request.files.get("file")
        scan_source = request.form.get("source", "extension")
    else:
        payload = _get_json_payload()
        url = str(payload.get("url", "")).strip()
        image_file = None
        scan_source = payload.get("source", "web")

    if not url:
        return _json_error("No URL provided", 400)

    try:
        if request.content_type and request.content_type.startswith("multipart/form-data"):
            result = _chrome_extension_scan(url, image_file)
            history_type = "extension"
        else:
            result = _manual_url_scan(url)
            history_type = "manual_url"
    except Exception as exc:
        logger.exception("Ensemble detection failed for %s", url)
        return _json_error("Ensemble detection failed", 500, str(exc))

    save_scan_record(result, url=url, scan_type=history_type, source=scan_source)
    logger.info("Ensemble API request complete for %s", url)
    return jsonify(result)


@app.route("/api/history", methods=["GET"])
def scan_history():
    logger.info("History API request started")
    data = list_scan_records(
        search=request.args.get("search", ""),
        status=request.args.get("status", ""),
        scan_type=request.args.get("scan_type", ""),
        source=request.args.get("source", ""),
        sort_by=request.args.get("sort", "date"),
        sort_dir=request.args.get("direction", "desc"),
        page=request.args.get("page", 1),
        page_size=request.args.get("page_size", 100),
    )
    return jsonify(data)


@app.route("/api/history", methods=["POST"])
def save_history_item():
    payload = _get_json_payload()
    result = payload.get("result") or payload
    url = payload.get("url") or result.get("url") or result.get("decoded_url")
    if not url:
        return _json_error("No URL provided", 400)

    record = save_scan_record(
        result,
        url=url,
        scan_type=payload.get("scan_type", "url"),
        source=payload.get("source", "frontend"),
        timestamp=payload.get("timestamp") or payload.get("scanned_at"),
    )
    return jsonify(record), 201


@app.route("/api/browser-history", methods=["POST"])
def browser_history_scan():
    payload = _get_json_payload()
    raw_items = payload.get("items") or payload.get("history") or []
    use_html = bool(payload.get("use_html", False))
    max_items = min(100, max(1, int(payload.get("limit", len(raw_items) or 25))))
    run_id = batch_id()
    logger.info(
        "Browser history scan started batch=%s received=%d limit=%d use_html=%s",
        run_id,
        len(raw_items),
        max_items,
        use_html,
    )

    if not isinstance(raw_items, list) or not raw_items:
        return _json_error("No browser history records provided", 400)

    records = []
    seen = set()
    for item in raw_items[:max_items]:
        url = str(item.get("url", "") if isinstance(item, dict) else item).strip()
        if not url or not url.startswith(("http://", "https://")) or url in seen:
            logger.info("Browser history item skipped batch=%s url=%r", run_id, url)
            continue
        seen.add(url)

        try:
            result = _manual_url_scan(url) if use_html else _url_only_scan(url)
            timestamp = epoch_millis_to_iso(item.get("lastVisitTime")) if isinstance(item, dict) else None
            record = save_scan_record(
                {**result, "browser_title": item.get("title", "") if isinstance(item, dict) else ""},
                url=url,
                scan_type="browser_history",
                source="browser_history",
                timestamp=timestamp,
            )
            record["batch_id"] = run_id
            records.append(record)
            logger.info(
                "Browser history item analyzed batch=%s status=%s risk=%.3f url=%s",
                run_id,
                record["status"],
                record["risk_score"],
                url,
            )
        except Exception as exc:
            logger.exception("Browser history analysis failed batch=%s url=%s", run_id, url)
            records.append({
                "url": url,
                "status": "Invalid",
                "prediction": "Invalid",
                "risk_score": 0,
                "confidence": 0,
                "reasons": [str(exc)],
                "source": "browser_history",
                "scan_type": "browser_history",
                "batch_id": run_id,
            })

    logger.info("Browser history scan complete batch=%s analyzed=%d", run_id, len(records))
    return jsonify({
        "batch_id": run_id,
        "items": records,
        "total": len(records),
    })


@app.route("/api/reports", methods=["GET"])
def accuracy_reports():
    logger.info("Accuracy reports API request started")
    reports = {
        name: _load_report(path)
        for name, path in REPORT_FILES.items()
    }
    return jsonify(reports)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)