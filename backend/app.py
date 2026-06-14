import logging
import json
from io import BytesIO
from pathlib import Path

from flask import Flask, jsonify, request
from flask_cors import CORS
from PIL import Image, ImageOps

try:
    import pytesseract
except ImportError:
    pytesseract = None

from services.ensemble_service import ensemble_decision
from services.history_store import (
    batch_id,
    epoch_millis_to_iso,
    list_scan_records,
    save_scan_record,
)
from services.html_analyzer import analyze_html
from services.ocr_ml_service import predict_ocr_text
from services.qr_service import analyze_qr_image
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


def extract_text_from_uploaded_image(file_storage):
    logger.info("OCR image upload received: filename=%s", file_storage.filename)
    if pytesseract is None:
        raise RuntimeError("pytesseract Python package is not installed")

    raw = file_storage.read()
    logger.info("OCR image bytes read: %d", len(raw))
    image = Image.open(BytesIO(raw))
    image = ImageOps.grayscale(image)
    text = pytesseract.image_to_string(image).strip()
    logger.info("OCR text extraction complete: %d characters", len(text))
    return text


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
        extracted_text = extract_text_from_uploaded_image(image_file)
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
        result = analyze_qr_image(image_file)
    except Exception as exc:
        logger.exception("QR phishing detection failed")
        return _json_error("QR phishing detection failed", 500, str(exc))

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
    ocr_text = None

    if request.content_type and request.content_type.startswith("multipart/form-data"):
        url = str(request.form.get("url", "")).strip()
        use_html = request.form.get("use_html", "true").lower() != "false"
        image_file = request.files.get("image") or request.files.get("file")
        if image_file is not None:
            try:
                ocr_text = extract_text_from_uploaded_image(image_file)
            except Exception as exc:
                logger.exception("Ensemble OCR extraction failed")
                return _json_error("Ensemble OCR extraction failed", 500, str(exc))
    else:
        payload = _get_json_payload()
        url = str(payload.get("url", "")).strip()
        use_html = bool(payload.get("use_html", True))
        ocr_text = payload.get("ocr_text")

    if not url:
        return _json_error("No URL provided", 400)

    try:
        result = ensemble_decision(url=url, ocr_text=ocr_text, use_html=use_html)
    except Exception as exc:
        logger.exception("Ensemble detection failed for %s", url)
        return _json_error("Ensemble detection failed", 500, str(exc))

    if ocr_text is not None:
        result["extracted_text"] = ocr_text

    save_scan_record(result, url=url, scan_type="url", source="api")
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
            result = ensemble_decision(url=url, use_html=use_html)
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
