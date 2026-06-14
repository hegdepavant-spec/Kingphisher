import json
import logging
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock


logger = logging.getLogger(__name__)
BASE_DIR = Path(__file__).resolve().parents[1]
HISTORY_PATH = BASE_DIR / "data" / "scan_history.json"
_LOCK = Lock()


def _now_iso():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _status_from_result(result):
    prediction = result.get("prediction") or result.get("verdict") or result.get("status")
    if prediction in {"Safe", "Suspicious", "Phishing"}:
        return prediction

    score = _float_or_default(result.get("risk_score"), 0)
    if score >= 0.6:
        return "Phishing"
    if score >= 0.35:
        return "Suspicious"
    return "Safe"


def _float_or_default(value, default=0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _read_records_unlocked():
    if not HISTORY_PATH.exists():
        return []
    try:
        return json.loads(HISTORY_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        logger.exception("Failed to read scan history from %s", HISTORY_PATH)
        return []


def _write_records_unlocked(records):
    HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    HISTORY_PATH.write_text(json.dumps(records, indent=2), encoding="utf-8")


def normalize_scan_record(result, url=None, scan_type="url", source="web", timestamp=None):
    status = _status_from_result(result)
    target_url = (
        url
        or result.get("url")
        or result.get("decoded_url")
        or result.get("target")
        or "Uploaded image"
    )
    risk_score = _float_or_default(result.get("risk_score"), 0)
    confidence = _float_or_default(result.get("confidence"), 0)
    details = result.get("details") or []
    reasons = result.get("reasons") or []

    return {
        "id": result.get("id") or uuid.uuid4().hex,
        "url": target_url,
        "timestamp": timestamp or result.get("timestamp") or result.get("scanned_at") or _now_iso(),
        "status": status,
        "prediction": status,
        "risk_score": round(risk_score, 3),
        "confidence": round(confidence, 2),
        "reasons": reasons,
        "details": details,
        "source": source,
        "scan_type": scan_type,
        "extracted_text": result.get("extracted_text", ""),
        "decoded_url": result.get("decoded_url", ""),
        "recommendation": recommendation_for(status, risk_score),
        "blocked": status in {"Suspicious", "Phishing"},
    }


def recommendation_for(status, score):
    if status == "Phishing" or score >= 0.6:
        return "Block access and avoid submitting credentials or payment information."
    if status == "Suspicious" or score >= 0.35:
        return "Verify the sender, domain, and page intent before continuing."
    return "No immediate phishing indicators were detected."


def save_scan_record(result, url=None, scan_type="url", source="web", timestamp=None):
    record = normalize_scan_record(result, url=url, scan_type=scan_type, source=source, timestamp=timestamp)
    with _LOCK:
        records = _read_records_unlocked()
        records.insert(0, record)
        _write_records_unlocked(records[:1000])
    logger.info(
        "Stored scan history record id=%s source=%s type=%s status=%s risk=%.3f url=%s",
        record["id"],
        source,
        scan_type,
        record["status"],
        record["risk_score"],
        record["url"],
    )
    return record


def list_scan_records(search="", status="", scan_type="", source="", sort_by="date", sort_dir="desc", page=1, page_size=100):
    with _LOCK:
        records = list(_read_records_unlocked())

    query = search.strip().lower()
    if query:
        records = [record for record in records if query in str(record.get("url", "")).lower()]
    if status:
        records = [record for record in records if record.get("status") == status]
    if scan_type:
        records = [record for record in records if record.get("scan_type") == scan_type]
    if source:
        records = [record for record in records if record.get("source") == source]

    reverse = sort_dir != "asc"
    if sort_by == "risk":
        records.sort(key=lambda item: _float_or_default(item.get("risk_score"), 0), reverse=reverse)
    else:
        records.sort(key=lambda item: item.get("timestamp", ""), reverse=reverse)

    total = len(records)
    safe_page = max(1, int(page or 1))
    safe_page_size = min(250, max(1, int(page_size or 100)))
    start = (safe_page - 1) * safe_page_size
    end = start + safe_page_size
    logger.info(
        "History query returned %d/%d records search=%r status=%r sort=%s:%s page=%d page_size=%d",
        len(records[start:end]),
        total,
        search,
        status,
        sort_by,
        sort_dir,
        safe_page,
        safe_page_size,
    )
    return {
        "items": records[start:end],
        "total": total,
        "page": safe_page,
        "page_size": safe_page_size,
    }


def epoch_millis_to_iso(value):
    try:
        return datetime.fromtimestamp(float(value) / 1000, timezone.utc).isoformat().replace("+00:00", "Z")
    except (TypeError, ValueError, OSError):
        return _now_iso()


def batch_id():
    return f"hist-{int(time.time())}-{uuid.uuid4().hex[:8]}"
