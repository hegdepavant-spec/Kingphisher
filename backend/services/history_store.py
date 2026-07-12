import json
import logging
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock

from services.db import get_cursor, initialize_database


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


def _timestamp_for_db(value):
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).replace(tzinfo=None) if value.tzinfo else value
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(timezone.utc).replace(tzinfo=None)
    except (TypeError, ValueError):
        return datetime.now(timezone.utc).replace(tzinfo=None)


def _timestamp_from_db(value):
    if isinstance(value, datetime):
        return value.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
    return value or _now_iso()


def _record_from_row(row):
    risk_score = _float_or_default(row.get("risk_score"), 0)
    confidence = _float_or_default(row.get("confidence"), 0)
    status = row.get("status") or row.get("prediction") or "Safe"
    return {
        "id": row.get("id"),
        "url": row.get("url") or "",
        "timestamp": _timestamp_from_db(row.get("timestamp")),
        "status": status,
        "prediction": row.get("prediction") or status,
        "risk_score": round(risk_score, 3),
        "confidence": round(confidence, 2),
        "reasons": [],
        "details": [],
        "source": row.get("source") or "",
        "scan_type": row.get("scan_type") or "",
        "extracted_text": row.get("extracted_text") or "",
        "decoded_url": row.get("decoded_url") or "",
        "recommendation": row.get("recommendation") or recommendation_for(status, risk_score),
        "blocked": bool(row.get("blocked")),
    }


def _save_record_to_json_backup(record):
    try:
        with _LOCK:
            records = _read_records_unlocked()
            records.insert(0, record)
            _write_records_unlocked(records[:1000])
    except OSError:
        logger.exception("Failed to write scan history backup to %s", HISTORY_PATH)


def _insert_record(record):
    initialize_database()
    insert_sql = """
    INSERT INTO scan_history (
        id, url, timestamp, status, prediction, risk_score, confidence,
        source, scan_type, extracted_text, decoded_url, recommendation, blocked
    ) VALUES (
        %(id)s, %(url)s, %(timestamp)s, %(status)s, %(prediction)s,
        %(risk_score)s, %(confidence)s, %(source)s, %(scan_type)s,
        %(extracted_text)s, %(decoded_url)s, %(recommendation)s, %(blocked)s
    )
    ON CONFLICT (id) DO UPDATE SET
        url = EXCLUDED.url,
        timestamp = EXCLUDED.timestamp,
        status = EXCLUDED.status,
        prediction = EXCLUDED.prediction,
        risk_score = EXCLUDED.risk_score,
        confidence = EXCLUDED.confidence,
        source = EXCLUDED.source,
        scan_type = EXCLUDED.scan_type,
        extracted_text = EXCLUDED.extracted_text,
        decoded_url = EXCLUDED.decoded_url,
        recommendation = EXCLUDED.recommendation,
        blocked = EXCLUDED.blocked
    """
    params = {
        "id": record["id"],
        "url": record.get("url", ""),
        "timestamp": _timestamp_for_db(record.get("timestamp")),
        "status": record.get("status", ""),
        "prediction": record.get("prediction", ""),
        "risk_score": record.get("risk_score", 0),
        "confidence": record.get("confidence", 0),
        "source": record.get("source", ""),
        "scan_type": record.get("scan_type", ""),
        "extracted_text": record.get("extracted_text", ""),
        "decoded_url": record.get("decoded_url", ""),
        "recommendation": record.get("recommendation", ""),
        "blocked": bool(record.get("blocked")),
    }
    with get_cursor(commit=True) as cursor:
        logger.info(
            "Executing PostgreSQL INSERT for scan_history id=%s source=%s type=%s status=%s",
            params["id"],
            params["source"],
            params["scan_type"],
            params["status"],
        )
        logger.info("PostgreSQL INSERT SQL: %s", insert_sql.strip())
        logger.info("PostgreSQL INSERT params: %r", params)
        cursor.execute(insert_sql, params)
        logger.info("PostgreSQL INSERT executed for scan_history id=%s rowcount=%s", params["id"], cursor.rowcount)


def _list_records_from_db(search="", status="", scan_type="", source="", sort_by="date", sort_dir="desc", page=1, page_size=100):
    initialize_database()
    safe_page = max(1, int(page or 1))
    safe_page_size = min(250, max(1, int(page_size or 100)))
    offset = (safe_page - 1) * safe_page_size

    where_clauses = []
    params = {}

    query = search.strip().lower()
    if query:
        where_clauses.append("LOWER(COALESCE(url, '')) LIKE %(search)s")
        params["search"] = f"%{query}%"
    if status:
        where_clauses.append("status = %(status)s")
        params["status"] = status
    if scan_type:
        where_clauses.append("scan_type = %(scan_type)s")
        params["scan_type"] = scan_type
    if source:
        where_clauses.append("source = %(source)s")
        params["source"] = source

    where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
    order_column = "risk_score" if sort_by == "risk" else "timestamp"
    order_direction = "ASC" if sort_dir == "asc" else "DESC"

    with get_cursor() as cursor:
        cursor.execute(f"SELECT COUNT(*) AS total FROM scan_history {where_sql}", params)
        total = int(cursor.fetchone()["total"])
        cursor.execute(
            f"""
            SELECT
                id, url, timestamp, status, prediction, risk_score, confidence,
                source, scan_type, extracted_text, decoded_url, recommendation, blocked
            FROM scan_history
            {where_sql}
            ORDER BY {order_column} {order_direction}
            LIMIT %(limit)s OFFSET %(offset)s
            """,
            {**params, "limit": safe_page_size, "offset": offset},
        )
        items = [_record_from_row(row) for row in cursor.fetchall()]

    return {
        "items": items,
        "total": total,
        "page": safe_page,
        "page_size": safe_page_size,
    }


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
    try:
        _insert_record(record)
        logger.info("Stored scan history record in PostgreSQL id=%s", record["id"])
    except Exception:
        logger.exception(
            "PostgreSQL insert failed for scan history record id=%s; writing JSON backup to %s",
            record["id"],
            HISTORY_PATH,
        )
        _save_record_to_json_backup(record)
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
    try:
        data = _list_records_from_db(
            search=search,
            status=status,
            scan_type=scan_type,
            source=source,
            sort_by=sort_by,
            sort_dir=sort_dir,
            page=page,
            page_size=page_size,
        )
        logger.info(
            "History query returned %d/%d records search=%r status=%r sort=%s:%s page=%d page_size=%d",
            len(data["items"]),
            data["total"],
            search,
            status,
            sort_by,
            sort_dir,
            data["page"],
            data["page_size"],
        )
        return data
    except Exception:
        logger.exception("PostgreSQL history query failed; falling back to JSON scan history backup")

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
