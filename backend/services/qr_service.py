import logging
from io import BytesIO

from PIL import Image

from services.ensemble_service import ensemble_decision


logger = logging.getLogger(__name__)


def _decode_with_opencv(image):
    try:
        import cv2
        import numpy as np
    except ImportError:
        return None

    cv_image = cv2.cvtColor(np.array(image.convert("RGB")), cv2.COLOR_RGB2BGR)
    detector = cv2.QRCodeDetector()
    decoded_text, _, _ = detector.detectAndDecode(cv_image)
    return decoded_text.strip() if decoded_text else None


def _decode_with_pyzbar(image):
    try:
        from pyzbar.pyzbar import decode
    except ImportError:
        return None

    decoded_items = decode(image)
    if not decoded_items:
        return None

    return decoded_items[0].data.decode("utf-8", errors="replace").strip()


def decode_qr_image(file_storage):
    logger.info("QR image upload received: filename=%s", file_storage.filename)
    raw = file_storage.read()
    logger.info("QR image bytes read: %d", len(raw))
    image = Image.open(BytesIO(raw))

    decoded_url = _decode_with_opencv(image) or _decode_with_pyzbar(image)
    if not decoded_url:
        raise ValueError("No QR code URL could be decoded from the image")

    if not decoded_url.lower().startswith(("http://", "https://")):
        raise ValueError("Decoded QR content is not a URL")

    logger.info("QR decode complete: %s", decoded_url)
    return decoded_url


def analyze_qr_image(file_storage):
    decoded_url = decode_qr_image(file_storage)
    detection = ensemble_decision(decoded_url, use_html=True)
    reasons = [
        f"Decoded QR URL: {decoded_url}",
        *detection.get("reasons", []),
    ]

    return {
        "decoded_url": decoded_url,
        "prediction": detection.get("prediction"),
        "verdict": detection.get("verdict"),
        "risk_score": detection.get("risk_score"),
        "confidence": detection.get("confidence"),
        "explanation": reasons,
        "reasons": reasons,
        "details": detection.get("details", []),
    }
