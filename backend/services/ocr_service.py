import logging
from io import BytesIO

import pytesseract
from PIL import Image, ImageOps


logger = logging.getLogger(__name__)


def _extract_text(image):
    gray = ImageOps.grayscale(image)
    text = pytesseract.image_to_string(gray)
    logger.info("OCR extraction complete with %d characters", len(text or ""))
    return text.strip()


def extract_text_from_image(image_path: str):
    """
    Extract text from screenshot image using OCR.
    """
    logger.info("OCR extraction started for %s", image_path)
    image = Image.open(image_path)
    return _extract_text(image)


def extract_text_from_upload(file_storage):
    """
    Extract text from an uploaded screenshot image using Tesseract OCR.
    """
    logger.info("OCR image upload received: filename=%s", file_storage.filename)
    raw = file_storage.read()
    logger.info("OCR image bytes read: %d", len(raw))
    image = Image.open(BytesIO(raw))
    return _extract_text(image)
