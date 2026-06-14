import logging

import pytesseract
from PIL import Image, ImageOps


logger = logging.getLogger(__name__)


def extract_text_from_image(image_path: str):
    """
    Extract text from screenshot image using OCR
    """
    logger.info("OCR extraction started for %s", image_path)
    try:
        image = Image.open(image_path)
    except Exception:
        logger.exception("OCR image open failed for %s", image_path)
        return ""

    gray = ImageOps.grayscale(image)
    text = pytesseract.image_to_string(gray)
    logger.info("OCR extraction complete with %d characters", len(text or ""))
    return text.strip()
