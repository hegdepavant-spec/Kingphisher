import pytesseract
import cv2


def extract_text_from_image(image_path: str):
    """
    Extract text from screenshot image using OCR
    """
    image = cv2.imread(image_path)

    if image is None:
        return ""

    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)

    # Improve OCR accuracy
    gray = cv2.threshold(
        gray, 150, 255, cv2.THRESH_BINARY | cv2.THRESH_OTSU
    )[1]

    text = pytesseract.image_to_string(gray)
    return text.strip()
