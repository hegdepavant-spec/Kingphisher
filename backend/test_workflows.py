import io
import sys
import types

from PIL import Image

import app
import services.html_analyzer as html_analyzer


OCR_TEXT = (
    "verify your account login immediately confirm password "
    "security alert update your account"
)


class FakeHtmlResponse:
    text = """
    <html>
      <body>
        verify your account security alert
        <form action="https://evil.test/login">
          <input type="password" />
        </form>
        <a href="https://other.test">external</a>
      </body>
    </html>
    """

    def raise_for_status(self):
        return None


def fake_get(*args, **kwargs):
    return FakeHtmlResponse()


def make_image_upload():
    image = Image.new("RGB", (240, 80), "white")
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    buffer.seek(0)
    return buffer


def main():
    html_analyzer.requests.get = fake_get
    app.pytesseract = types.SimpleNamespace(image_to_string=lambda image: OCR_TEXT)
    client = app.app.test_client()

    url_response = client.post("/api/url", json={"url": "https://example.com/login"})
    assert url_response.status_code == 200, url_response.get_data(as_text=True)
    url_data = url_response.get_json()
    assert "prediction" in url_data
    assert "risk_score" in url_data
    assert "confidence" in url_data
    assert "features" in url_data
    print("URL workflow:", url_data)

    image_buffer = make_image_upload()
    ocr_response = client.post(
        "/api/ocr",
        data={"image": (image_buffer, "scan.png")},
        content_type="multipart/form-data",
    )
    assert ocr_response.status_code == 200, ocr_response.get_data(as_text=True)
    ocr_data = ocr_response.get_json()
    assert ocr_data["extracted_text"] == OCR_TEXT
    assert "prediction" in ocr_data
    assert "risk_score" in ocr_data
    print("OCR workflow:", ocr_data)

    html_response = client.post("/api/html", json={"url": "https://example.com/login"})
    assert html_response.status_code == 200, html_response.get_data(as_text=True)
    html_data = html_response.get_json()
    assert html_data["risk_score"] > 0
    assert "prediction" in html_data
    print("HTML workflow:", html_data)

    ensemble_response = client.post(
        "/api/ensemble",
        json={
            "url": "https://example.com/login",
            "ocr_text": OCR_TEXT,
            "use_html": True,
        },
    )
    assert ensemble_response.status_code == 200, ensemble_response.get_data(as_text=True)
    ensemble_data = ensemble_response.get_json()
    assert len(ensemble_data["details"]) == 3
    assert "prediction" in ensemble_data
    assert "risk_score" in ensemble_data
    print("Ensemble workflow:", ensemble_data)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
