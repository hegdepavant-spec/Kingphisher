# KingPhisher

KingPhisher is a phishing detection platform that combines URL machine learning, OCR text analysis, HTML inspection, QR decoding, and ensemble scoring into a production-style cybersecurity dashboard.

The project includes:

- Flask backend API for URL, OCR, QR, HTML, and ensemble detection
- React + Vite frontend dashboard with scanner pages and analytics
- Chrome browser extension for real-time page checks
- Training and evaluation scripts for URL, OCR, and ensemble models

## Features

- Modern dark cybersecurity dashboard
- URL Scanner for direct destination analysis
- OCR Scanner for phishing text extracted from screenshots
- QR Scanner for decoding and analyzing embedded URLs
- HTML Analyzer for page structure, form, script, and redirect signals
- Ensemble detector that combines multiple signals into a final score
- Detection history, analytics, risk badges, score visualizations, loading states, and toast notifications
- Browser extension integration for live browsing protection

## Project Structure

```text
kingphisher/
  backend/
    app.py
    requirements.txt
    train_url_model.py
    train_ocr_model.py
    evaluate_ensemble.py
    test_workflows.py
    data/
    models/
    services/
  frontend/
    kingphisher-ui/
      src/
      package.json
  kingphisher-extension/
    manifest.json
    background.js
    content.js
    popup.html
    popup.js
```

## Requirements

- Python 3.10+
- Node.js 18+
- npm
- Tesseract OCR installed on the system for OCR image scanning

Python packages are listed in `backend/requirements.txt`.

## Backend Setup

From the repository root:

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

The backend runs at:

```text
http://127.0.0.1:5000
```

## Frontend Setup

Open a second terminal:

```bash
cd frontend/kingphisher-ui
npm install
npm run dev
```

The frontend runs at:

```text
http://127.0.0.1:5173
```

## Browser Extension Setup

1. Open Chrome and go to `chrome://extensions`.
2. Enable Developer mode.
3. Click Load unpacked.
4. Select the `kingphisher-extension` folder.
5. Keep the backend running at `http://127.0.0.1:5000`.

## API Endpoints

### URL Detection

```http
POST /api/url
Content-Type: application/json

{
  "url": "https://example.com/login"
}
```

Also available as:

```http
POST /predict
```

### OCR Detection

```http
POST /api/ocr
Content-Type: multipart/form-data

image=<screenshot file>
```

Response includes extracted text:

```json
{
  "prediction": "Suspicious",
  "confidence": 82,
  "risk_score": 0.62,
  "reasons": ["Suspicious urgency language detected"],
  "extracted_text": "..."
}
```

### QR Detection

```http
POST /api/qr
Content-Type: multipart/form-data

image=<qr image file>
```

### HTML Analysis

```http
POST /api/html
Content-Type: application/json

{
  "url": "https://example.com/login"
}
```

### Manual URL Scan

```http
POST /api/ensemble
Content-Type: application/json

{
  "url": "https://example.com/login"
}
```

Manual URL scans run URL ML, fetch the webpage source, run HTML analysis, and combine URL + HTML scores. OCR is not run because no screenshot is available. If HTML fetching fails, the response falls back to URL ML only and includes the failure reason.

```json
{
  "prediction": "Phishing",
  "confidence": 95,
  "risk_score": 0.84,
  "url_score": 90,
  "html_score": 97,
  "ocr_score": null,
  "reasons": ["High URL risk", "Suspicious HTML indicators"],
  "details": [
    {
      "module": "URL ML",
      "result": {
        "prediction": "Phishing",
        "risk_score": 0.88,
        "reasons": []
      }
    }
  ]
}
```

### Chrome Extension Scan

```http
POST /api/ensemble
Content-Type: multipart/form-data

url=https://example.com/login
image=<webpage screenshot>
source=extension
```

Chrome extension scans run URL ML and OCR only. HTML analysis is not run in this mode. If OCR extraction or OCR ML scoring fails, the response falls back to URL ML only and includes the failure reason.

### Accuracy Reports

```http
GET /api/reports
```

Returns available URL, OCR, and ensemble evaluation reports from `backend/models`.

## Training and Evaluation

Train the URL model:

```bash
cd backend
python train_url_model.py
```

Train the OCR model:

```bash
cd backend
python train_ocr_model.py
```

Evaluate ensemble performance:

```bash
cd backend
python evaluate_ensemble.py
```

## Testing

Run backend workflow tests:

```bash
cd backend
python test_workflows.py
```

Run frontend checks:

```bash
cd frontend/kingphisher-ui
npm run lint
npm run build
```

## Detection Result Fields

The frontend expects these common fields:

- `prediction`: `Safe`, `Suspicious`, `Phishing`, or `Invalid`
- `confidence`: model confidence percentage
- `risk_score`: numeric score from `0.0` to `1.0`
- `reasons`: explainable detection reasons
- `details`: module-level results for ensemble scans
- `extracted_text`: OCR text, when available
- `decoded_url`: QR decoded URL, when available

## Troubleshooting

If OCR fails, confirm Tesseract is installed and available on your system path.

If QR scanning fails, verify that `opencv-python` and `pyzbar` are installed and that the uploaded image contains a clear QR code.

If the frontend cannot scan, make sure the Flask backend is running at `http://127.0.0.1:5000`.

If model files are missing, run the training scripts to regenerate the `.pkl` files in `backend/models`.
