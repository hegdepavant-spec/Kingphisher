import argparse
import json
from pathlib import Path

import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split

from services.ensemble_service import ENSEMBLE_WEIGHTS, weighted_ensemble_score
from services.ocr_ml_service import predict_ocr_text
from services.url_ml_service import predict_url


BASE_DIR = Path(__file__).resolve().parent
URL_DATA_PATH = BASE_DIR / "data" / "url_dataset.csv"
OCR_DATA_PATH = BASE_DIR / "data" / "phishing_text.csv"
REPORT_PATH = BASE_DIR / "models" / "ensemble_accuracy_report.json"


def normalize_labels(labels):
    label_map = {
        "phishing": 1,
        "bad": 1,
        "malicious": 1,
        "scam": 1,
        "safe": 0,
        "legit": 0,
        "good": 0,
        "benign": 0,
    }
    return labels.astype(str).str.lower().str.strip().map(label_map)


def load_holdout(path, feature_column, sample_size, random_state=42):
    data = pd.read_csv(path)
    data["label"] = normalize_labels(data["label"])
    data = data.dropna(subset=[feature_column, "label"])
    _, holdout = train_test_split(
        data,
        test_size=0.2,
        random_state=random_state,
        stratify=data["label"].astype(int),
    )

    if sample_size and len(holdout) > sample_size:
        holdout = holdout.sample(n=sample_size, random_state=random_state)

    return holdout.reset_index(drop=True)


def main():
    parser = argparse.ArgumentParser(
        description="Evaluate the weighted URL/OCR/HTML ensemble on local holdout data."
    )
    parser.add_argument(
        "--sample-size",
        type=int,
        default=1000,
        help="Maximum paired holdout rows to score. Use 0 for all available pairs.",
    )
    parser.add_argument(
        "--html-score",
        type=float,
        default=0.5,
        help="Explainable HTML rule score to use when no labeled HTML benchmark is available.",
    )
    args = parser.parse_args()

    sample_size = args.sample_size or None
    url_holdout = load_holdout(URL_DATA_PATH, "url", sample_size)
    ocr_holdout = load_holdout(OCR_DATA_PATH, "text", sample_size)
    pair_count = min(len(url_holdout), len(ocr_holdout))

    y_true = []
    y_pred = []
    scored_samples = []

    for idx in range(pair_count):
        url_row = url_holdout.iloc[idx]
        ocr_row = ocr_holdout.iloc[idx]

        # Pair samples by shared label where possible; otherwise prefer the URL label because
        # phishing URLs are the primary user-facing scan target.
        label = int(url_row["label"])
        if label != int(ocr_row["label"]):
            continue

        url_result = predict_url(str(url_row["url"]))
        ocr_result = predict_ocr_text(str(ocr_row["text"]))
        final_score = weighted_ensemble_score(
            url_result["risk_score"],
            ocr_result["risk_score"],
            args.html_score,
        )
        predicted_label = 1 if final_score >= 0.5 else 0

        y_true.append(label)
        y_pred.append(predicted_label)
        scored_samples.append(
            {
                "url_score": url_result["risk_score"],
                "ocr_score": ocr_result["risk_score"],
                "html_score": args.html_score,
                "ensemble_score": round(final_score, 4),
                "actual": label,
                "predicted": predicted_label,
            }
        )

    if not y_true:
        raise RuntimeError("No same-label URL/OCR holdout pairs were available for ensemble evaluation")

    report = {
        "task": "Weighted Ensemble",
        "weights": ENSEMBLE_WEIGHTS,
        "html_analysis": "Explainable rule-based scoring; offline benchmark uses supplied html_score.",
        "html_score_source": "neutral fallback" if args.html_score == 0.5 else "command line",
        "positive_threshold": 0.5,
        "sample_count": len(y_true),
        "metrics": {
            "accuracy": round(accuracy_score(y_true, y_pred), 4),
            "precision": round(precision_score(y_true, y_pred, zero_division=0), 4),
            "recall": round(recall_score(y_true, y_pred, zero_division=0), 4),
            "f1_score": round(f1_score(y_true, y_pred, zero_division=0), 4),
            "confusion_matrix": confusion_matrix(y_true, y_pred).tolist(),
        },
        "sample_predictions": scored_samples[:25],
    }

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(json.dumps(report, indent=2), encoding="utf-8")

    metrics = report["metrics"]
    print(
        "Weighted Ensemble: "
        f"accuracy={metrics['accuracy']:.4f} "
        f"precision={metrics['precision']:.4f} "
        f"recall={metrics['recall']:.4f} "
        f"f1={metrics['f1_score']:.4f}"
    )
    print(f"Confusion matrix: {metrics['confusion_matrix']}")
    print(f"Accuracy report saved at: {REPORT_PATH}")


if __name__ == "__main__":
    main()
