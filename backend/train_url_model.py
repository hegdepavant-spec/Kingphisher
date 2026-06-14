import json
import re
from pathlib import Path
from urllib.parse import urlparse

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split

try:
    from xgboost import XGBClassifier
except ImportError:
    XGBClassifier = None

try:
    from lightgbm import LGBMClassifier
except ImportError:
    LGBMClassifier = None


BASE_DIR = Path(__file__).resolve().parent
DATA_PATH = BASE_DIR / "data" / "url_dataset.csv"
MODEL_PATH = BASE_DIR / "models" / "url_ml_model.pkl"
REPORT_PATH = BASE_DIR / "models" / "url_accuracy_report.json"

FEATURE_NAMES = [
    "url_length",
    "num_dots",
    "num_hyphens",
    "num_at",
    "num_question",
    "num_slash",
    "num_digits",
    "has_ip",
    "https",
    "domain_length",
]


def extract_url_features(url: str):
    parsed = urlparse(url)
    values = {
        "url_length": len(url),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_at": url.count("@"),
        "num_question": url.count("?"),
        "num_slash": url.count("/"),
        "num_digits": sum(c.isdigit() for c in url),
        "has_ip": 1 if re.search(r"\d+\.\d+\.\d+\.\d+", url) else 0,
        "https": 1 if url.lower().startswith("https") else 0,
        "domain_length": len(parsed.netloc),
    }
    return [values[name] for name in FEATURE_NAMES]


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


def candidate_models():
    models = {
        "Random Forest": RandomForestClassifier(
            n_estimators=250,
            max_depth=None,
            min_samples_leaf=2,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        )
    }

    if XGBClassifier is not None:
        models["XGBoost"] = XGBClassifier(
            n_estimators=250,
            max_depth=6,
            learning_rate=0.08,
            subsample=0.9,
            colsample_bytree=0.9,
            eval_metric="logloss",
            random_state=42,
            n_jobs=-1,
        )
    else:
        print("Skipping XGBoost: xgboost is not installed")

    if LGBMClassifier is not None:
        models["LightGBM"] = LGBMClassifier(
            n_estimators=250,
            learning_rate=0.08,
            num_leaves=31,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
            verbose=-1,
        )
    else:
        print("Skipping LightGBM: lightgbm is not installed")

    return models


def evaluate_model(name, model, X_train, X_test, y_train, y_test):
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    metrics = {
        "accuracy": round(accuracy_score(y_test, y_pred), 4),
        "precision": round(precision_score(y_test, y_pred, zero_division=0), 4),
        "recall": round(recall_score(y_test, y_pred, zero_division=0), 4),
        "f1_score": round(f1_score(y_test, y_pred, zero_division=0), 4),
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
    }
    print(
        f"{name}: accuracy={metrics['accuracy']:.4f} "
        f"precision={metrics['precision']:.4f} "
        f"recall={metrics['recall']:.4f} f1={metrics['f1_score']:.4f}"
    )
    return metrics


def main():
    data = pd.read_csv(DATA_PATH)
    data["label"] = normalize_labels(data["label"])
    data = data.dropna(subset=["url", "label"])

    X = data["url"].astype(str).apply(extract_url_features).tolist()
    y = data["label"].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )

    results = {}
    fitted_models = {}
    for name, model in candidate_models().items():
        metrics = evaluate_model(name, model, X_train, X_test, y_train, y_test)
        results[name] = metrics
        fitted_models[name] = model

    if not results:
        raise RuntimeError("No URL detection models were available to evaluate")

    best_name = max(
        results,
        key=lambda name: (
            results[name]["f1_score"],
            results[name]["recall"],
            results[name]["precision"],
            results[name]["accuracy"],
        ),
    )
    best_model = fitted_models[best_name]

    report = {
        "task": "URL Detection",
        "selection_metric_order": ["f1_score", "recall", "precision", "accuracy"],
        "best_model": best_name,
        "models": results,
    }

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "model": best_model,
            "model_name": best_name,
            "feature_names": FEATURE_NAMES,
            "metrics": results[best_name],
        },
        MODEL_PATH,
    )
    REPORT_PATH.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(f"Best URL model: {best_name}")
    print(f"Model saved at: {MODEL_PATH}")
    print(f"Accuracy report saved at: {REPORT_PATH}")


if __name__ == "__main__":
    main()
