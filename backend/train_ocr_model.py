import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

try:
    from xgboost import XGBClassifier
except ImportError:
    XGBClassifier = None

try:
    import torch
    from transformers import AutoModel, AutoTokenizer
except ImportError:
    torch = None
    AutoModel = None
    AutoTokenizer = None


BASE_DIR = Path(__file__).resolve().parent
DATA_PATH = BASE_DIR / "data" / "phishing_text.csv"
MODEL_PATH = BASE_DIR / "models" / "ocr_model.pkl"
VECTORIZER_PATH = BASE_DIR / "models" / "ocr_vectorizer.pkl"
REPORT_PATH = BASE_DIR / "models" / "ocr_accuracy_report.json"
DISTILBERT_MODEL = "distilbert-base-uncased"


def normalize_labels(labels):
    label_map = {
        "phishing": 1,
        "bad": 1,
        "scam": 1,
        "malicious": 1,
        "safe": 0,
        "legit": 0,
        "good": 0,
        "benign": 0,
    }
    return labels.astype(str).str.lower().str.strip().map(label_map)


def tfidf_logistic_regression():
    return Pipeline(
        steps=[
            (
                "vectorizer",
                TfidfVectorizer(
                    stop_words="english",
                    max_features=5000,
                    ngram_range=(1, 2),
                ),
            ),
            (
                "classifier",
                LogisticRegression(
                    max_iter=1000,
                    class_weight="balanced",
                    random_state=42,
                ),
            ),
        ]
    )


def tfidf_xgboost():
    if XGBClassifier is None:
        return None

    return Pipeline(
        steps=[
            (
                "vectorizer",
                TfidfVectorizer(
                    stop_words="english",
                    max_features=5000,
                    ngram_range=(1, 2),
                ),
            ),
            (
                "classifier",
                XGBClassifier(
                    n_estimators=180,
                    max_depth=4,
                    learning_rate=0.08,
                    subsample=0.9,
                    colsample_bytree=0.9,
                    eval_metric="logloss",
                    random_state=42,
                    n_jobs=-1,
                ),
            ),
        ]
    )


def evaluate_predictions(name, y_test, y_pred):
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


def evaluate_pipeline(name, pipeline, X_train, X_test, y_train, y_test):
    pipeline.fit(X_train, y_train)
    y_pred = pipeline.predict(X_test)
    return evaluate_predictions(name, y_test, y_pred)


def mean_pool(last_hidden_state, attention_mask):
    mask = attention_mask.unsqueeze(-1).expand(last_hidden_state.size()).float()
    masked = last_hidden_state * mask
    return masked.sum(1) / mask.sum(1).clamp(min=1e-9)


def distilbert_embeddings(texts, tokenizer, model, device, batch_size=16):
    embeddings = []
    model.eval()
    with torch.no_grad():
        for start in range(0, len(texts), batch_size):
            batch = texts[start : start + batch_size]
            encoded = tokenizer(
                batch,
                padding=True,
                truncation=True,
                max_length=256,
                return_tensors="pt",
            )
            encoded = {key: value.to(device) for key, value in encoded.items()}
            output = model(**encoded)
            pooled = mean_pool(output.last_hidden_state, encoded["attention_mask"])
            embeddings.append(pooled.cpu().numpy())
    return np.vstack(embeddings)


def evaluate_distilbert(X_train, X_test, y_train, y_test):
    if torch is None or AutoTokenizer is None or AutoModel is None:
        return None, "transformers/torch is not installed"

    try:
        tokenizer = AutoTokenizer.from_pretrained(DISTILBERT_MODEL, local_files_only=True)
        model = AutoModel.from_pretrained(DISTILBERT_MODEL, local_files_only=True)
    except Exception as exc:
        return None, f"{DISTILBERT_MODEL} is not available in the local Hugging Face cache: {exc}"

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)
    X_train_emb = distilbert_embeddings(list(X_train), tokenizer, model, device)
    X_test_emb = distilbert_embeddings(list(X_test), tokenizer, model, device)

    classifier = LogisticRegression(
        max_iter=1000,
        class_weight="balanced",
        random_state=42,
    )
    classifier.fit(X_train_emb, y_train)
    y_pred = classifier.predict(X_test_emb)
    metrics = evaluate_predictions("DistilBERT", y_test, y_pred)
    return {
        "model": classifier,
        "tokenizer_name": DISTILBERT_MODEL,
        "encoder_name": DISTILBERT_MODEL,
        "metrics": metrics,
    }, None


def main():
    data = pd.read_csv(DATA_PATH)
    data["label"] = normalize_labels(data["label"])
    data = data.dropna(subset=["text", "label"])

    X = data["text"].astype(str)
    y = data["label"].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )

    candidates = {
        "TF-IDF + Logistic Regression": tfidf_logistic_regression(),
    }
    xgb_pipeline = tfidf_xgboost()
    if xgb_pipeline is not None:
        candidates["TF-IDF + XGBoost"] = xgb_pipeline
    else:
        print("Skipping TF-IDF + XGBoost: xgboost is not installed")

    results = {}
    fitted_models = {}
    skipped = {}

    for name, pipeline in candidates.items():
        metrics = evaluate_pipeline(name, pipeline, X_train, X_test, y_train, y_test)
        results[name] = metrics
        fitted_models[name] = {
            "model": pipeline,
            "model_type": "pipeline",
            "metrics": metrics,
        }

    distilbert_result, skip_reason = evaluate_distilbert(X_train, X_test, y_train, y_test)
    if distilbert_result is None:
        skipped["DistilBERT"] = skip_reason
        print(f"Skipping DistilBERT: {skip_reason}")
    else:
        results["DistilBERT"] = distilbert_result["metrics"]
        fitted_models["DistilBERT"] = {
            "model": distilbert_result["model"],
            "model_type": "distilbert_embeddings",
            "tokenizer_name": distilbert_result["tokenizer_name"],
            "encoder_name": distilbert_result["encoder_name"],
            "metrics": distilbert_result["metrics"],
        }

    if not results:
        raise RuntimeError("No OCR text detection models were available to evaluate")

    best_name = max(
        results,
        key=lambda name: (
            results[name]["f1_score"],
            results[name]["recall"],
            results[name]["precision"],
            results[name]["accuracy"],
        ),
    )
    best_bundle = fitted_models[best_name]

    report = {
        "task": "OCR Text Detection",
        "selection_metric_order": ["f1_score", "recall", "precision", "accuracy"],
        "best_model": best_name,
        "models": results,
        "skipped": skipped,
    }

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            **best_bundle,
            "model_name": best_name,
        },
        MODEL_PATH,
    )

    # Keep the legacy vectorizer path populated when the selected model is a TF-IDF pipeline.
    if best_bundle["model_type"] == "pipeline":
        vectorizer = best_bundle["model"].named_steps["vectorizer"]
        joblib.dump(vectorizer, VECTORIZER_PATH)

    REPORT_PATH.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(f"Best OCR model: {best_name}")
    print(f"Model saved at: {MODEL_PATH}")
    print(f"Accuracy report saved at: {REPORT_PATH}")


if __name__ == "__main__":
    main()
