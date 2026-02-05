import pandas as pd
import re
import joblib
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score


# ---------------- URL FEATURE EXTRACTION ----------------
def extract_url_features(url: str):
    features = {}

    features["url_length"] = len(url)
    features["num_dots"] = url.count(".")
    features["num_hyphens"] = url.count("-")
    features["num_at"] = url.count("@")
    features["num_question"] = url.count("?")
    features["num_slash"] = url.count("/")
    features["num_digits"] = sum(c.isdigit() for c in url)

    # IP address presence
    features["has_ip"] = 1 if re.search(r"\d+\.\d+\.\d+\.\d+", url) else 0

    # HTTPS usage
    features["https"] = 1 if url.startswith("https") else 0

    parsed = urlparse(url)
    features["domain_length"] = len(parsed.netloc)

    return list(features.values())


# ---------------- LOAD DATASET ----------------
data = pd.read_csv("data/url_dataset.csv")

data["label"] = data["label"].str.lower().str.strip()

# Label mapping (FIXED)
label_map = {
    "phishing": 1,
    "bad": 1,
    "malicious": 1,
    "scam": 1,

    "safe": 0,
    "legit": 0,
    "good": 0,
    "benign": 0
}

data["label"] = data["label"].map(label_map)

# Remove invalid rows
data = data.dropna()

print("Label distribution:")
print(data["label"].value_counts())

# ---------------- FEATURES ----------------
X = data["url"].apply(extract_url_features).tolist()
y = data["label"]

# ---------------- TRAIN TEST SPLIT ----------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

# ---------------- TRAIN MODEL ----------------
model = LogisticRegression(max_iter=1000)
model.fit(X_train, y_train)

# ---------------- EVALUATE ----------------
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)

print(f"URL ML Accuracy: {accuracy:.2f}")

# ---------------- SAVE MODEL ----------------
joblib.dump(model, "models/url_ml_model.pkl")
print("Model saved at: models/url_ml_model.pkl")
