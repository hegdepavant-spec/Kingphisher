import pandas as pd
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score


# ---------------- LOAD DATA ----------------
data = pd.read_csv("data/phishing_text.csv")

# Normalize labels
data["label"] = data["label"].str.lower()

label_map = {
    "phishing": 1,
    "bad": 1,
    "scam": 1,
    "malicious": 1,

    "safe": 0,
    "legit": 0,
    "good": 0,
    "benign": 0
}


data["label"] = data["label"].map(label_map)
data = data.dropna()

X = data["text"]
y = data["label"]

# ---------------- TEXT VECTORIZATION ----------------
vectorizer = TfidfVectorizer(
    stop_words="english",
    max_features=5000
)

X_vec = vectorizer.fit_transform(X)

# ---------------- TRAIN / TEST SPLIT ----------------
X_train, X_test, y_train, y_test = train_test_split(
    X_vec, y, test_size=0.2, random_state=42
)

# ---------------- TRAIN MODEL ----------------
model = LogisticRegression(max_iter=1000)
model.fit(X_train, y_train)

# ---------------- EVALUATE ----------------
y_pred = model.predict(X_test)
acc = accuracy_score(y_test, y_pred)

print(f"OCR NLP Accuracy: {acc:.2f}")

# ---------------- SAVE MODEL ----------------
joblib.dump(model, "models/ocr_text_model.pkl")
joblib.dump(vectorizer, "models/ocr_vectorizer.pkl")

print("OCR NLP model & vectorizer saved")
