"""
AI-DAMS NLP SQL-injection classifier.

Reads sqli_corpus.csv (from generate_sqli_corpus.py) and trains a text
classifier to distinguish benign queries from injection payloads.

Unlike the Isolation Forest, this IS a supervised task -- labels are
legitimate training signal here, not just an evaluation-only check.
There's no "real deployment won't have labels" caveat for this model,
because query text with a known benign/malicious label is exactly the
kind of curated training set this task expects.

Uses TF-IDF over CHARACTER n-grams (not word-level) deliberately -- SQL
injection syntax lives in punctuation and symbol sequences (quotes,
semicolons, comment markers like -- and #, operators like =) far more
than in "words" in the natural-language sense. Character n-grams capture
that; word-level tokenization would treat "OR" the same whether it's in
a legitimate WHERE clause or a tautology attack, throwing away the
structural signal that actually distinguishes them.
"""

import pandas as pd
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

INPUT_PATH = "sqli_corpus.csv"
MODEL_PATH = "nlp_classifier_model.joblib"
VECTORIZER_PATH = "nlp_classifier_vectorizer.joblib"


def main():
    df = pd.read_csv(INPUT_PATH)
    print(f"Loaded {len(df)} rows: {df['label'].sum()} malicious, {(df['label'] == 0).sum()} benign")

    X_train, X_test, y_train, y_test, cat_train, cat_test = train_test_split(
        df["query_text"],
        df["label"],
        df["category"],
        test_size=0.2,
        random_state=42,
        stratify=df["label"],
    )
    print(f"Train: {len(X_train)} rows, Test: {len(X_test)} rows")

    vectorizer = TfidfVectorizer(analyzer="char", ngram_range=(2, 4), min_df=2)
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    model = LogisticRegression(max_iter=1000, random_state=42)
    model.fit(X_train_vec, y_train)

    y_pred = model.predict(X_test_vec)

    print("\n--- Evaluation on held-out test set ---")
    print(confusion_matrix(y_test, y_pred))
    print(classification_report(y_test, y_pred, target_names=["benign", "malicious"]))

    print("\n--- Recall by attack category (test set only) ---")
    results = pd.DataFrame({"category": cat_test.values, "true": y_test.values, "pred": y_pred})
    malicious_results = results[results["true"] == 1]
    breakdown = (
        malicious_results.groupby("category")["pred"]
        .agg(["sum", "count"])
        .rename(columns={"sum": "caught", "count": "total"})
    )
    breakdown["recall"] = (breakdown["caught"] / breakdown["total"]).round(3)
    print(breakdown)

    feature_names = vectorizer.get_feature_names_out()
    coefs = model.coef_[0]
    top_malicious_idx = coefs.argsort()[-15:][::-1]
    top_benign_idx = coefs.argsort()[:15]

    print("\n--- Top n-grams pushing toward MALICIOUS ---")
    for i in top_malicious_idx:
        print(f"  {feature_names[i]!r}: {coefs[i]:.3f}")

    print("\n--- Top n-grams pushing toward BENIGN ---")
    for i in top_benign_idx:
        print(f"  {feature_names[i]!r}: {coefs[i]:.3f}")

    joblib.dump(model, MODEL_PATH)
    joblib.dump(vectorizer, VECTORIZER_PATH)
    print(f"\nSaved model to {MODEL_PATH} and vectorizer to {VECTORIZER_PATH}")


if __name__ == "__main__":
    main()