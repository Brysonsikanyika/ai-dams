"""
AI-DAMS alert explanations (objective 3).

Reads risk_scores.csv (from build_risk_aggregator.py), picks every
(customer, 15-minute bucket) above the alert line, and writes alerts.json /
alerts.csv with a plain-English explanation for each one.

Two explanation paths, matching the two kinds of evidence:

1. BEHAVIOURAL alerts (Isolation Forest). SHAP TreeExplainer attributes the
   riskiest event's anomaly score to its input features. The top features are
   turned into a sentence ("12 statements at the same instant", "off-hours").
   This is a genuine SHAP explanation of the Isolation Forest only. The LSTM
   autoencoder is NOT explained: it has no SHAP path here, and alerts it alone
   raised say so.

2. SQL-TEXT alerts (injection classifier). The classifier is a linear model
   (char n-gram TF-IDF + logistic regression), so each n-gram's contribution
   is exactly tfidf_value * coefficient. We report the strongest n-grams and,
   separately, name readable SQL patterns found in the text (UNION SELECT,
   comment terminators, tautologies, ...). The pattern names are a rule-based
   LABEL for the analyst, not a statement about what the model internally
   used; the n-gram contributions are the faithful part.

Privacy: student numbers in the SQL shown to the analyst are masked, and
customer_id is replaced by a stable pseudonym (salted hash). The salt comes
from AIDAMS_PSEUDO_SALT; set it, or pseudonyms are reproducible by anyone who
reads this file.

Ground-truth labels are NEVER used to build an explanation. They are copied
into a separate `truth` field so the dashboard/evaluation can compare.

Usage:
    python3 explain_alerts.py [--threshold 0.90] [--max-alerts 500]
"""

import hashlib
import json
import os
import re
import sys

import joblib
import numpy as np
import pandas as pd
from behaviour_features import engineer, feature_columns, LSTM_NUMERIC
import shap
from sklearn.ensemble import IsolationForest

from train_isolation_forest import engineer_features as if_engineer_features

THRESHOLD = 0.90
MAX_ALERTS = 500
TIME_BUCKET = "15min"
MODEL_PATH = "nlp_classifier_v2_model.joblib"
CONFIG_PATH = "nlp_classifier_v2_config.json"
SALT = os.environ.get("AIDAMS_PSEUDO_SALT", "CHANGE-ME")

TAG_RE = re.compile(r"/\*\s*evt:[0-9a-f]{8}-\d+\s*\*/\s*")
STUDENT_RE = re.compile(r"\b23\d{5}\b")

# (label, regex, plain-English meaning). Labels for the analyst, not model internals.
PATTERNS = [
    ("UNION SELECT", r"\bunion\b.{0,20}\bselect\b", "appends a second query to pull data from another table"),
    ("comment terminator", r"(--\s|--$|#|/\*)", "uses a comment to cut off the rest of the original query"),
    ("always-true condition", r"\b(or|and)\b\s+['\"(]?\w+['\"]?\s*=\s*['\"]?\w+|\bor\b\s+1\b|\|\|\s*1", "makes the filter true for every row"),
    ("stacked statement", r";\s*\w+", "tries to run a second statement after the first"),
    ("schema probing", r"information_schema|sysobjects|pg_catalog|mysql\.user", "reads the database's own catalogue"),
    ("time delay", r"\b(sleep|benchmark|waitfor|pg_sleep)\b", "measures response time to infer hidden data"),
    ("ORDER BY probing", r"\border\s+by\s+\d{1,3}\b", "counts the columns of the query"),
    ("sub-query probe", r"\(\s*select\b", "embeds a query inside a condition"),
    ("error-based extraction", r"\b(extractvalue|updatexml|convert\(|cast\()", "forces an error message that leaks data"),
    ("function call", r"\b(user|version|database|current_user)\s*\(\s*\)", "asks the server who/what it is"),
]

FEATURE_WORDS = {
    "events_last_10s": lambda v: f"{int(v)} statements in the previous 10 seconds",
    "events_last_60s": lambda v: f"{int(v)} statements in the previous minute",
    "distinct_targets_last_60s": lambda v: f"it touched {int(v)} different student records within a minute",
    "distinct_tables_last_60s": lambda v: f"it spanned {int(v)} different tables within a minute",
    "events_last_hour": lambda v: f"{int(v)} statements in the previous hour",
    "distinct_tables_last_hour": lambda v: f"{int(v)} different tables in the previous hour",
    "is_night": lambda v: "the activity was outside normal hours" if v else "it ran during normal hours",
    "hour_of_day": lambda v: f"it ran at {int(v):02d}:00",
    "day_of_week": lambda v: "it ran on a " + ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"][int(v)],
}


def pseudonym(customer_id) -> str:
    return "S-" + hashlib.sha256(f"{SALT}:{customer_id}".encode()).hexdigest()[:8]


def clean_sql(text: str) -> str:
    return STUDENT_RE.sub("<student>", TAG_RE.sub("", str(text))).strip()


def describe_feature(name: str, value: float) -> str:
    if name in FEATURE_WORDS:
        return FEATURE_WORDS[name](value)
    if name.startswith("table_"):
        return f"it targeted the '{name[6:]}' table" if value else f"it did not touch '{name[6:]}'"
    if name.startswith("op_"):
        return f"the operation was {name[3:]}" if value else f"the operation was not {name[3:]}"
    return f"{name} = {value}"


def fit_isolation_forest(raw: pd.DataFrame):
    """Same model as build_risk_aggregator.run_isolation_forest (same seed/params)."""
    df = if_engineer_features(raw.copy())
    cols = feature_columns(df, tables=False)
    X = df[cols].fillna(0).astype(float)
    model = IsolationForest(n_estimators=200, contamination=0.11, random_state=42).fit(X)
    df["if_raw_score"] = -model.decision_function(X)
    # SHAP values of decision_function: negative = pushes toward "anomalous". Flip sign
    # so a positive attribution means "made this event look MORE anomalous".
    sv = -shap.TreeExplainer(model).shap_values(X)
    return df, X, cols, sv


def explain_behaviour(df, X, cols, sv, event_row) -> dict:
    i = event_row
    contrib = pd.Series(sv[i], index=cols)
    top = contrib.sort_values(ascending=False)
    top = top[top > 0].head(3)
    bits = [describe_feature(n, X.iloc[i][n]) for n in top.index]
    if not bits:
        return {"headline": "Unusual activity pattern", "explanation":
                "The Isolation Forest scored this activity as unusual, but no single feature stood out.",
                "top_features": []}
    return {
        "headline": "Unusual activity pattern",
        "explanation": "Flagged because " + "; ".join(bits) + ". These are the factors that pushed this "
                       "activity furthest from the normal baseline (SHAP attribution on the Isolation Forest).",
        "top_features": [{"feature": n, "value": float(X.iloc[i][n]), "shap": round(float(top[n]), 4)} for n in top.index],
    }


def explain_sql(pipe, cutoff, sql_text, prob) -> dict:
    text = TAG_RE.sub("", str(sql_text))
    vec, clf = pipe.named_steps["features"], pipe.named_steps["clf"]
    x = vec.transform([text])
    prob = float(prob)  # the score the pipeline actually alerted on (from nlp_scores.csv)
    contrib = x.multiply(clf.coef_[0]).tocsr()
    idx, vals = contrib.indices, contrib.data
    names = vec.get_feature_names_out()
    order = np.argsort(-vals)[:6]
    grams = [{"fragment": names[idx[j]], "contribution": round(float(vals[j]), 4)} for j in order if vals[j] > 0]
    found = [(lab, why) for lab, rx, why in PATTERNS if re.search(rx, text, re.I | re.S)]
    if found:
        what = "; ".join(f"{lab} ({why})" for lab, why in found[:3])
        body = f"The SQL text looks like an injection attempt: {what}."
    else:
        body = ("The SQL text scored above the injection cutoff, but no known attack pattern was "
                "recognised in it. Check it by hand: this is the typical shape of a false positive.")
    body += f" Classifier score {prob:.2f} against an alert cutoff of {cutoff:.2f}."
    return {"headline": "Possible SQL injection", "explanation": body,
            "patterns": [lab for lab, _ in found], "top_ngrams": grams, "nlp_prob": round(prob, 4)}


def main():
    threshold, max_alerts = THRESHOLD, MAX_ALERTS
    if "--threshold" in sys.argv:
        threshold = float(sys.argv[sys.argv.index("--threshold") + 1])
    if "--max-alerts" in sys.argv:
        max_alerts = int(sys.argv[sys.argv.index("--max-alerts") + 1])
    if SALT == "CHANGE-ME":
        print("WARNING: AIDAMS_PSEUDO_SALT not set; pseudonyms are guessable. Set it before sharing output.")

    raw = pd.read_csv("ground_truth.csv", parse_dates=["simulated_timestamp"])
    risk = pd.read_csv("risk_scores.csv", parse_dates=["time_bucket"])
    nlp = pd.read_csv("nlp_scores.csv", parse_dates=["simulated_timestamp"])
    pipe = joblib.load(MODEL_PATH)
    cutoff = float(json.load(open(CONFIG_PATH))["cutoff"])

    print("Fitting Isolation Forest and computing SHAP values...")
    df, X, cols, sv = fit_isolation_forest(raw)
    df["time_bucket"] = df["simulated_timestamp"].dt.floor(TIME_BUCKET)
    nlp["time_bucket"] = nlp["simulated_timestamp"].dt.floor(TIME_BUCKET)
    account = nlp.drop_duplicates("customer_id").set_index("customer_id")["account"].to_dict()

    alerts = risk[risk["combined_risk"] > threshold].sort_values("combined_risk", ascending=False).head(max_alerts)
    out = []
    for n, (_, a) in enumerate(alerts.iterrows(), 1):
        cust, tb = a["customer_id"], a["time_bucket"]
        from_text = a["nlp_risk"] >= a["behavioural_risk"]
        rec = {"alert_id": f"A{n:04d}", "time_bucket": str(tb), "pseudonym": pseudonym(cust),
               "account": account.get(cust, ""), "combined_risk": round(float(a["combined_risk"]), 4),
               "behavioural_risk": round(float(a["behavioural_risk"]), 4),
               "nlp_risk": round(float(a["nlp_risk"]), 4)}
        if from_text:
            sub = nlp[(nlp.customer_id == cust) & (nlp.time_bucket == tb)]
            row = sub.loc[sub["nlp_prob"].idxmax()]
            rec.update(explain_sql(pipe, cutoff, row["sql_text"], row["nlp_prob"]))
            rec["source"] = "sql_text"
            rec["sql"] = clean_sql(row["sql_text"])
        else:
            mask = (df.customer_id == cust) & (df.time_bucket == tb)
            i = df.loc[mask, "if_raw_score"].idxmax()
            rec.update(explain_behaviour(df, X, cols, sv, i))
            rec["source"] = "behaviour"
            if pd.notna(a.get("lstm_risk")) and a["lstm_risk"] > a["if_risk"]:
                rec["explanation"] += " (The LSTM scored this window higher than the Isolation Forest did; the LSTM has no SHAP explanation.)"
        rec["truth"] = {"bucket_has_anomaly": int(a.get("bucket_has_anomaly", 0)),
                        "bucket_has_injection": int(a.get("bucket_has_injection", 0)),
                        "bucket_has_burst": int(a.get("bucket_has_burst", 0))}
        out.append(rec)

    json.dump(out, open("alerts.json", "w"), indent=1, default=str)
    pd.json_normalize(out).to_csv("alerts.csv", index=False)
    by = pd.Series([r["source"] for r in out]).value_counts().to_dict()
    print(f"Wrote {len(out)} alerts to alerts.json / alerts.csv  {by}")
    for r in out[:3]:
        print(f"\n[{r['alert_id']}] risk {r['combined_risk']} {r['headline']}\n  {r['explanation']}")


if __name__ == "__main__":
    main()
