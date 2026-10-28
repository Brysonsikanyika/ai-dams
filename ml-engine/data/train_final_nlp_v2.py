"""
Train the DEPLOYED v2 SQL-injection classifier and calibrate its alert cutoff.

Design B: character 2-5 n-gram TF-IDF + logistic regression (C=1, balanced class
weights), fitted on sqli_v2_train.csv only. This is the design that was
evaluated, so the deployed model is the evaluated model, not a refit on more
data. It has no custom code in its pickle, so any script can load it.

Why B: on the confirmation exam the design that scored best on attacks (F,
characters + masked tokens) flagged 18% of unfamiliar WikiSQL-style queries at
its calibrated cutoff, against 3.2% for B. The project's objective is low false
positives, so B was chosen on that criterion. The choice was made after seeing
that exam, so B's figures from it are slightly optimistic; the earlier first
test, scored before the choice, gave the same picture.

The CUTOFF is not a fixed 0.5 and is not taken from public data: a cutoff chosen
on public benchmarks did not transfer (it flagged 27-31% of the application's own
benign queries). It is set to the 99th percentile of the scores the model gives to
a baseline of the monitored application's own known-benign queries, i.e. a 1%
false-positive budget on that traffic.

Usage:
    python3 train_final_nlp_v2.py [DATA_DIR] [BASELINE_CSV]
BASELINE_CSV needs a query_text column of benign queries only (default:
sqli_v2_calib.csv, a separate draw of the academic catalogue). In operation this
should be replaced by queries captured during an attack-free baseline window.
"""

import datetime
import json
import sys
import warnings

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

warnings.filterwarnings("ignore")
FPR_TARGET = 0.01
D = sys.argv[1] if len(sys.argv) > 1 else "."
BASELINE = sys.argv[2] if len(sys.argv) > 2 else f"{D}/sqli_v2_calib.csv"
MODEL_OUT = f"{D}/nlp_classifier_v2_model.joblib"
CONFIG_OUT = f"{D}/nlp_classifier_v2_config.json"


def cutoff_for_fpr(benign_scores, fpr):
    """Lowest cutoff such that at most `fpr` of the benign scores lie above it."""
    s = np.sort(benign_scores)
    k = int(np.ceil((1 - fpr) * len(s))) - 1
    return float(s[min(max(k, 0), len(s) - 1)])


def main():
    tr = pd.read_csv(f"{D}/sqli_v2_train.csv")
    base = pd.read_csv(BASELINE)
    if "label" in base.columns and (base["label"] != 0).any():
        sys.exit("baseline file contains attack rows; the cutoff must be calibrated on benign queries only")

    model = Pipeline([
        ("features", TfidfVectorizer(analyzer="char", ngram_range=(2, 5), sublinear_tf=True,
                                     min_df=2, max_features=300000)),
        ("clf", LogisticRegression(C=1.0, class_weight="balanced", max_iter=3000)),
    ])
    model.fit(tr["query_text"], tr["label"])

    scores = model.predict_proba(base["query_text"])[:, 1]
    cutoff = cutoff_for_fpr(scores, FPR_TARGET)
    print(f"design: B char 2-5, C=1, fitted on {len(tr)} rows of sqli_v2_train.csv")
    print(f"baseline: {len(base)} benign queries from {BASELINE}")
    print("baseline score percentiles: " + ", ".join(f"p{q}={np.percentile(scores, q):.3f}" for q in (50, 90, 99, 100)))
    print(f"cutoff (score above which a query is flagged): {cutoff:.4f}  "
          f"-> {(scores > cutoff).mean():.2%} of the baseline would be flagged")

    joblib.dump(model, MODEL_OUT)
    json.dump({
        "design": "B char 2-5", "C": 1.0, "fitted_on": "sqli_v2_train.csv", "fitted_rows": int(len(tr)),
        "baseline_file": BASELINE.split("/")[-1], "baseline_rows": int(len(base)),
        "fpr_target": FPR_TARGET, "cutoff": cutoff,
        "sklearn_version": sklearn.__version__, "created": datetime.datetime.now().isoformat(timespec="seconds"),
    }, open(CONFIG_OUT, "w"), indent=1)
    print(f"saved {MODEL_OUT.split('/')[-1]} and {CONFIG_OUT.split('/')[-1]}")


if __name__ == "__main__":
    main()
