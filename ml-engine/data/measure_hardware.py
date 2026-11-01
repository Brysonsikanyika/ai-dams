"""
AI-DAMS hardware measurement (objective 2: "within ZUT hardware limits").

Measures, on THIS machine, what each component costs: training time, peak
memory, and the time to score one event. Each stage runs in its own process so
peak memory is per stage and not a running maximum. Results go to
hardware_report.json and a summary table.

    python3 measure_hardware.py                 # all stages
    python3 measure_hardware.py --threads 2     # limit CPU threads (approximates a smaller server)
    python3 measure_hardware.py --stage nlp     # one stage

What this does and does not show:
  * It measures this machine. Whether that is "within ZUT's limits" depends on
    ZUT's real server specification, which you must state and compare against.
  * Peak memory is the stage process's own peak (VmHWM). baseline_rss_mb is the peak after imports
    and data loading (TensorFlow alone is several hundred MB); if peak_rss_mb is
    close to it, training itself added little.
  * Single-event latencies exclude the trailing-window feature calculation,
    which is measured separately in stage 'features' (per event).
  * Training times are for the synthetic 5000-event dataset. Real traffic would
    be larger; training time scales with data, so these are lower bounds.
"""

import argparse
import json
import os
import platform
import re
import resource
import statistics
import subprocess
import sys
import time

STAGES = ["features", "if", "lstm", "nlp", "shap", "docker"]
TAG_RE = re.compile(r"/\*\s*evt:[0-9a-f]{8}-\d+\s*\*/\s*")


def rss_mb():
    """Peak resident memory of THIS process in MB.

    Reads VmHWM from /proc/self/status. resource.getrusage(...).ru_maxrss is NOT
    used: Linux carries the parent's peak across exec(), so every stage would
    report the parent's memory (it had imported TensorFlow) as its own.
    """
    try:
        for line in open("/proc/self/status"):
            if line.startswith("VmHWM:"):
                return int(line.split()[1]) / 1024.0
    except OSError:
        pass
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0


def pct(values, q):
    values = sorted(values)
    return values[min(int(q * len(values)), len(values) - 1)]


def lat(fn, n):
    times = []
    for _ in range(n):
        t = time.perf_counter()
        fn()
        times.append((time.perf_counter() - t) * 1000)
    return {"median_ms": round(statistics.median(times), 3), "p95_ms": round(pct(times, 0.95), 3), "n": n}


def system_info():
    info = {"python": platform.python_version(), "platform": platform.platform(), "cpu_count": os.cpu_count()}
    try:
        for line in open("/proc/cpuinfo"):
            if line.startswith("model name"):
                info["cpu_model"] = line.split(":", 1)[1].strip()
                break
        for line in open("/proc/meminfo"):
            if line.startswith("MemTotal"):
                info["ram_gb"] = round(int(line.split()[1]) / 1024 / 1024, 1)
                break
    except OSError:
        pass
    from importlib import metadata  # versions without importing the packages (imports inflate memory)
    for mod, pkg in (("numpy", "numpy"), ("pandas", "pandas"), ("sklearn", "scikit-learn"),
                     ("tensorflow", "tensorflow"), ("shap", "shap")):
        try:
            info[mod] = metadata.version(pkg)
        except Exception:
            info[mod] = "not installed"
    return info


# ----------------------------- stages -----------------------------
def stage_features():
    import pandas as pd
    from behaviour_features import engineer
    raw = pd.read_csv("ground_truth.csv", parse_dates=["simulated_timestamp"])
    base = rss_mb()
    t = time.perf_counter()
    engineer(raw, tables=False)
    s = time.perf_counter() - t
    return {"events": len(raw), "feature_time_s": round(s, 3), "per_event_ms": round(s / len(raw) * 1000, 4),
            "baseline_rss_mb": round(base), "peak_rss_mb": round(rss_mb())}


def stage_if():
    import pandas as pd
    from sklearn.ensemble import IsolationForest
    from behaviour_features import engineer, feature_columns
    raw = pd.read_csv("ground_truth.csv", parse_dates=["simulated_timestamp"])
    df = engineer(raw, tables=False)
    X = df[feature_columns(df, tables=False)].fillna(0).astype(float)
    base = rss_mb()
    t = time.perf_counter()
    model = IsolationForest(n_estimators=200, contamination=0.11, random_state=42).fit(X)
    train = time.perf_counter() - t
    t = time.perf_counter()
    model.decision_function(X)
    batch = time.perf_counter() - t
    i = [0]

    def one():
        i[0] = (i[0] + 1) % len(X)
        model.decision_function(X.iloc[i[0]:i[0] + 1])
    return {"train_rows": len(X), "train_s": round(train, 2), "batch_score_s": round(batch, 3),
            "events_per_s_batch": round(len(X) / batch), "single_event": lat(one, 300),
            "baseline_rss_mb": round(base), "peak_rss_mb": round(rss_mb())}


def stage_lstm():
    import numpy as np
    import pandas as pd
    from sklearn.preprocessing import StandardScaler
    base_before = rss_mb()
    from train_lstm_autoencoder import engineer_features, build_windows, build_autoencoder, WINDOW_SIZE
    from behaviour_features import feature_columns, LSTM_NUMERIC
    raw = pd.read_csv("ground_truth.csv", parse_dates=["simulated_timestamp"])
    df = engineer_features(raw)
    cols = feature_columns(df, tables=True)
    df[list(LSTM_NUMERIC)] = StandardScaler().fit_transform(df[list(LSTM_NUMERIC)])
    X, y, _t, _c, _e = build_windows(df, cols, WINDOW_SIZE)
    Xn = X[y == 0]
    Xtr = Xn[:int(len(Xn) * 0.8)]
    base = rss_mb()
    model = build_autoencoder(WINDOW_SIZE, X.shape[2])
    t = time.perf_counter()
    model.fit(Xtr, Xtr, epochs=20, batch_size=32, validation_split=0.1, verbose=0)
    train = time.perf_counter() - t
    t = time.perf_counter()
    model.predict(X, verbose=0)
    batch = time.perf_counter() - t
    j = [0]

    def one():
        j[0] = (j[0] + 1) % len(X)
        model(X[j[0]:j[0] + 1], training=False)
    one()  # warm up graph
    import tempfile
    path = os.path.join(tempfile.mkdtemp(), "lstm.keras")
    model.save(path)
    return {"train_windows": len(Xtr), "epochs": 20, "train_s": round(train, 1), "batch_score_s": round(batch, 2),
            "windows_per_s_batch": round(len(X) / batch), "single_window": lat(one, 200),
            "model_file_mb": round(os.path.getsize(path) / 1024 / 1024, 2),
            "baseline_rss_mb": round(base), "import_rss_mb": round(base_before), "peak_rss_mb": round(rss_mb())}


def stage_nlp():
    import joblib
    import pandas as pd
    t = time.perf_counter()
    pipe = joblib.load("nlp_classifier_v2_model.joblib")
    load = time.perf_counter() - t
    nlp = pd.read_csv("nlp_scores.csv")
    texts = [TAG_RE.sub("", s) for s in nlp["sql_text"].astype(str)]
    base = rss_mb()
    t = time.perf_counter()
    pipe.predict_proba(texts)
    batch = time.perf_counter() - t
    k = [0]

    def one():
        k[0] = (k[0] + 1) % len(texts)
        pipe.predict_proba([texts[k[0]]])
    out = {"model_file_mb": round(os.path.getsize("nlp_classifier_v2_model.joblib") / 1024 / 1024, 2),
           "load_s": round(load, 2), "batch_score_s": round(batch, 2),
           "queries_per_s_batch": round(len(texts) / batch), "single_query": lat(one, 500),
           "baseline_rss_mb": round(base), "peak_rss_mb": round(rss_mb())}
    train_csv = "sqli_v2_train.csv"
    if os.path.exists(train_csv):
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression
        from sklearn.pipeline import Pipeline
        tr = pd.read_csv(train_csv)
        m = Pipeline([("features", TfidfVectorizer(analyzer="char", ngram_range=(2, 5), sublinear_tf=True,
                                                   min_df=2, max_features=300000)),
                      ("clf", LogisticRegression(C=1.0, class_weight="balanced", max_iter=3000))])
        t = time.perf_counter()
        m.fit(tr["query_text"], tr["label"])
        out["train_rows"] = len(tr)
        out["train_s"] = round(time.perf_counter() - t, 1)
        out["peak_rss_mb"] = round(rss_mb())
    else:
        out["train_s"] = "sqli_v2_train.csv not found; run build_sqli_dataset.py first"
    return out


def stage_shap():
    import numpy as np
    import pandas as pd
    import shap
    from sklearn.ensemble import IsolationForest
    from behaviour_features import engineer, feature_columns
    raw = pd.read_csv("ground_truth.csv", parse_dates=["simulated_timestamp"])
    df = engineer(raw, tables=False)
    X = df[feature_columns(df, tables=False)].fillna(0).astype(float)
    model = IsolationForest(n_estimators=200, contamination=0.11, random_state=42).fit(X)
    base = rss_mb()
    t = time.perf_counter()
    ex = shap.TreeExplainer(model)
    build = time.perf_counter() - t
    m = [0]

    def one():
        m[0] = (m[0] + 7) % len(X)
        ex.shap_values(X.iloc[m[0]:m[0] + 1])
    return {"explainer_build_s": round(build, 2), "per_alert_explanation": lat(one, 100),
            "baseline_rss_mb": round(base), "peak_rss_mb": round(rss_mb())}


def stage_docker():
    try:
        out = subprocess.run(["docker", "stats", "--no-stream", "--format",
                              "{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}"], capture_output=True, text=True, timeout=60)
        rows = [r.split("|") for r in out.stdout.strip().splitlines() if r.startswith("aidams")]
        return {"containers": [{"name": r[0], "cpu": r[1], "mem": r[2]} for r in rows]}
    except Exception as e:
        return {"error": str(e)}


FUNCS = {"features": stage_features, "if": stage_if, "lstm": stage_lstm, "nlp": stage_nlp,
         "shap": stage_shap, "docker": stage_docker}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stage", choices=STAGES)
    ap.add_argument("--threads", type=int, default=0, help="limit CPU threads (0 = no limit)")
    ap.add_argument("--child", action="store_true")
    a = ap.parse_args()
    if a.threads:
        for v in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS",
                  "TF_NUM_INTRAOP_THREADS", "TF_NUM_INTEROP_THREADS"):
            os.environ[v] = str(a.threads)
    if a.child:
        print("RESULT " + json.dumps(FUNCS[a.stage]()))
        return
    report = {"system": system_info(), "threads_limit": a.threads or "none", "stages": {}}
    print(json.dumps(report["system"], indent=1))
    for st in ([a.stage] if a.stage else STAGES):
        print(f"\n== {st} ==", flush=True)
        cmd = [sys.executable, __file__, "--child", "--stage", st] + (["--threads", str(a.threads)] if a.threads else [])
        p = subprocess.run(cmd, capture_output=True, text=True)
        line = next((l for l in p.stdout.splitlines() if l.startswith("RESULT ")), None)
        if line is None:
            tail = (p.stderr or p.stdout).strip().splitlines()[-3:]
            report["stages"][st] = {"error": " | ".join(tail)}
            print("FAILED:", report["stages"][st]["error"])
            continue
        report["stages"][st] = json.loads(line[7:])
        print(json.dumps(report["stages"][st]))
    json.dump(report, open("hardware_report.json", "w"), indent=1)
    print("\nSaved hardware_report.json")


if __name__ == "__main__":
    main()
