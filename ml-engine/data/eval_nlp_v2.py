"""Score the evaluated v2 classifier and the metadata-augmented v2m on the same exams."""
import json, joblib, pandas as pd
EXAMS = [("valid", "sqli_v2_valid.csv"), ("test", "sqli_v2_test.csv"), ("test2", "sqli_v2_test2.csv"), ("meta_heldout", "meta_heldout.csv")]
LIVE = ["select @@version_comment limit 1", "SHOW DATABASES", "SELECT DATABASE()", "show tables",
        "SELECT * FROM grades WHERE 1=1 OR 'a'='a' LIMIT 3",
        "SELECT * FROM grades WHERE 1=1 UNION SELECT id,id,id,id,id FROM grades --"]


def run(tag, d):
    model = joblib.load(f"{d}/nlp_classifier_v2_model.joblib")
    cut = json.load(open(f"{d}/nlp_classifier_v2_config.json"))["cutoff"]
    print(f"\n== {tag}   cutoff {cut:.4f}")
    for name, f in EXAMS:
        df = pd.read_csv(f)
        flag = pd.Series(model.predict_proba(df["query_text"])[:, 1] > cut, index=df.index)
        att, ben = df["label"] == 1, df["label"] == 0
        rec = f"{flag[att].mean():6.2%}" if att.any() else "   n/a"
        print(f"{name:13s} attacks {att.sum():5d} recall {rec} | benign {ben.sum():5d} flagged {flag[ben].sum():4d} ({flag[ben].mean():.2%})")
        if name == "meta_heldout":
            print("   flagged by family:", flag[ben].groupby(df.loc[ben, "source"]).sum().loc[lambda s: s > 0].to_dict())
    print("live-test statements:")
    for q, s in zip(LIVE, model.predict_proba(LIVE)[:, 1]):
        print(f"  {s:.3f} {'FLAG' if s > cut else 'ok  '} {q[:70]}")


run("v2 (evaluated model)", ".")
run("v2m (+ metadata benign, cutoff on app queries + metadata)", "v2m")
run("v2n (+ metadata in training only, cutoff on app queries)", "v2n")
