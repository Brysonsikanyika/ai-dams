import pandas as pd
from housekeeping import is_housekeeping
print(f"{'file':22s} {'attack rows':>11s} {'attacks skipped':>16s} {'benign rows':>12s} {'benign skipped':>15s}")
for f in ["sqli_v2_valid.csv", "sqli_v2_test.csv", "sqli_v2_test2.csv", "sqli_v2_train.csv", "meta_heldout.csv"]:
    d = pd.read_csv(f); m = d["query_text"].map(is_housekeeping); a = d["label"] == 1
    print(f"{f:22s} {a.sum():11d} {m[a].sum():16d} {(~a).sum():12d} {m[~a].sum():15d}")
    if m[a].any(): print("   ATTACKS MATCHED:", d.loc[a & m, "query_text"].head(5).tolist())
for q in ["SHOW DATABASES; DROP TABLE grades", "SELECT DATABASE() -- x", "SELECT @@version UNION SELECT 1", "SHOW DATABASES", "select @@version_comment limit 1"]:
    print(is_housekeeping(q), q)
