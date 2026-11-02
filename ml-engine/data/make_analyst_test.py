"""
Build a small analyst test from alerts.json: 6 alerts (3 behaviour, 2 SQL text, 1 LSTM-led),
with real problems and false alarms mixed. Writes analyst_test_handout.html (what a participant
sees: no ground truth) and analyst_test_key.json (the answers). Fixed seed, so it is repeatable.
"""
import html, json, random
random.seed(7)
A = json.load(open("alerts.json"))
real = lambda r: int(r["truth"]["bucket_has_anomaly"]) == 1
lstm = [r for r in A if r["source"] == "behaviour" and "lstm_top_features" in r]
beh = [r for r in A if r["source"] == "behaviour" and "lstm_top_features" not in r]
sql = [r for r in A if r["source"] == "sql_text"]
pick = []
def take(pool, n_real, n_fake):
    r_, f_ = [r for r in pool if real(r)], [r for r in pool if not real(r)]
    random.shuffle(r_); random.shuffle(f_)
    pick.extend(r_[:n_real] + f_[:n_fake])
take(beh, 2, 1); take(sql, 1, 1); take(lstm, 1, 0)
random.shuffle(pick)
print(f"{len(pick)} alerts picked; real: {sum(real(r) for r in pick)}, false alarms: {sum(not real(r) for r in pick)}")

key = {r["alert_id"]: {"source": r["source"], "lstm_led": "lstm_top_features" in r, "real_problem": int(real(r))} for r in pick}
json.dump(key, open("analyst_test_key.json", "w"), indent=1)

e = html.escape
css = "body{font-family:Georgia,serif;max-width:720px;margin:2em auto;line-height:1.5} .card{page-break-after:always;border:1px solid #888;padding:1em 1.4em;margin-bottom:2em} pre{background:#f1f1f1;padding:.6em;white-space:pre-wrap} td{padding:.3em .8em} .f{border-bottom:1px solid #000;display:inline-block;width:14em}"
out = [f"<html><head><meta charset='utf-8'><title>AI-DAMS analyst test</title><style>{css}</style></head><body>",
       "<h1>AI-DAMS alert review</h1><p>You will see six alerts raised by a database monitoring tool, each with the tool's explanation. All data is synthetic. For each alert, decide whether it is a real problem, what you would do, and how clear the explanation was. Some alerts are false alarms. There are no trick questions and you are not being tested; the explanations are.</p>",
       "<p>Name or code: <span class='f'></span> &nbsp; Role/background: <span class='f'></span></p><p>Time started: <span class='f'></span> Time finished: <span class='f'></span></p><div style='page-break-after:always'></div>"]
for n, r in enumerate(pick, 1):
    out.append(f"<div class='card'><h2>Alert {n} of {len(pick)} (ID {e(r['alert_id'])})</h2>"
               f"<table><tr><td>Window</td><td>{e(r['time_bucket'])}</td></tr><tr><td>Student</td><td>{e(r['pseudonym'])}</td></tr>"
               f"<tr><td>Risk score</td><td>{r['combined_risk']}</td></tr><tr><td>Headline</td><td>{e(r['headline'])}</td></tr></table>"
               f"<p><b>Explanation shown to the analyst:</b> {e(r['explanation'])}</p>")
    if r.get("sql"):
        out.append(f"<p><b>SQL:</b></p><pre>{e(r['sql'])}</pre>")
    out.append("<ol><li>Is this a real problem? &nbsp; Yes &nbsp; No &nbsp; Unsure</li>"
               "<li>What would you do? &nbsp; Ignore &nbsp; Check it &nbsp; Escalate</li>"
               "<li>How clear was the explanation? (1 = not at all, 5 = completely) &nbsp; 1 &nbsp; 2 &nbsp; 3 &nbsp; 4 &nbsp; 5</li>"
               "<li>What in the explanation made you decide? <br><br><br></li></ol></div>")
out.append("</body></html>")
open("analyst_test_handout.html", "w").write("\n".join(out))
print("wrote analyst_test_handout.html and analyst_test_key.json")
