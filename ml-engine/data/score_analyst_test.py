"""
Score analyst test responses. responses.csv columns: participant,alert_id,verdict,action,clarity
verdict: yes/no/unsure   action: ignore/check/escalate   clarity: 1-5
"""
import json, sys
import pandas as pd
key = json.load(open("analyst_test_key.json"))
d = pd.read_csv(sys.argv[1] if len(sys.argv) > 1 else "responses.csv")
d["verdict"] = d["verdict"].str.strip().str.lower()
d["real"] = d["alert_id"].map(lambda a: key[a]["real_problem"])
d["source"] = d["alert_id"].map(lambda a: "lstm-led" if key[a]["lstm_led"] else key[a]["source"])
d["correct"] = ((d["verdict"] == "yes") & (d["real"] == 1)) | ((d["verdict"] == "no") & (d["real"] == 0))
d["unsure"] = d["verdict"] == "unsure"
print(f"participants: {d['participant'].nunique()}, responses: {len(d)}")
print(f"correct {d['correct'].mean():.0%}, unsure {d['unsure'].mean():.0%}, mean clarity {d['clarity'].mean():.2f}/5")
print(d.groupby("source").agg(n=("correct", "size"), correct=("correct", "mean"), unsure=("unsure", "mean"), clarity=("clarity", "mean")).round(2))
print(d.groupby("real").agg(n=("correct", "size"), correct=("correct", "mean")).rename(index={0: "false alarm", 1: "real problem"}).round(2))
print("escalated false alarms:", int(((d["action"].str.lower() == "escalate") & (d["real"] == 0)).sum()))
