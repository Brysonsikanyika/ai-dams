import csv, os
f = 'responses_real.csv'
if not os.path.exists(f):
    open(f, 'w').write('participant,alert_id,verdict,action,clarity\n')
p = input("participant code (p1, p2, p3): ").strip()
rows = []
for a in ['A0267','A0107','A0128','A0037','A0184','A0145']:
    v = input(f"{a} real problem? (yes/no/unsure): ").strip().lower()
    act = input(f"{a} action (ignore/check/escalate): ").strip().lower()
    c = input(f"{a} clarity (1-5): ").strip()
    rows.append([p, a, v, act, c])
with open(f, 'a', newline='') as fh:
    csv.writer(fh).writerows(rows)
print("saved", len(rows), "rows for", p)
