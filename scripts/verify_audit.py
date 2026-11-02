"""
Verify the hash chain of dashboard-server/audit.log.
Usage: python scripts/verify_audit.py [PATH]
Lines written before chaining (no hash) are skipped. The first chained line is an anchor:
its own hash is checked, its prev is not (older lines may have been removed by retention).
Record the printed head hash outside this server; a rewritten chain can only be caught by
comparing against a head hash that was saved elsewhere.
"""
import hashlib, json, pathlib, sys
path = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else pathlib.Path(__file__).resolve().parent.parent / "dashboard-server" / "audit.log"
prev_hash, legacy, chained, first = None, 0, 0, None
for n, line in enumerate(path.read_text().splitlines(), 1):
    if not line.strip():
        continue
    try:
        e = json.loads(line)
    except ValueError:
        sys.exit(f"BROKEN at line {n}: not valid JSON")
    if "hash" not in e:
        if chained:
            sys.exit(f"BROKEN at line {n}: unchained line after the chain started")
        legacy += 1
        continue
    want = hashlib.sha256("|".join([e["prev"], e["ts"], e.get("user") or "", e["action"], str(e["outcome"]), e.get("ip") or ""]).encode()).hexdigest()
    if want != e["hash"]:
        sys.exit(f"BROKEN at line {n}: entry does not match its hash (edited)")
    if prev_hash is not None and e["prev"] != prev_hash:
        sys.exit(f"BROKEN at line {n}: does not follow the previous line (line removed or reordered)")
    if first is None:
        first = n
    prev_hash, chained = e["hash"], chained + 1
print(f"OK: {chained} chained entries (from line {first}), {legacy} older unchained lines skipped")
print("head hash:", prev_hash)
