"""
Build the v2 SQL-injection dataset from independent public sources.

Why: the v1 classifier was trained on ~24 templates written by this project and
evaluated on payloads written by the same author, so both its 100% test score
and its 100% external-set recall said little about unseen attacks. v2 uses data
written by other people and splits it by AUTHORSHIP, so the final test only
contains sources the model has never seen.

Sources (clone them first; see fetch_sqli_sources.sh):
  attacks   SecLists Fuzzing/Databases/SQLi (community fuzz lists + sqlmap
            payload templates + polyglots)
  benign    jkkummerfeld/text2sql-data (real SQL from published text-to-SQL
            datasets: ATIS, Geography, Restaurants, Scholar, Spider, IMDB, Yelp,
            Advising, Academic) plus the project's own academic catalogue

Split (nothing crosses between splits):
  TRAIN  attacks: Generic-SQLi, quick-SQLi, Oracle, MSSQL, MySQL, MySQL-login
         benign : ATIS, Geography, Restaurants, Spider, a small synthetic
                  CRUD bank (other domains, date functions), v1 corpus
  VALID  attacks: Generic-BlindSQLi, sqli.auth.bypass       (used to pick the
         benign : IMDB, Yelp, Scholar                        model and the cutoff)
  TEST   attacks: sqlmap payload templates + SQLi-Polyglots  (scanner-generated,
                  a different style from the training lists)
         benign : Advising, Academic (real university schemas) + this project's
                  academic catalogue (apostrophes in names and titles included)
  DEV    the 30 hand-written payloads used in the project's own traffic. They were
         already seen while diagnosing v1, so they are reported separately and are
         never used for selection or as the final test.

Attack queries are built by injecting each payload into a benign query of the
same split (so a payload never meets a host from another split). Nothing here is
ever executed against a database; these are text samples for classification.
"""

import argparse
import csv
import hashlib
import json
import tarfile
import random
import re
import sys
from datetime import datetime
from pathlib import Path

SEED = 20261015

T2S_SPLITS = {
    "train": ["atis", "geography", "restaurants", "spider"],
    "valid": ["imdb", "yelp", "scholar"],
    "test": ["advising", "academic"],
}
VALID_FILE_HINTS = ("blindsqli", "auth.bypass")
HOSTS_PER_PAYLOAD = {"train": 3, "valid": 3, "test": 2}   # plus 3 catalogue contexts in test
CAPS = {"train": 6000, "valid": 1500, "test": 2500}        # benign text2sql queries per split
APOS_NAMES = ["O'Brien", "D'Souza", "O'Connor", "D'Arcy", "N'Diaye", "L'Heureux",
              "St. John's College", "Women's Studies", "King's Lynn", "Children's Literature",
              "Dean's List", "Smith's Bakery"]

STR_RE = re.compile(r"'((?:[^'\\]|\\.|'')*)'")
NUM_RE = re.compile(r"(?<![\w.'\"])\d+(?![\w.'\"])")


# ---------------------------------------------------------------- benign side
def _quote(value: str, style: str) -> str:
    if style == "double":
        return '"' + value.replace('"', '\\"') + '"'
    return "'" + value.replace("'", "\\'") + "'"


def _is_number(v: str) -> bool:
    return re.fullmatch(r"-?\d+(\.\d+)?", v.strip()) is not None


def _to_single_quotes(sql: str) -> str:
    def repl(m):
        body = m.group(1).replace('\\"', '"').replace("'", "\\'")
        return "'" + body + "'"
    return re.sub(r'"((?:[^"\\]|\\.)*)"', repl, sql)


def load_text2sql(path: Path, rng: random.Random, per_item: int = 2):
    """Instantiate each template with example / per-sentence values."""
    data = json.load(open(path, encoding="utf-8"))
    out = []
    for item in data:
        sqls = item.get("sql") or []
        sentences = item.get("sentences") or [{}]
        examples = {v["name"]: str(v.get("example", "")) for v in item.get("variables", []) if "name" in v}
        for sql in sorted(set(sqls)):   # sorted: set order changes with Python's per-run hash seed
            for sent in rng.sample(sentences, min(per_item, len(sentences))):
                varmap = dict(examples)
                for k, v in (sent.get("variables") or {}).items():
                    if v not in (None, ""):
                        varmap[k] = str(v)
                text = sql
                for name, value in sorted(varmap.items(), key=lambda kv: -len(kv[0])):
                    pat_q = re.compile('"' + re.escape(name) + '"')
                    if pat_q.search(text):
                        text = pat_q.sub(lambda _m, v=value: _quote(v, "double"), text)
                    pat_b = re.compile(r"\b" + re.escape(name) + r"\b")
                    text = pat_b.sub(lambda _m, v=value: v if _is_number(v) else _quote(v, "double"), text)
                text = re.sub(r"\s+", " ", text).strip()
                if rng.random() < 0.7:
                    text = _to_single_quotes(text)
                if len(text) > 12:
                    out.append(text)
    return list(dict.fromkeys(out))


def augment_apostrophe(sql: str, rng: random.Random):
    lits = list(STR_RE.finditer(sql))
    if not lits:
        return None
    m = rng.choice(lits)
    name = rng.choice(APOS_NAMES)
    esc = name.replace("'", "\\'") if rng.random() < 0.6 else name.replace("'", "''")
    return sql[:m.start()] + "'" + esc + "'" + sql[m.end():]


CRUD = [
    "SELECT * FROM employees WHERE department = '{dept}' AND salary > {n} ORDER BY hire_date DESC LIMIT {k}",
    "SELECT name, email FROM customers WHERE created_at BETWEEN '{d1}' AND '{d2}'",
    "UPDATE tickets SET status = 'closed', closed_at = NOW() WHERE id = {n}",
    "DELETE FROM sessions WHERE expires_at < NOW() - INTERVAL {k} DAY",
    "INSERT INTO invoices (customer_id, total, issued_on) VALUES ({n}, {f}, '{d1}')",
    "SELECT COUNT(*) FROM orders WHERE status = '{status}' AND created_at > CURDATE() - INTERVAL {k} DAY",
    "SELECT p.name, SUM(oi.qty) AS sold FROM products p JOIN order_items oi ON oi.product_id = p.id GROUP BY p.name HAVING SUM(oi.qty) > {n} ORDER BY sold DESC",
    "SELECT * FROM patients WHERE last_name LIKE '{prefix}%' ORDER BY last_name LIMIT {k}",
    "UPDATE inventory SET stock = stock - {k} WHERE sku = '{sku}'",
    "SELECT id, title FROM articles WHERE published = 1 AND author_id IN ({n}, {n2}, {n3})",
    "SELECT AVG(rating) FROM reviews WHERE product_id = {n} AND created_at >= '{d1}'",
    "INSERT INTO comments (post_id, author, body) VALUES ({n}, '{name}', '{text}')",
    "SELECT * FROM flights WHERE origin = '{ap}' AND destination = '{ap2}' AND departure > NOW()",
    "SELECT u.id, u.email FROM users u LEFT JOIN subscriptions s ON s.user_id = u.id WHERE s.id IS NULL",
    "SELECT DISTINCT city FROM addresses WHERE country = '{country}' ORDER BY city",
    "UPDATE accounts SET balance = balance + {f} WHERE account_no = '{acct}'",
    "SELECT * FROM bookings WHERE room_id = {n} AND check_in <= '{d2}' AND check_out >= '{d1}'",
    "DELETE FROM carts WHERE user_id = {n} AND updated_at < '{d1}'",
    "SELECT MAX(price), MIN(price) FROM listings WHERE category = '{cat}'",
    "SELECT t.name FROM teams t WHERE t.id NOT IN (SELECT team_id FROM matches WHERE season = {year})",
]
_VALS = {
    "dept": ["Sales", "Engineering", "Finance", "Support"], "status": ["open", "shipped", "pending"],
    "prefix": ["Mu", "Ba", "Ch", "Ph"], "sku": ["AB-1021", "ZX-77", "QL-300"],
    "name": ["Alice", "Bob", "Chipo", "O'Hara", "D'Costa"], "text": ["Great product", "It's late", "Won't buy again", "OK"],
    "ap": ["LUN", "NDO", "JNB", "LHR"], "ap2": ["DXB", "NBO", "CPT"], "country": ["Zambia", "Kenya", "Ghana"],
    "acct": ["ACC-1001", "ACC-2090"], "cat": ["laptops", "phones", "books"],
}


def synthetic_crud(rng: random.Random, per_template: int = 40):
    out = []
    for tpl in CRUD:
        for _ in range(per_template):
            vals = {k: rng.choice(v) for k, v in _VALS.items()}
            vals.update(n=rng.randint(1, 9999), n2=rng.randint(1, 9999), n3=rng.randint(1, 9999),
                        k=rng.randint(1, 60), f=round(rng.uniform(5, 5000), 2), year=rng.randint(2015, 2026),
                        d1=f"20{rng.randint(15, 25)}-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d}",
                        d2=f"20{rng.randint(15, 25)}-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d}")
            text = tpl.format(**vals)
            out.append(re.sub(r"(?<=\w)'(?=\w)", lambda _m: "\\'", text) if False else text)
    return list(dict.fromkeys(out))


def wikisql_dev(sources: Path, rng: random.Random, n: int = 1200):
    """Real-world values (names, titles, places -- many with apostrophes) rendered as SQL.
    Uses the dev split only; none of WikiSQL is used for training."""
    root = sources / "WikiSQL"
    data = root / "data"
    if not (data / "dev.jsonl").exists():
        with tarfile.open(root / "data.tar.bz2", "r:bz2") as t:
            t.extractall(root)
    heads = {}
    for line in open(data / "dev.tables.jsonl", encoding="utf-8"):
        t = json.loads(line)
        heads[t["id"]] = t["header"]
    aggs, ops = ["", "MAX", "MIN", "COUNT", "SUM", "AVG"], ["=", ">", "<", "="]
    out = []
    for line in open(data / "dev.jsonl", encoding="utf-8"):
        q = json.loads(line)
        h = heads.get(q["table_id"])
        if not h:
            continue
        sql = q["sql"]
        col = "`" + h[sql["sel"]] + "`"
        sel = col if sql["agg"] == 0 else f"{aggs[sql['agg']]}({col})"
        conds = []
        for c, o, v in sql["conds"]:
            v = str(v)
            lit = v if _is_number(v) else _quote(v, "single")
            conds.append(f"`{h[c]}` {ops[o]} {lit}")
        text = f"SELECT {sel} FROM `{q['table_id']}`" + (" WHERE " + " AND ".join(conds) if conds else "")
        out.append(text)
    out = list(dict.fromkeys(out))
    rng.shuffle(out)
    return out[:n]


# ---------------------------------------------------------------- attack side
def _rand_str(rng, n=5):
    return "".join(rng.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(n))


def instantiate(line: str, rng: random.Random) -> str:
    """Fill sqlmap-style placeholders; the same placeholder gets the same value within a line."""
    vals = {}

    def sub(m):
        tok = m.group(1)
        if tok not in vals:
            if tok.startswith("RANDNUM"):
                vals[tok] = str(rng.randint(1000, 9999))
            elif tok == "RANDSTR":
                vals[tok] = _rand_str(rng, rng.randint(4, 6))
            elif tok.startswith("DELIMITER"):
                vals[tok] = _rand_str(rng)
            elif tok == "SLEEPTIME":
                vals[tok] = "5"
            elif tok == "ORIGVALUE":
                vals[tok] = "1"
            elif tok == "GENERIC_SQL_COMMENT":
                vals[tok] = "-- -"
            else:
                vals[tok] = rng.choice(["1=1", "1", "NULL"])
        return vals[tok]

    return re.sub(r"\[([A-Z_0-9]+)\]", sub, line).strip()


def load_payload_file(path: Path, rng: random.Random):
    out = []
    for raw in open(path, encoding="utf-8", errors="replace"):
        line = raw.rstrip("\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        out.append(instantiate(line, rng))
    return list(dict.fromkeys(out))


def inject(host: str, payload: str, rng: random.Random) -> str:
    """Place a payload where an attacker's input would land in the host query."""
    p = payload.strip()
    if p[:1] in ("'", '"'):
        lits = list(STR_RE.finditer(host))
        if lits:
            m = rng.choice(lits)
            return host[:m.start()] + "'" + m.group(1) + p + "'" + host[m.end():]
    nums = list(NUM_RE.finditer(host))
    if nums and p[:1] not in ("'", '"'):
        m = rng.choice(nums)
        sep = "" if p.startswith((" ", ")")) else " "
        return host[:m.end()] + sep + p + host[m.end():]
    lits = list(STR_RE.finditer(host))
    if lits:
        # break out of the literal, run the payload, comment out the rest of the host
        m = rng.choice(lits)
        return host[:m.end()] + " " + p + " -- '" + host[m.end():]
    return host.rstrip("; ") + " " + p


# ---------------------------------------------------------------- orchestration
def classify_attack_files(secdir: Path):
    train, valid, test = {}, {}, {}
    for f in sorted(secdir.rglob("*.txt")):
        rel = str(f.relative_to(secdir)).lower()
        if "nosql" in rel:
            continue
        if "sqlmap-risk-classified" in rel or "polyglot" in rel:
            test[f] = f.stem if "polyglot" in rel else "sqlmap:" + f.parent.name + "/" + f.stem
        elif any(h in rel for h in VALID_FILE_HINTS):
            valid[f] = f.stem
        else:
            train[f] = f.stem
    return train, valid, test


class _FixedClock(datetime):
    """The catalogue stamps queries with datetime.now(); pin it so builds are reproducible."""
    @classmethod
    def now(cls, tz=None):
        return datetime(2026, 10, 15, 12, 0, 0)


def catalogue_benign(rng, per_kind=70, seed=0):
    """The project's own academic query catalogue, rendered the way the server receives it.
    The catalogue draws values from the global random module and the clock, so both are
    pinned here (otherwise two builds of the same inputs differ)."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import pymysql
    import academic_workload
    from academic_workload import BENIGN_KINDS
    academic_workload.datetime = _FixedClock
    random.seed(seed)
    conn = pymysql.connections.Connection(defer_connect=True)
    conn.server_status = 0
    cur = conn.cursor()
    out = []
    for kind, (_t, _op, sql, params_fn) in BENIGN_KINDS.items():
        for _ in range(per_kind):
            sid = f"23000{rng.randint(1, 20):02d}"
            out.append((cur.mogrify(sql, params_fn(sid)), "catalogue:" + kind))
    return out


def catalogue_hosts():
    return ["SELECT * FROM grades WHERE student_id = '2300001'",
            "SELECT course_code, course_name FROM courses WHERE course_name LIKE '%Security%'",
            "SELECT * FROM fees WHERE id = 5"]


def dev_attacks(rng):
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from academic_workload import INJECTION_CONTEXTS, INJECTION_PAYLOADS
    out = []
    for family, ctx, suffix in INJECTION_PAYLOADS:
        _tbl, tpl = INJECTION_CONTEXTS[ctx]
        value = f"23000{rng.randint(1, 20):02d}" + suffix if ctx == "quoted" else suffix
        out.append((tpl.format(v=value), "dev:" + family))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sources", required=True, help="folder containing SecLists/ and text2sql-data/")
    ap.add_argument("--out", default=".")
    ap.add_argument("--corpus", default="sqli_corpus.csv", help="v1 corpus, added to TRAIN if present")
    args = ap.parse_args()
    rng = random.Random(SEED)
    src, out = Path(args.sources), Path(args.out)
    t2s_dir = src / "text2sql-data" / "data"
    sec_dir = src / "SecLists" / "Fuzzing" / "Databases" / "SQLi"
    for p in (t2s_dir, sec_dir):
        if not p.exists():
            sys.exit(f"missing {p} -- run fetch_sqli_sources.sh first")

    rows = {"train": [], "valid": [], "test": []}   # (text, label, source)
    hosts = {}
    spider_heldout = []   # table-group hold-out used only by the confirmation exam (test2)
    for split, names in T2S_SPLITS.items():
        pool = []
        for n in names:
            f = t2s_dir / f"{n}.json"
            if not f.exists():
                print(f"  (skipping missing {f.name})")
                continue
            qs = load_text2sql(f, rng)
            rng.shuffle(qs)
            if n == "spider":
                keep = []
                for q in qs:   # hold out ~20% of Spider by first FROM table (a proxy for its database)
                    m = re.search(r"\bFROM\s+(\w+)", q, re.I)
                    key = (m.group(1).lower() if m else q).encode()
                    (spider_heldout if int(hashlib.sha1(key).hexdigest()[:8], 16) % 5 == 0 else keep).append(q)
                qs = keep
            qs = qs[: max(200, CAPS[split] // len(names))]
            pool += [(q, n) for q in qs]
        hosts[split] = [q for q, _ in pool if STR_RE.search(q) or NUM_RE.search(q)]
        for q, n in pool:
            rows[split].append((q, 0, "t2s:" + n))
            if split != "test" and rng.random() < 0.15:
                a = augment_apostrophe(q, rng)
                if a:
                    rows[split].append((a, 0, f"t2s:{n}+apostrophe"))
    for q in synthetic_crud(rng):
        rows["train"].append((q, 0, "synthetic-crud"))
        hosts["train"].append(q)
    corpus = Path(args.corpus)
    if corpus.exists():
        for r in csv.DictReader(open(corpus, encoding="utf-8")):
            rows["train"].append((r["query_text"], int(r["label"]), "v1-corpus"))
    for q, src_name in catalogue_benign(rng, seed=SEED + 2):
        rows["test"].append((q, 0, src_name))

    ftrain, fvalid, ftest = classify_attack_files(sec_dir)

    def norm(p):
        return re.sub(r"\d+", "0", re.sub(r"\s+", " ", p.strip().lower()))

    seen_train = set()
    for f in list(ftrain) + list(fvalid):
        seen_train |= {norm(p) for p in load_payload_file(f, random.Random(0))}
    dropped = 0
    for split, files in (("train", ftrain), ("valid", fvalid), ("test", ftest)):
        used = []
        for f, tag in files.items():
            payloads = load_payload_file(f, rng)
            if split == "test":
                kept = [p for p in payloads if norm(p) not in seen_train]
                dropped += len(payloads) - len(kept)
                payloads = kept
                seen_train |= {norm(p) for p in payloads}
            used.append(f"{tag}({len(payloads)})")
            for p in payloads:
                chosen = rng.sample(hosts[split], min(HOSTS_PER_PAYLOAD[split], len(hosts[split])))
                if split == "test":
                    chosen += catalogue_hosts()
                for h in chosen:
                    rows[split].append((inject(h, p, rng), 1, "attack:" + tag))
        print(f"  {split} attack files: {', '.join(used)}")
    print(f"  test payloads dropped because their digit-masked text also appears in train/valid: {dropped}")

    # ---- test2: confirmation exam from sources never used in any earlier split ----
    rng2 = random.Random(SEED + 7)
    wiki = wikisql_dev(src, rng2)
    spider_h = list(dict.fromkeys(spider_heldout))[:800]
    test2 = [(q, 0, "wikisql:dev") for q in wiki] + [(q, 0, "t2s:spider-heldout") for q in spider_h]
    pat_dir = src / "PayloadsAllTheThings" / "SQL Injection" / "Intruder"
    p2, kept_n, all_n = [], 0, 0
    for f in sorted(pat_dir.iterdir()):
        if not f.is_file() or f.name.upper().startswith("FUZZDB") or f.suffix.lower() not in ("", ".txt"):
            continue
        for p in load_payload_file(f, rng2):
            all_n += 1
            if norm(p) not in seen_train:
                kept_n += 1
                p2.append((p, f.stem))
    rng2.shuffle(p2)
    p2 = p2[:400]
    print(f"  test2 payload files: PayloadsAllTheThings/Intruder (non-FUZZDB): {all_n} lines, "
          f"{kept_n} not seen in train/valid/test1, using {len(p2)}")
    for p, tag in p2:
        hs = [("app", rng2.choice(catalogue_hosts()))]
        if spider_h:
            hs.append(("spider", rng2.choice(spider_h)))
        hs.append(("wiki", rng2.choice(wiki)))
        for hk, h in hs:
            test2.append((inject(h, p, rng2), 1, f"attack2:{tag}|host={hk}"))

    dev = [(t, 1, s) for t, s in dev_attacks(rng)]
    # Separate draw of the application's own benign traffic (different seed) used only to
    # calibrate a per-deployment cutoff; never part of training or of the test set.
    calib = [(q, 0, s.replace("catalogue:", "calib:")) for q, s in catalogue_benign(random.Random(SEED + 1), seed=SEED + 3)]
    for split, data in list(rows.items()) + [("dev", dev), ("calib", calib), ("test2", test2)]:
        seen, uniq = set(), []
        for t, y, s in data:
            if (t, y) not in seen:
                seen.add((t, y))
                uniq.append((t, y, s))
        rng.shuffle(uniq)
        path = out / f"sqli_v2_{split}.csv"
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["query_text", "label", "source"])
            w.writerows(uniq)
        n1 = sum(y for _, y, _ in uniq)
        print(f"{split:5s}: {len(uniq):6d} rows  ({len(uniq) - n1} benign, {n1} attack)  -> {path}")


if __name__ == "__main__":
    main()
