"""
AI-DAMS live behavioural features.

Rebuilds, one event at a time, the exact feature vector the batch Isolation
Forest was trained on (behaviour_features.py v4): hour, weekday, is_night, six
trailing-window counts per account, and the operation one-hot. A window is
(t - width, t], current event included, matching pandas rolling("Ns").

parse_sql() recovers operation, table and target customer from the SQL text,
because a live audit record has no such columns.
"""
import re
from collections import defaultdict, deque

OPS = ("DELETE", "INSERT", "SELECT", "UPDATE")
LEAD_COMMENTS = re.compile(r"^\s*(?:/\*.*?\*/\s*)+", re.S)
TABLE_RE = re.compile(r"\b(?:FROM|INTO|UPDATE)\s+`?([A-Za-z_]\w*)`?", re.I)
TARGET_RE = re.compile(r"\bstudent_id\s*=\s*'?(\d{7})", re.I)
ACCT_RE = re.compile(r"^student_(\d+)$")


def account_to_customer(acct):
    m = ACCT_RE.match(acct or "")
    return int("23000" + m.group(1)[-2:]) if m else None


def parse_sql(sql, acct=None):
    """Return (operation, table, target_customer_id); operation None if not a data statement."""
    s = LEAD_COMMENTS.sub("", sql or "").strip()
    first = s.split(None, 1)[0].upper() if s else ""
    if first not in OPS:
        return None, None, None
    m = TABLE_RE.search(s)
    table = m.group(1).lower() if m else None
    t = TARGET_RE.search(s)
    target = int(t.group(1)) if t else account_to_customer(acct)
    return first, table, target


class LiveFeatures:
    def __init__(self):
        self.hist = defaultdict(deque)   # account -> deque of (seconds, table, target)

    def update(self, acct, ts, op, table, target):
        """ts: naive local datetime. Returns the feature dict for this event."""
        t = ts.timestamp()
        h = self.hist[acct]
        h.append((t, table, target))
        while h and h[0][0] <= t - 3600:
            h.popleft()
        in10 = in60 = 0
        tab60, tabh, tgt60 = set(), set(), set()
        for (u, tb, tg) in h:
            tabh.add(tb)
            if u > t - 60:
                in60 += 1
                tab60.add(tb)
                tgt60.add(tg)
                if u > t - 10:
                    in10 += 1
        hour = ts.hour
        f = {
            "hour_of_day": hour, "day_of_week": ts.weekday(),
            "is_night": int(hour < 6 or hour >= 22),
            "events_last_10s": in10, "events_last_60s": in60, "events_last_hour": len(h),
            "distinct_tables_last_60s": len(tab60), "distinct_tables_last_hour": len(tabh),
            "distinct_targets_last_60s": len(tgt60),
        }
        for o in OPS:
            f["op_" + o] = int(op == o)
        return f
