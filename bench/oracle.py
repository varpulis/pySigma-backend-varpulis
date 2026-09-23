"""The same rules and the same events through an independent Sigma engine:
pySigma's official Sysmon and Windows log-source pipelines, pySigma's SQLite
backend (the one Zircolite runs on), and SQLite. Writes, for every rule, the
exact set of event lines (`_n`) that match, to `oracle.json`."""

import json
import pathlib
import re
import sqlite3
import sys
import time
from functools import lru_cache

from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection
from sigma.pipelines.sysmon import sysmon_pipeline
from sigma.pipelines.windows import windows_logsource_pipeline

# NXLog writes numbers as strings ("LogonType": "3"); so does this dataset.
INT = re.compile(r"^-?[0-9]{1,18}$")


class TwoValued(sqliteBackend):
    """SQL's NOT of unknown (a comparison on a missing field) is unknown, which
    drops the event: `selection and not filter` would lose every event that
    lacks the filter's field. Sigma, Splunk and Elasticsearch keep it."""

    def convert_condition_not(self, cond, state):
        out = super().convert_condition_not(cond, state)
        prefix = self.not_token + self.token_separator
        assert isinstance(out, str) and out.startswith(prefix), out
        return f"NOT IFNULL({out[len(prefix):]}, 0)"


@lru_cache(maxsize=None)
def compiled(pattern):
    return re.compile(pattern)


def regexp(pattern, value):
    return None if value is None else compiled(pattern).search(str(value)) is not None


events_path, rules_root, conversion = sys.argv[1], pathlib.Path(sys.argv[2]), sys.argv[3]
db = sqlite3.connect(":memory:")
db.create_function("REGEXP", 2, regexp, deterministic=True)

start = time.perf_counter()
rows, columns = [], {}
for line in open(events_path):
    row = {}
    for key, value in json.loads(line).items():
        key = columns.setdefault(key.lower(), key)  # SQLite column names ignore case
        if isinstance(value, str) and INT.match(value):
            value = int(value)
        elif isinstance(value, (list, dict)):
            value = json.dumps(value)
        if row.get(key) is None:
            row[key] = value
    rows.append(row)
names = list(columns.values())
# As Zircolite creates its table: Sigma compares strings case-insensitively,
# and the backend writes a plain equality as `=`.
db.execute("CREATE TABLE logs (" + ", ".join(f'"{c}" COLLATE NOCASE' for c in names) + ")")
db.executemany(f"INSERT INTO logs VALUES ({','.join('?' * len(names))})", [[r.get(c) for c in names] for r in rows])
db.execute('CREATE INDEX channel_event ON logs("Channel", "EventID")')
print(f"{len(rows)} events loaded in {time.perf_counter() - start:.1f} s", file=sys.stderr)

wanted = {e["id"] for e in json.load(open(conversion)) if e["converted"]}
collection = SigmaCollection.load_ruleset([str(p) for p in sorted(rules_root.rglob("*.yml"))])
backend = TwoValued(sysmon_pipeline() + windows_logsource_pipeline())
matches, errors = {}, {}
start = time.perf_counter()
for rule in collection.rules:
    rid = str(rule.id)
    if rid not in wanted:
        continue
    sql = backend.convert_rule(rule)[0].replace("<TABLE_NAME>", "logs").replace("SELECT *", "SELECT _n", 1)
    while True:
        try:
            matches[rid] = sorted(r[0] for r in db.execute(sql))
            break
        except sqlite3.OperationalError as e:
            missing = re.match(r"no such column: (.+)", str(e))
            if not missing:  # "Expression tree is too large": SQLite's own limit
                errors[rid] = str(e)
                break
            db.execute(f'ALTER TABLE logs ADD COLUMN "{missing.group(1)}" COLLATE NOCASE')
print(f"{len(matches)} rules run, {len(errors)} beyond SQLite, in {time.perf_counter() - start:.1f} s", file=sys.stderr)
json.dump({"matches": matches, "errors": errors}, open("oracle.json", "w"))
