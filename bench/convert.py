"""Convert every rule under a directory, one at a time, into one VPL program,
and record for each rule whether it converted and, if not, why.

Writes `rules.vpl` (the program as the backend writes it), `rules_n.vpl` (the
same program, each alert also carrying the line number `_n` of its event) and
`conversion.json`."""

import json
import pathlib
import sys

from sigma.backends.varpulis import VarpulisBackend
from sigma.backends.varpulis.varpulis import event_types_for
from sigma.collection import SigmaCollection

root = pathlib.Path(sys.argv[1])
collection = SigmaCollection.load_ruleset([str(p) for p in sorted(root.rglob("*.yml"))])
backend = VarpulisBackend(collect_errors=True)
queries, report = [], []
for rule in collection.rules:
    errors = len(backend.errors)
    converted = backend.convert_rule(rule, "default")
    ls = rule.logsource
    entry = {
        "id": str(rule.id),
        "title": rule.title,
        "file": str(pathlib.Path(rule.source.path).relative_to(root)) if rule.source else None,
        "status": rule.status.name.lower() if rule.status else None,
        "level": rule.level.name.lower() if rule.level else None,
        "logsource": "/".join(x or "-" for x in (ls.product, ls.category, ls.service)),
        "event_types": event_types_for(rule),
        "mitre": [str(t.name).upper() for t in rule.tags if t.namespace == "attack" and str(t.name)[:1] == "t"],
        "converted": len(backend.errors) == errors,
    }
    if entry["converted"]:
        queries.extend(converted)
    else:
        entry["error"] = str(backend.errors[-1][1])
    report.append(entry)

program = backend.finalize_output_default(queries)
pathlib.Path("rules.vpl").write_text(program)
emit = "    .emit(\n        rule: "
assert program.count(emit) == len(queries)
pathlib.Path("rules_n.vpl").write_text(program.replace(emit, "    .emit(\n        _n: _n,\n        rule: "))
pathlib.Path("conversion.json").write_text(json.dumps(report, indent=1))
print(f"{sum(e['converted'] for e in report)} of {len(report)} rules converted", file=sys.stderr)
