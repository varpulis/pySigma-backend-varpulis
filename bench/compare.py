"""Compare the engine's alerts with the oracle's matches, rule by rule and
event by event, and summarise the run in `results.json`."""

import collections
import json
import sys

conversion = json.load(open("conversion.json"))
by_id = {e["id"]: e for e in conversion}
oracle = json.load(open("oracle.json"))
engine = json.load(open("engine.json"))
events = sum(1 for _ in open(sys.argv[1]))

alerts = collections.defaultdict(set)
for line in open("alerts.jsonl"):
    if line.startswith("{"):
        a = json.loads(line)
        alerts[a["sigma_id"]].add(a["_n"])

compared = oracle["matches"]
differ = {rid: (sorted(alerts.get(rid, set()) - set(m)), sorted(set(m) - alerts.get(rid, set())))
          for rid, m in compared.items() if set(m) != alerts.get(rid, set())}
fired = [rid for rid in alerts]
techniques = sorted({t for rid in fired for t in by_id[rid]["mitre"]})
failed = collections.Counter(
    "keyword search (no field)" if "keyword" in e["error"] else e["error"][:100]
    for e in conversion if not e["converted"]
)
results = {
    "rules": len(conversion),
    "converted": sum(e["converted"] for e in conversion),
    "not_converted": dict(failed),
    "events": events,
    "alerts": sum(len(s) for s in alerts.values()),
    "rules_fired": len(fired),
    "techniques": techniques,
    "engine": engine,
    "compared_rules": len(compared),
    "identical_rules": len(compared) - len(differ),
    "beyond_sqlite": {by_id[r]["title"]: len(alerts.get(r, ())) for r in oracle["errors"]},
    "differ": {by_id[r]["title"]: {"engine_only": a, "oracle_only": b} for r, (a, b) in differ.items()},
    "fired": sorted(
        ({"title": by_id[r]["title"], "level": by_id[r]["level"], "alerts": len(alerts[r]), "mitre": by_id[r]["mitre"]}
         for r in fired), key=lambda x: -x["alerts"]),
}
json.dump(results, open("results.json", "w"), indent=1)
print(f"""{results['converted']} of {results['rules']} rules converted; not converted: {results['not_converted']}
{events} events, {results['alerts']} alerts from {results['rules_fired']} rules, {len(techniques)} ATT&CK techniques
engine: {engine['elapsed_s']} s, {engine['max_rss_mib']} MiB at most
same events as the oracle for {results['identical_rules']} of {results['compared_rules']} rules
beyond SQLite's expression limit (engine alerts): {results['beyond_sqlite']}""")
if differ:
    print("DIFFERENT:", json.dumps(results["differ"], indent=1)[:4000])
    sys.exit(1)
