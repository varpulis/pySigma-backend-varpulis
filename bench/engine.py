"""Run the program over the events with `varpulis simulate`, timed."""

import json
import resource
import subprocess
import sys
import time

varpulis, program, events = sys.argv[1:4]
start = time.perf_counter()
with open("alerts.jsonl", "w") as out:
    run = subprocess.run([varpulis, "simulate", "-p", program, "-e", events], stdout=out, stderr=subprocess.PIPE, text=True)
elapsed = time.perf_counter() - start
if run.returncode != 0:
    sys.exit(run.stderr)
rss = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
rss_mib = rss / 1024 / (1024 if sys.platform == "darwin" else 1)
json.dump({"elapsed_s": round(elapsed, 2), "max_rss_mib": round(rss_mib), "summary": run.stderr.strip().splitlines()[-1]}, open("engine.json", "w"))
print(f"{run.stderr.strip().splitlines()[-1]} in {elapsed:.1f} s, {rss_mib:.0f} MiB at most", file=sys.stderr)
