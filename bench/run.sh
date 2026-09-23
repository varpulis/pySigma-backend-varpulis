#!/usr/bin/env bash
# Every SigmaHQ Windows rule, converted by this backend and run by Varpulis
# over the MITRE ATT&CK Evaluations APT29 day-1 data, then checked event by
# event against an independent Sigma engine. See README.md.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
work=${WORK:-$here/work}
sigma_rev=${SIGMA_REV:-16eb58704e941956d29b1a27da6f967c5525a9bb}
varpulis=${VARPULIS_BIN:-$(command -v varpulis)}
python=${PYTHON:-python3}
data=https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/compound/apt29/day1/apt29_evals_day1_manual.zip

mkdir -p "$work" && cd "$work"
if [ ! -d sigma ]; then
    git init -q sigma
    git -C sigma fetch -q --depth 1 https://github.com/SigmaHQ/sigma "$sigma_rev"
    git -C sigma checkout -q FETCH_HEAD
fi
[ -f apt29_day1.zip ] || curl -sSfL -o apt29_day1.zip "$data"
echo "98a073140860560d70080ace9142961be4f64b4862bae892d62d0f254d0fdbe5  apt29_day1.zip" | sha256sum -c --quiet -
[ -f events.jsonl ] || { unzip -p apt29_day1.zip > apt29_day1.json && "$python" "$here/prep.py" apt29_day1.json events.jsonl; }

"$python" "$here/convert.py" sigma/rules/windows
"$varpulis" check rules.vpl
"$python" "$here/engine.py" "$varpulis" rules_n.vpl events.jsonl
"$python" "$here/oracle.py" events.jsonl sigma/rules/windows conversion.json
"$python" "$here/compare.py" events.jsonl
