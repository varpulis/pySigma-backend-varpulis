"""The converted programs, run by the engine they are written for.

A backend that emits text which looks right is only half tested: these tests
hand every program to `varpulis check`, then replay events through
`varpulis simulate` and count the alerts. Set VARPULIS_BIN, or put `varpulis`
on the PATH; without it they are skipped, and say so.
"""

import json
import os
import pathlib
import shutil
import subprocess

import pytest
from sigma.collection import SigmaCollection

from sigma.backends.varpulis import VarpulisBackend

HERE = pathlib.Path(__file__).parent
VARPULIS = os.environ.get("VARPULIS_BIN") or shutil.which("varpulis")

pytestmark = pytest.mark.skipif(not VARPULIS, reason="no varpulis binary (set VARPULIS_BIN)")


def program_for(rules: str, output_format: str = "default") -> str:
    collection = SigmaCollection.load_ruleset([str(HERE / "rules" / rules)])
    return VarpulisBackend().convert(collection, output_format)


def check(program: str, tmp_path: pathlib.Path) -> pathlib.Path:
    path = tmp_path / "program.vpl"
    path.write_text(program)
    result = subprocess.run([VARPULIS, "check", str(path)], capture_output=True, text=True)
    assert result.returncode == 0, f"{result.stdout}{result.stderr}\n{program}"
    return path


def alerts(program: pathlib.Path, events: str) -> list[dict]:
    result = subprocess.run(
        [VARPULIS, "simulate", "-p", str(program), "-e", str(HERE / "events" / events), "-w", "1"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    return [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]


def test_the_file_name_rule_sees_psexec_and_misses_it_renamed(tmp_path):
    program = check(program_for("psexec.yml"), tmp_path)
    assert [a["rule"] for a in alerts(program, "psexec_named.jsonl")] == ["PsExec Execution"]
    assert alerts(program, "lateral_movement.jsonl") == []


def test_the_behaviour_correlation_catches_the_renamed_binary(tmp_path):
    program = check(program_for("lateral_movement.yml"), tmp_path)
    found = alerts(program, "lateral_movement.jsonl")
    assert [a["rule"] for a in found] == ["Lateral movement over SMB, judged on behaviour"]
    alert = found[0]
    assert alert["SmbConnection_Hostname"] == "WS01"
    assert alert["ServiceChild_Hostname"] == "DC01"
    assert alert["ServiceChild_ParentImage"].lower().endswith("\\services.exe")
    assert alert["level"] == "critical"
    assert alert["mitre"] == "T1021.002"


def test_counts_fire_once_per_address_that_crosses_the_threshold(tmp_path):
    program = check(program_for("brute_force.yml"), tmp_path)
    found = alerts(program, "brute_force.jsonl")
    by_rule = {a["rule"]: a for a in found}
    assert sorted(by_rule) == [
        "Many failed logons from one address",
        "Password spraying, one address and many accounts",
    ]
    assert by_rule["Many failed logons from one address"]["IpAddress"] == "10.0.0.66"
    assert by_rule["Many failed logons from one address"]["count"] == 6
    assert by_rule["Password spraying, one address and many accounts"]["count"] == 5


def test_a_category_over_several_sysmon_events_sees_each_and_powershell_is_read_by_channel(tmp_path):
    program = check(program_for("windows_channels.yml"), tmp_path)
    found = alerts(program, "windows_channels.jsonl")
    assert found and all(a["Computer"] == "WS01" for a in found)
    run_keys = [a for a in found if a["rule"] == "Run key written"]
    assert sorted(a["TargetObject"][-1] for a in run_keys) == ["a", "b", "c"]
    # ps_script is event 4104 of the PowerShell channel; the service rule sees
    # the whole channel, the module log included.
    assert [a["rule"] for a in found if "Mimikatz" in a["rule"]] == [
        "Mimikatz in a PowerShell script block",
        "PowerShell channel mentions Mimikatz",
        "PowerShell channel mentions Mimikatz",
    ]


def test_temporal_over_four_rules_fires_once_all_four_are_seen_in_a_window(tmp_path):
    program = check(program_for("temporal_four.yml"), tmp_path)
    found = [a for a in alerts(program, "temporal_four.jsonl") if a["rule"].startswith("Console session")]
    assert len(found) == 1
    assert found[0]["rules"] == 4


@pytest.mark.parametrize(
    "rules", ["psexec.yml", "lateral_movement.yml", "brute_force.yml", "windows_channels.yml", "temporal_four.yml"]
)
def test_the_vejas_program_checks(rules, tmp_path):
    check(program_for(rules, "vejas"), tmp_path)
