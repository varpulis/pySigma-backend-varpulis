# Every SigmaHQ Windows rule on APT29

This takes every rule under `rules/windows` in [SigmaHQ](https://github.com/SigmaHQ/sigma)
and converts all of them with this backend into one VPL program. It runs that program with
`varpulis simulate` over the day-1 data of the MITRE ATT&CK Evaluations APT29 round,
then checks every alert against an independent Sigma engine, event by event.

## Results

Run on 2026-09-23 with SigmaHQ at `16eb587` (2026-09-22), Varpulis at `9e92c0b`
and this backend at 0.2.0.

| | |
|---|---|
| Rules | 2,410 |
| Converted | 2,398. The other 12 are keyword searches (a value with no field), which need the name of the field that holds the log line (`-O keyword_field=`) |
| Events | 196,081: Sysmon 143,884, Security 41,002, PowerShell 10,979, other channels 216 |
| Alerts | 2,824, from 81 rules, tagged with 41 ATT&CK techniques (59 technique and sub-technique IDs) |
| Same alerts as the reference engine | 2,396 rules of 2,396, on the same events |
| Too large for SQLite | 2 rules exceed SQLite's expression depth. Varpulis runs them, and they match nothing in this data |
| Time | 22.8 s on one core of an Intel i7-6920HQ (a 2016 laptop CPU, under WSL2), of which about 5 s is reading and parsing the 387 MB of JSON |

The time covers 17.7 million rule evaluations. Every event is tested by every rule of its
log source: a Security event by 145 rules, a registry value by 236, a process creation by
1,185. That comes to about 1 µs per rule and event. `varpulis simulate` loads the whole file
before it starts, so its 1.4 GB of memory is mostly the events; the 2,398 rules add about
80 MB to it.

## The reference engine

The oracle is pySigma's own Sysmon and Windows log-source pipelines, plus pySigma's SQLite
backend (the one [Zircolite](https://github.com/wagga40/Zircolite) is built on), run over the
same events loaded into SQLite. It shares no code with this backend or with the engine,
beyond the pySigma parser. Two settings make it follow the Sigma specification, and they
are the only two:

- The columns are declared `COLLATE NOCASE`, as Zircolite does. The SQLite backend writes a
  plain equality as `=`, and Sigma compares strings without regard to case. Without this,
  84 alerts differ, on three rules comparing `GrantedAccess: '0x1F3FFF'` or
  `ObjectName: 'servicesactive'` with events that write `0x1f3fff` and `ServicesActive`.
- `not` is two-valued. In SQL, `NOT` of a comparison on a missing field is unknown, which
  drops the event, so `selection and not filter` would lose every event that lacks the
  filter's field. Sigma keeps it, and so do Splunk and Elasticsearch.

## Routing the events

A log shipper sends each Windows channel to its own subject, and each subject is one event
type. `prep.py` does that routing for this file: every channel gets the event type the
backend reads for its Sigma service (`Security` is `WindowsSecurity`,
`Microsoft-Windows-PowerShell/Operational` is `WindowsPowershell`, and so on). Sysmon lines
are left alone, because the engine types them by EventID. Each line also gets its number
`_n`, and `rules_n.vpl` adds `_n` to every alert. That is how an alert is matched to the
event that raised it.

## Running it

```bash
pip install -e '..[test]' -r requirements.txt
VARPULIS_BIN=/path/to/varpulis ./run.sh
```

It needs git, curl and unzip, about 1 GB of disk under `work/` and 2 GB of memory. It
fetches SigmaHQ at the commit above (`SIGMA_REV` picks another) and the dataset from
[OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets/tree/master/datasets/compound/apt29/day1),
whose checksum it verifies. It prints the summary and writes the details to
`work/results.json`. The last step exits non-zero if any rule's alerts differ from the
oracle's.

## The 81 rules that fired

<details>
<summary>By number of alerts</summary>

| Alerts | Level | Rule | ATT&CK |
|---:|---|---|---|
| 954 | medium | Alternate PowerShell Hosts - PowerShell Module | T1059.001 |
| 620 | informational | PowerShell Decompress Commands | T1140 |
| 348 | medium | Python Initiated Connection | T1046 |
| 292 | medium | Potential Binary Or Script Dropper Via PowerShell |  |
| 237 | informational | User Logoff Event | T1531 |
| 74 | high | Suspicious Svchost Process Access | T1685.001 |
| 24 | high | HackTool - SysmonEnte Execution | T1685.001 |
| 16 | informational | New PowerShell Instance Created | T1059.001 |
| 16 | high | First Time Seen Remote Named Pipe | T1021.002 |
| 13 | medium | Windows Defender Exclusions Added - Registry | T1685 |
| 12 | low | Non Interactive PowerShell Process Spawned | T1059.001 |
| 11 | medium | Password Policy Enumerated | T1201 |
| 11 | medium | Potentially Suspicious AccessMask Requested From LSASS | T1003.001 |
| 10 | low | Potential Execution of Sysinternals Tools | T1588.002 |
| 10 | low | PUA - Sysinternal Tool Execution - Registry | T1588.002 |
| 10 | medium | PUA - Sysinternals Tools Execution - Registry | T1588.002 |
| 10 | low | PowerShell Module File Created |  |
| 8 | medium | SCM Database Privileged Operation | T1548 |
| 7 | medium | Elevated System Shell Spawned From Uncommon Parent Location | T1059 |
| 6 | informational | Suspicious High IntegrityLevel Conhost Legacy Option | T1202 |
| 6 | low | Suspicious Process Discovery With Get-Process | T1057 |
| 6 | high | Potential File Overwrite Via Sysinternals SDelete | T1485 |
| 6 | high | Suspicious Execution Of Renamed Sysinternals Tools - Registry | T1588.002 |
| 5 | medium | WebDav Client Execution Via Rundll32.EXE | T1048.003 |
| 4 | medium | PSScriptPolicyTest Creation By Uncommon Process |  |
| 4 | informational | New Application in AppCompat | T1204.002 |
| 4 | low | Suspicious PowerShell Get Current User | T1033 |
| 4 | high | Remote PowerShell Sessions Network Connections (WinRM) | T1059.001 |
| 4 | high | Potential Remote PowerShell Session Initiated | T1059.001, T1021.006 |
| 4 | medium | Psexec Execution | T1569, T1021 |
| 4 | high | Potential PsExec Remote Execution | T1587.001 |
| 4 | low | PsExec Service File Creation | T1569.002 |
| 4 | medium | PsExec Service Execution |  |
| 3 | medium | New Root or CA or AuthRoot Certificate to Store | T1490 |
| 3 | medium | Suspicious WSMAN Provider Image Loads | T1059.001, T1021.003 |
| 3 | low | Potential PowerShell Obfuscation Using Alias Cmdlets | T1027, T1059.001 |
| 3 | medium | File Deleted Via Sysinternals SDelete | T1070.004 |
| 3 | medium | Potential Credential Dumping Activity Via LSASS | T1003.001 |
| 3 | medium | Potential Suspicious PowerShell Keywords | T1059.001 |
| 3 | low | Potential Defense Evasion Via Raw Disk Access By Uncommon Tools | T1006 |
| 2 | medium | Removal of Potential COM Hijacking Registry Keys | T1112 |
| 2 | low | Dynamic CSharp Compile Artefact | T1027.004 |
| 2 | medium | Dynamic .NET Compilation Via Csc.EXE | T1027.004 |
| 2 | high | Cred Dump Tools Dropped Files | T1003.001, T1003.002, T1003.003, T1003.004, T1003.005 |
| 2 | medium | PowerShell Core DLL Loaded By Non PowerShell Process | T1059.001 |
| 2 | medium | LSASS Access From Non System Account | T1003.001 |
| 2 | medium | Windows Screen Capture with CopyFromScreen | T1113 |
| 2 | low | Uncommon Process Access Rights For Target Image | T1055.011 |
| 2 | medium | Powershell Keylogging | T1056.001 |
| 2 | high | Malicious PowerShell Commandlets - ScriptBlock | T1482, T1087, T1087.001, T1087.002, T1069.001, T1069.002, T1069, T1059.001 |
| 2 | medium | Potential In-Memory Execution Using Reflection.Assembly | T1620 |
| 2 | high | RunMRU Registry Key Deletion - Registry | T1070.003 |
| 2 | medium | Suspicious FromBase64String Usage On Gzip Archive - Ps Script | T1132.001 |
| 2 | medium | Malicious PowerShell Keywords | T1059.001 |
| 1 | high | Bypass UAC Using DelegateExecute | T1548.002 |
| 1 | medium | Potential UAC Bypass Via Sdclt.EXE | T1548.002 |
| 1 | medium | Sdclt Child Processes | T1548.002 |
| 1 | medium | Change PowerShell Policies to an Insecure Level | T1059.001 |
| 1 | high | Suspicious PowerShell Parameter Substring | T1059.001 |
| 1 | high | Potential Startup Shortcut Persistence Via PowerShell.EXE | T1547.001 |
| 1 | medium | Startup Folder File Write | T1547.001 |
| 1 | medium | Potential Binary Impersonating Sysinternals Tools | T1218, T1202, T1036.005 |
| 1 | medium | Certificate Exported Via PowerShell - ScriptBlock | T1552.004 |
| 1 | high | Potential Credential Dumping Attempt Via PowerShell Remote Thread | T1003.001 |
| 1 | medium | PowerShell Get Clipboard | T1115 |
| 1 | medium | Suspicious New-PSDrive to Admin Share | T1021.002 |
| 1 | medium | Execute Invoke-command on Remote Host | T1021.006 |
| 1 | medium | Remote PowerShell Session Host Process (WinRM) | T1059.001, T1021.006 |
| 1 | high | Remote LSASS Process Access Through Windows Remote Management | T1003.001, T1059.001, T1021.006 |
| 1 | low | Files Added To An Archive Using Rar.EXE | T1560.001 |
| 1 | high | Rar Usage with Password and Compression Level | T1560.001 |
| 1 | low | Windows Firewall Settings Have Been Changed | T1686.003 |
| 1 | medium | Rundll32 Execution With Uncommon DLL Extension | T1218.011 |
| 1 | high | Rundll32 Execution Without Parameters | T1021.002, T1570, T1569.002 |
| 1 | high | Bad Opsec Defaults Sacrificial Processes With Improper Arguments | T1218.011 |
| 1 | medium | New Network Trace Capture Started Via Netsh.EXE | T1040 |
| 1 | medium | Suspicious PowerShell WindowStyle Option | T1564.003 |
| 1 | high | Disable Windows Defender Functionalities Via Registry Keys | T1685 |
| 1 | high | PowerShell Base64 Encoded FromBase64String Cmdlet | T1140, T1059.001 |
| 1 | high | Malicious Base64 Encoded PowerShell Keywords in Command Lines | T1059.001 |
| 1 | medium | Suspicious Execution of Powershell with Base64 | T1059.001 |

</details>

ATT&CK IDs are the tags SigmaHQ gives its rules.
