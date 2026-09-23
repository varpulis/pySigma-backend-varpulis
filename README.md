# pySigma-backend-varpulis

A [pySigma](https://github.com/SigmaHQ/pySigma) backend that turns Sigma rules,
correlation rules included, into [VPL](https://www.varpulis-cep.com/docs/language/overview),
the rule language of the Varpulis detection engine. The output is a program you
can run as it is: offline against a file of events with `varpulis simulate`, or
on a NATS bus as a detect unit of [Vejas](https://vejas.dev).

Correlation is the part worth looking at. Sigma's correlation rules
(`temporal_ordered`, `temporal`, `event_count`, `value_count`) are converted by
a handful of backends, each into a query over stored events that buckets
time. Here it becomes what a streaming engine does natively: a `temporal_ordered` correlation is a sequence matched
as events arrive, in the time the logs carry, and its state survives a restart
when it runs in Vejas.

## Install and convert

```bash
pip install sigma-cli pysigma-backend-varpulis
sigma convert -t varpulis rules/                 # a VPL program on stdout
sigma convert -t varpulis -f vejas rules/        # the same, bound to a NATS bus
```

`pip install git+https://github.com/varpulis/pySigma-backend-varpulis` gives
the latest commit instead of the release.

The generated programs need a Varpulis engine with single-quoted raw strings,
`regex_match` and backticked field names, which is `main` from 2026-09-23 on
(`cargo install --git https://github.com/varpulis/varpulis varpulis-cli`).
Counts that close on their log source's event time, and correlations over
counts, need `main` from 2026-09-24 on.

On the 3 760 rules of the SigmaHQ repository (2026-09-22), all 3 760 convert
with `-O keyword_field=message` and 3 653 without it (the 107 others are
keyword searches, see below), and every generated program passes `varpulis
check`, the engine's parser and semantic validator.

What the programs catch is tested as well. In [`bench/`](bench/), the 2 398
Windows rules that convert run as one program over the 196 081 events of the
MITRE ATT&CK Evaluations APT29 round (day 1). They raise 2 824 alerts from 81
rules, and for every rule these are the same events that an independent Sigma
engine finds (pySigma's SQLite backend, the one Zircolite runs on). The run
takes 23 s on one core of a laptop.

## What a rule becomes

The PsExec rule from SigmaHQ, reduced to its selection:

```yaml
title: PsExec Execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: ['\PsExec.exe', '\PsExec64.exe']
        - OriginalFileName: 'psexec.c'
    condition: selection
level: high
```

```vpl
# PsExec Execution
stream PsExecExecution = SysmonProcessCreate
    .where(ends_with(lower(Image), '\psexec.exe') or ends_with(lower(Image), '\psexec64.exe') or lower(OriginalFileName) == 'psexec.c')
    .emit(
        rule: 'PsExec Execution',
        sigma_id: '730fc21b-eaff-474b-ad23-90fd265d4988',
        level: 'high',
        mitre: 'T1569.002,T1021.002',
        Image: Image,
        OriginalFileName: OriginalFileName,
        Computer: Computer,
        Hostname: Hostname,
        User: User,
        CommandLine: CommandLine,
        ParentImage: ParentImage,
        ParentCommandLine: ParentCommandLine
    )
```

The fields after the rule's own are the ones an analyst needs to act on a
process alert; one the event does not carry is left out of the alert.

Rename `PsExec.exe` to `svcupdate.exe` and that rule goes quiet. The behaviour
does not change though (an SMB connection, then a process that `services.exe`
starts on the target), and that is a two-rule correlation:

```yaml
correlation:
    type: temporal_ordered
    rules:
        - smb_connection     # DestinationPort: 445
        - service_child      # ParentImage|endswith: '\services.exe'
    timespan: 2m
```

```vpl
stream LateralMovementOverSMBJudgedOnBehaviour = SmbConnection as a
    -> ServiceChild as b
    .within(2m)
    .emit(
        rule: 'Lateral movement over SMB, judged on behaviour',
        level: 'critical',
        SmbConnection_Hostname: a.Hostname,
        ServiceChild_Hostname: b.Hostname,
        ServiceChild_CommandLine: b.CommandLine
        # ... and the other context fields of both events
    )
```

Both files are in [`tests/rules`](tests/rules), and
[`tests/test_on_varpulis.py`](tests/test_on_varpulis.py) runs them through the
engine: the file name rule fires on PsExec and stays silent on the renamed
copy, the correlation catches the renamed copy across the two hosts.

## How things map

| Sigma | VPL |
|---|---|
| a value (case-insensitive, as Sigma specifies) | `lower(Field) == 'value'` |
| `startswith`, `endswith`, `contains` | `starts_with(lower(F), '...')` and friends |
| `cased` | the same without `lower()` |
| wildcards inside a value | `regex_match(F, '(?is)^...$')` |
| `re` (with `i`, `m`, `s`) | `regex_match(F, '(?i)...')` |
| numbers, `gt`/`gte`/`lt`/`lte` | `F == 4625`, `F >= 1000` |
| `null`, `exists` | `is_null(F)`, `not is_null(F)` |
| `cidr` | prefix matches (`starts_with(lower(F), '10.')`) |
| `fieldref` (and with `startswith`, `endswith`, `contains`) | `F == G`, `contains(F, G)` |
| a field name that is not an identifier (`cs-uri-query`) | `` `cs-uri-query` `` |
| keywords (a value with no field), with `-O keyword_field=message` | `contains(lower(message), 'value')` |
| `temporal_ordered` | a sequence `A as a -> B where g == a.g as b .within(T)` |
| `temporal` | that sequence in every order of its rules, up to three; over three, the distinct rules seen per group in a window of the timespan (`merge(...).window(T).aggregate(rules: count_distinct(sigma_rule))`) |
| `event_count`, `value_count` | `.partition_by(g).window(T).aggregate(n: count())`, or `count_distinct(field)` |
| `value_sum`, `value_avg` | `sum(field)`, `avg(field)` |

Values are written as single-quoted VPL strings, which are raw: a backslash
is only a backslash, so `'\AppData\Local\Temp\'` goes through exactly as the
rule wrote it, and `''` stands for a quote.

A condition on a field the event does not carry is false, and `not` of it is
true, so `selection and not filter` keeps an event that lacks the filter's
field. That is how Splunk and Elasticsearch behave too, which matters when you
compare the alerts of a converted rule with the ones your SIEM raised.

The event type comes from the log source. Windows categories take the names
`varpulis simulate` gives Sysmon events (`SysmonProcessCreate`,
`SysmonNetworkConnect`, ...). A category that covers several Sysmon events
reads all of them: `registry_event` is events 12, 13 and 14, as in pySigma's
Sysmon pipeline, so the rule reads
`merge(SysmonRegistryAddDel, SysmonRegistryValueSet, Sysmon14)`. The
PowerShell categories are one event of their channel: `ps_script` reads
`WindowsPowershell` and tests `EventID == 4104`. Any other log source is its
product and service or category in CamelCase (`WindowsSecurity`,
`LinuxProcessCreation`, `Proxy`). `-O event_type=MyEvents` forces one type for
every rule.

Every alert from a Windows log source says which machine it came from:
`Computer`, or `Hostname`, whichever the event carries.

## Options

| Option | Default | Meaning |
|---|---|---|
| `-O event_type=X` | from the log source | read every rule from event type `X` |
| `-O keyword_field=F` | none | the field that holds the log line, where keywords are searched |
| `-O dots=flat` | `nested` | read `id.orig_h` as one flat key instead of a path into nested objects |
| `-O subject_prefix=P` (`-f vejas`) | `logs` | event type `T` is read from the subject `P.T` |
| `-O alert_subject=S` (`-f vejas`) | `alerts.sigma` | where alerts are published |

## What does not convert, and why

- **Keyword detections** (a value with no field), unless you name the field
  that holds the log line with `-O keyword_field=message`. An event has no
  text of all its fields to search.
- **PCRE-only regular expressions.** The engine uses Rust's `regex`, which
  matches in linear time whatever the input and so has no look-around and no
  back-references. The conversion refuses such a rule and says which construct
  it met, rather than emitting a pattern that would never compile.
- **A dotted field name is a path**: `process.parent.name` reads nested
  objects. If your events carry flat keys with dots in them (Zeek's JSON
  writes `id.orig_h` that way), pass `-O dots=flat`.
- **A correlation over a `temporal` of up to three rules**, which is one
  sequence per order of its rules rather than one stream to read. A
  correlation over any other correlation (a count, a `temporal_ordered`, a
  `temporal` over more rules) is converted, and reads that correlation's
  alerts.
- **`value_percentile`, `value_median`**, timestamp-part modifiers.

Three behaviours to know about. Count correlations, and `temporal` over more
than three rules, use tumbling windows, the way the Splunk and Elasticsearch
backends bucket time, so a burst that straddles a window boundary is counted
in two halves. Such a window closes, and its alert goes out, on the next event
of its log source past its end, whichever rule or group that event belongs
to: a brute force counted per address fires even when the attacker got in and
stopped (Varpulis `main` from 2026-09-24; before, it waited for a later event
of the same rule and group). Sequences (`temporal_ordered`, and `temporal` up
to three rules) alert as their last event arrives. And a `temporal` sequence
can alert twice when its events come in both orders (A, B, A).

Correlation rules may come in any order, a directory included: the backend
converts every rule after the rules it refers to. (pySigma's own sort can
leave a correlation ahead of its rules, and every backend then fails with
"Conversion result not available".)

## Testing a conversion on your own logs

```bash
sigma convert -t varpulis my_rules/ > rules.vpl
varpulis check rules.vpl
varpulis simulate -p rules.vpl -e events.jsonl -w 1
```

Each JSON line is one event. Sysmon lines (`EventID` and `Channel`) are typed
automatically; anything else needs a `"type"` naming the event type the rule
reads, and an `@timestamp`, since sequences and windows are judged in the time
the events carry. For Windows event logs that means one type per channel,
the way a shipper sends each channel to its own subject:

| Channel | Event type |
|---|---|
| `Security` | `WindowsSecurity` |
| `System` | `WindowsSystem` |
| `Microsoft-Windows-PowerShell/Operational` | `WindowsPowershell` |
| `Windows PowerShell` | `WindowsPowershellClassic` |
| `Microsoft-Windows-WMI-Activity/Operational` | `WindowsWmi` |

and so on, after the channel's Sigma service. [`bench/prep.py`](bench/prep.py)
does exactly that to the APT29 dataset.

## Development

```bash
pip install -e '.[test]'
VARPULIS_BIN=/path/to/varpulis pytest
```

Without a `varpulis` binary the engine tests are skipped, and pytest says so.

## License

MIT.
