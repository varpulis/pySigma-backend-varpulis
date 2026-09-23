"""How a Sigma detection becomes a VPL `.where()`."""

import re

import pytest
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError

from sigma.backends.varpulis import VarpulisBackend


def convert(yaml_text: str, **options) -> str:
    return VarpulisBackend(**options).convert(SigmaCollection.from_yaml(yaml_text))


def rule(detection: str, logsource: str = "category: process_creation\n    product: windows") -> str:
    return f"""
title: Test rule
id: 1b0b2c3d-0000-4000-8000-000000000001
status: test
logsource:
    {logsource}
detection:
{detection}
level: medium
"""


def where(yaml_text: str, **options) -> str:
    program = convert(yaml_text, **options)
    m = re.search(r"^    \.where\((.*)\)$", program, re.M)
    assert m, program
    return m.group(1)


def test_plain_value_is_compared_case_insensitively():
    assert where(rule("    sel:\n        Image: 'C:\\Windows\\PsExec.exe'\n    condition: sel")) == (
        "lower(Image) == 'c:\\windows\\psexec.exe'"
    )


def test_modifiers_become_string_functions():
    assert where(rule("    sel:\n        Image|endswith: '\\PsExec.exe'\n    condition: sel")) == (
        "ends_with(lower(Image), '\\psexec.exe')"
    )
    assert where(rule("    sel:\n        Image|startswith: 'C:\\Users\\'\n    condition: sel")) == (
        "starts_with(lower(Image), 'c:\\users\\')"
    )
    assert where(rule("    sel:\n        CommandLine|contains: ' -enc '\n    condition: sel")) == (
        "contains(lower(CommandLine), ' -enc ')"
    )


def test_a_value_may_end_in_a_backslash():
    # The case a double-quoted VPL string cannot express, and a raw
    # single-quoted one can.
    assert where(rule("    sel:\n        Image|contains: '\\AppData\\Local\\Temp\\'\n    condition: sel")) == (
        "contains(lower(Image), '\\appdata\\local\\temp\\')"
    )


def test_a_quote_in_a_value_is_doubled():
    assert where(rule("    sel:\n        CommandLine|contains: \"it's\"\n    condition: sel")) == (
        "contains(lower(CommandLine), 'it''s')"
    )


def test_inner_wildcards_become_an_anchored_regex():
    # In Sigma `\\*` is an escaped, literal asterisk; `x*` is the wildcard.
    assert where(rule("    sel:\n        Image: 'C:\\Users\\x*\\svc?.exe'\n    condition: sel")) == (
        "regex_match(Image, '(?is)^c:\\\\users\\\\x.*\\\\svc.\\.exe$')"
    )
    assert where(rule("    sel:\n        Image: 'C:\\*'\n    condition: sel")) == "lower(Image) == 'c:*'"


def test_a_lone_wildcard_means_the_field_is_there():
    assert where(rule("    sel:\n        Image: '*'\n    condition: sel")) == "not is_null(Image)"


def test_cased_values_are_not_lowered():
    assert where(rule("    sel:\n        Image|cased: 'PsExec.exe'\n    condition: sel")) == "Image == 'PsExec.exe'"
    assert where(rule("    sel:\n        Image|cased|endswith: '\\PsExec.exe'\n    condition: sel")) == (
        "ends_with(Image, '\\PsExec.exe')"
    )


def test_regular_expressions_keep_their_text_and_flags():
    assert where(rule("    sel:\n        CommandLine|re: '\\s-e(nc)?\\s'\n    condition: sel")) == (
        "regex_match(CommandLine, '\\s-e(nc)?\\s')"
    )
    assert where(rule("    sel:\n        CommandLine|re|i: 'invoke-\\w+'\n    condition: sel")) == (
        "regex_match(CommandLine, '(?i)invoke-\\w+')"
    )


@pytest.mark.parametrize("pattern", ["powershell(?!.*-nop)", "(?<=x)y", "(a)\\1"])
def test_pcre_only_constructs_are_refused_with_the_reason(pattern):
    with pytest.raises(SigmaError, match="does not support"):
        convert(rule(f"    sel:\n        CommandLine|re: '{pattern}'\n    condition: sel"))


def test_numbers_comparisons_null_and_existence():
    assert where(rule("    sel:\n        EventID: 4688\n    condition: sel")) == "EventID == 4688"
    assert where(rule("    sel:\n        Size|gte: 1000\n    condition: sel")) == "Size >= 1000"
    assert where(rule("    sel:\n        CommandLine: null\n    condition: sel")) == "is_null(CommandLine)"
    assert where(rule("    sel:\n        CommandLine|exists: true\n    condition: sel")) == (
        "not is_null(CommandLine)"
    )
    assert where(rule("    sel:\n        User|fieldref: TargetUser\n    condition: sel")) == "User == TargetUser"
    assert where(rule("    sel:\n        CommandLine|fieldref|contains: TargetUser\n    condition: sel")) == (
        "contains(CommandLine, TargetUser)"
    )


def test_cidr_expands_to_prefixes():
    assert where(
        rule(
            "    sel:\n        DestinationIp|cidr: 10.0.0.0/8\n    condition: sel",
            "category: network_connection\n    product: windows",
        )
    ) == "starts_with(lower(DestinationIp), '10.')"


def test_lists_conditions_and_filters():
    w = where(
        rule(
            "    selection:\n"
            "        Image|endswith:\n"
            "            - '\\PsExec.exe'\n"
            "            - '\\PsExec64.exe'\n"
            "    filter:\n"
            "        ParentImage|endswith: '\\msiexec.exe'\n"
            "    condition: selection and not filter"
        )
    )
    assert w == (
        "(ends_with(lower(Image), '\\psexec.exe') or ends_with(lower(Image), '\\psexec64.exe'))"
        " and not ends_with(lower(ParentImage), '\\msiexec.exe')"
    )
    assert where(rule("    sel:\n        CommandLine|contains|all:\n            - ' -w '\n            - hidden\n    condition: sel")) == (
        "contains(lower(CommandLine), ' -w ') and contains(lower(CommandLine), 'hidden')"
    )


def test_keyword_searches_need_the_field_that_holds_the_line():
    with pytest.raises(SigmaError, match="keyword_field"):
        convert(rule("    keywords:\n        - mimikatz\n    condition: keywords"))
    assert where(
        rule("    keywords:\n        - mimikatz\n        - 'sekurlsa::*'\n    condition: keywords"),
        keyword_field="message",
    ) == "contains(lower(message), 'mimikatz') or contains(lower(message), 'sekurlsa::')"


def test_a_field_name_that_is_not_an_identifier_goes_between_backticks():
    program = convert(rule("    sel:\n        cs-uri-query|contains: 'cmd='\n    condition: sel", "category: webserver"))
    assert "    .where(contains(lower(`cs-uri-query`), 'cmd='))\n" in program
    # The alert's own names stay identifiers.
    assert "cs_uri_query: `cs-uri-query`" in program
    assert "c_ip: `c-ip`" in program


def test_dots_can_be_one_flat_key():
    w = where(
        rule("    sel:\n        id.orig_h: 10.0.0.5\n    condition: sel", "product: zeek\n    service: conn"),
        dots="flat",
    )
    assert w == "lower(`id.orig_h`) == '10.0.0.5'"


def test_dots_read_nested_objects():
    assert where(rule("    sel:\n        process.parent.name: cmd.exe\n    condition: sel")) == (
        "lower(process.parent.name) == 'cmd.exe'"
    )


@pytest.mark.parametrize(
    "logsource, event_type",
    [
        ("category: process_creation\n    product: windows", "SysmonProcessCreate"),
        ("category: network_connection\n    product: windows", "SysmonNetworkConnect"),
        ("category: registry_set\n    product: windows", "SysmonRegistryValueSet"),
        (
            "category: registry_event\n    product: windows",
            "merge(SysmonRegistryAddDel, SysmonRegistryValueSet, Sysmon14)",
        ),
        ("category: pipe_created\n    product: windows", "merge(SysmonPipeCreated, SysmonPipeConnected)"),
        ("category: ps_script\n    product: windows", "WindowsPowershell"),
        ("category: ps_classic_start\n    product: windows", "WindowsPowershellClassic"),
        ("product: windows\n    service: powershell", "WindowsPowershell"),
        ("product: windows\n    service: security", "WindowsSecurity"),
        ("category: process_creation\n    product: linux", "LinuxProcessCreation"),
        ("category: proxy", "Proxy"),
    ],
)
def test_event_type_follows_the_log_source(logsource, event_type):
    program = convert(rule("    sel:\n        Image: x\n    condition: sel", logsource))
    assert f"stream TestRule = {event_type}\n" in program


def test_a_powershell_category_is_its_channel_and_event_id():
    assert where(
        rule("    sel:\n        ScriptBlockText|contains: x\n    condition: sel", "category: ps_script\n    product: windows")
    ) == "EventID == 4104 and (contains(lower(ScriptBlockText), 'x'))"
    assert where(
        rule("    sel:\n        Data|contains: x\n    condition: sel", "category: ps_classic_start\n    product: windows")
    ) == "EventID == 400 and (contains(lower(Data), 'x'))"


def test_a_rule_over_several_sysmon_events_carries_the_context_of_each():
    program = convert(rule("    sel:\n        TargetObject|contains: x\n    condition: sel", "category: registry_event\n    product: windows"))
    assert "Details: Details" in program
    assert "TargetObject: TargetObject" in program


@pytest.mark.parametrize(
    "logsource",
    [
        "product: windows\n    service: security",
        "category: ps_script\n    product: windows",
        "category: raw_access_thread\n    product: windows",
        "product: windows\n    service: system",
    ],
)
def test_every_windows_alert_says_which_machine(logsource):
    program = convert(rule("    sel:\n        Data: x\n    condition: sel", logsource))
    assert "Computer: Computer" in program
    assert "Hostname: Hostname" in program


def test_event_type_can_be_forced():
    program = convert(rule("    sel:\n        Image: x\n    condition: sel"), event_type="ProcessEvents")
    assert "stream TestRule = ProcessEvents\n" in program


def test_the_alert_names_the_rule_and_carries_what_an_analyst_needs():
    program = convert(rule("    sel:\n        Image|endswith: '\\PsExec.exe'\n    condition: sel"))
    assert "rule: 'Test rule'" in program
    assert "sigma_id: '1b0b2c3d-0000-4000-8000-000000000001'" in program
    assert "level: 'medium'" in program
    for f in ["Image: Image", "Computer: Computer", "CommandLine: CommandLine", "ParentImage: ParentImage"]:
        assert f in program


def test_the_vejas_format_binds_sources_and_alerts_to_the_bus():
    program = VarpulisBackend(subject_prefix="sysmon", alert_subject="alerts.soc").convert(
        SigmaCollection.from_yaml(rule("    sel:\n        Image: x\n    condition: sel")), "vejas"
    )
    assert "connector Bus = nats" in program
    assert "stream SysmonProcessCreateSource = SysmonProcessCreate\n    .from(Bus, topic: 'sysmon.SysmonProcessCreate')" in program
    assert "stream TestRule = SysmonProcessCreateSource\n" in program
    assert "    .to(Bus, topic: 'alerts.soc')" in program


def test_the_vejas_format_merges_the_sources_of_a_rule_over_several_events():
    program = VarpulisBackend().convert(
        SigmaCollection.from_yaml(
            rule("    sel:\n        TargetObject: x\n    condition: sel", "category: registry_event\n    product: windows")
        ),
        "vejas",
    )
    for t in ["SysmonRegistryAddDel", "SysmonRegistryValueSet", "Sysmon14"]:
        assert f"stream {t}Source = {t}\n    .from(Bus, topic: 'logs.{t}')" in program
    assert "stream TestRule = merge(SysmonRegistryAddDelSource, SysmonRegistryValueSetSource, Sysmon14Source)\n" in program
