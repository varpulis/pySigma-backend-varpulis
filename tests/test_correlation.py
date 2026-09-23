"""How a Sigma correlation becomes a VPL sequence or windowed aggregate."""

import pytest
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError

from sigma.backends.varpulis import VarpulisBackend

BASE = """
title: Outbound SMB connection
name: smb_connection
id: 2b0b2c3d-0000-4000-8000-000000000001
status: test
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        DestinationPort: 445
    condition: selection
---
title: Process started by services.exe
name: service_child
id: 2b0b2c3d-0000-4000-8000-000000000002
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\\services.exe'
    condition: selection
"""


def convert(yaml_text: str) -> str:
    return VarpulisBackend().convert(SigmaCollection.from_yaml(yaml_text))


def correlation(body: str) -> str:
    return BASE + f"""---
title: Correlated
id: 2b0b2c3d-0000-4000-8000-0000000000ff
status: test
correlation:
{body}
level: high
"""


def test_temporal_ordered_is_a_sequence_within_the_timespan():
    program = convert(
        correlation(
            "    type: temporal_ordered\n    rules:\n        - smb_connection\n        - service_child\n"
            "    group-by:\n        - Computer\n    timespan: 2m"
        )
    )
    assert "stream Correlated = SmbConnection as a\n    -> ServiceChild where Computer == a.Computer as b\n" in program
    assert "    .within(2m)\n    .partition_by(Computer)\n" in program
    assert "Computer: a.Computer" in program
    # The referenced rules are filters the sequence reads, not alerts of
    # their own (Sigma's `generate` defaults to false).
    assert "stream SmbConnection = SysmonNetworkConnect\n    .where(DestinationPort == 445)\n\n" in program


def test_aliases_name_the_group_key_per_rule_and_drop_the_partition():
    program = convert(
        correlation(
            "    type: temporal_ordered\n    rules:\n        - smb_connection\n        - service_child\n"
            "    group-by:\n        - host\n    timespan: 2m\n"
            "    aliases:\n        host:\n            smb_connection: DestinationHostname\n"
            "            service_child: Computer"
        )
    )
    assert "-> ServiceChild where Computer == a.DestinationHostname as b" in program
    assert ".partition_by(" not in program
    assert "host: a.DestinationHostname" in program


def test_temporal_is_the_sequence_in_every_order():
    program = convert(
        correlation(
            "    type: temporal\n    rules:\n        - smb_connection\n        - service_child\n"
            "    group-by:\n        - Computer\n    timespan: 10m"
        )
    )
    assert "stream Correlated = SmbConnection as a\n    -> ServiceChild where Computer == a.Computer as b" in program
    assert "stream Correlated2 = ServiceChild as a\n    -> SmbConnection where Computer == a.Computer as b" in program


def test_event_count_is_a_windowed_count_per_group():
    program = convert(
        correlation(
            "    type: event_count\n    rules:\n        - service_child\n"
            "    group-by:\n        - Computer\n    timespan: 5m\n    condition:\n        gte: 10"
        )
    )
    assert (
        "stream Correlated = ServiceChild\n    .partition_by(Computer)\n    .window(5m)\n"
        "    .aggregate(Computer: last(Computer), n: count())\n    .where(n >= 10)\n"
    ) in program


def test_value_count_counts_distinct_values():
    program = convert(
        correlation(
            "    type: value_count\n    rules:\n        - smb_connection\n"
            "    group-by:\n        - Computer\n    timespan: 1h\n    condition:\n        field: DestinationIp\n        gt: 20"
        )
    )
    assert "    .aggregate(Computer: last(Computer), n: count_distinct(DestinationIp))\n    .where(n > 20)\n" in program


def test_generate_keeps_the_referenced_rules_as_alerts():
    program = convert(
        correlation(
            "    type: temporal_ordered\n    rules:\n        - smb_connection\n        - service_child\n"
            "    timespan: 2m\n    generate: true"
        )
    )
    assert "stream SmbConnection = SysmonNetworkConnect\n    .where(DestinationPort == 445)\n    .emit(" in program


def test_temporal_over_four_rules_counts_the_distinct_rules_seen_in_a_window():
    extra = "".join(
        f"""---
title: Extra {i}
name: extra_{i}
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: x{i}
    condition: selection
"""
        for i in (1, 2)
    )
    yaml_text = BASE + extra + """---
title: Too many
status: test
correlation:
    type: temporal
    rules: [smb_connection, service_child, extra_1, extra_2]
    timespan: 5m
"""
    program = convert(yaml_text)
    assert "stream TooMany_Extra1 = Extra1\n    .select(sigma_rule: 'Extra1')" in program
    assert (
        "stream TooMany = merge(TooMany_SmbConnection, TooMany_ServiceChild, TooMany_Extra1, TooMany_Extra2)\n"
        "    .window(5m)\n    .aggregate(rules: count_distinct(sigma_rule))\n    .where(rules >= 4)\n"
    ) in program


def test_a_correlation_ahead_of_the_rules_it_refers_to_still_converts():
    # A directory is read in the file system's order, and pySigma's sort (a
    # partial order) can leave a correlation ahead of its rules: the
    # conversion then failed with "Conversion result not available".
    text = correlation(
        "    type: temporal_ordered\n    rules:\n        - smb_connection\n        - service_child\n"
        "    timespan: 2m"
    )
    rules = text.split("\n---\n")
    unrelated = rules[0].replace("smb_connection", "unrelated").replace("-000000000001", "-0000000000aa")
    program = convert("\n---\n".join([rules[2], unrelated, rules[0], rules[1]]))
    assert "stream Correlated = SmbConnection as a\n    -> ServiceChild as b\n" in program


def test_a_count_over_a_sequence_reads_the_sequence_alerts():
    text = correlation(
        "    type: temporal_ordered\n    rules:\n        - smb_connection\n        - service_child\n"
        "    timespan: 2m"
    ).replace("title: Correlated\n", "title: Correlated\nname: correlated\n")
    outer = """title: Outer
id: 2b0b2c3d-0000-4000-8000-0000000000fe
status: test
correlation:
    type: event_count
    rules:
        - correlated
    timespan: 1h
    condition:
        gte: 2
level: high
"""
    rules = text.split("\n---\n")
    program = convert("\n---\n".join([outer, rules[2], rules[1], rules[0]]))
    assert program.index("stream Correlated =") < program.index("stream Outer =")
    assert "stream Outer = Correlated\n    .window(1h)\n    .aggregate(n: count())\n    .where(n >= 2)\n" in program


def test_a_sequence_over_a_count_reads_the_count_alerts():
    text = correlation(
        "    type: event_count\n    rules:\n        - smb_connection\n    timespan: 30s\n"
        "    condition:\n        gte: 3"
    ).replace("title: Correlated\n", "title: Correlated\nname: correlated\n")
    outer = """title: Outer
status: test
correlation:
    type: temporal_ordered
    rules:
        - correlated
        - service_child
    timespan: 2m
"""
    program = convert(text + "---\n" + outer)
    assert "stream Correlated = SmbConnection\n    .window(30s)" in program
    assert "stream Outer = Correlated as a\n    -> ServiceChild as b\n" in program


def test_a_correlation_over_a_temporal_of_up_to_three_rules_is_refused_with_the_reason():
    text = correlation(
        "    type: temporal\n    rules:\n        - smb_connection\n        - service_child\n"
        "    timespan: 2m"
    ).replace("title: Correlated\n", "title: Correlated\nname: correlated\n")
    outer = """title: Outer
status: test
correlation:
    type: event_count
    rules:
        - correlated
    timespan: 1h
    condition:
        gte: 2
"""
    with pytest.raises(SigmaError, match="a sequence per order of its rules"):
        convert(text + "---\n" + outer)
