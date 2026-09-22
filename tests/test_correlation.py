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


def test_temporal_over_four_rules_is_refused():
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
    with pytest.raises(SigmaError, match="temporal_ordered"):
        convert(yaml_text)
