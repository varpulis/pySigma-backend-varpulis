"""Sigma to VPL, the rule language of the Varpulis detection engine.

A Sigma rule becomes a stream: the rule's condition in a `.where()`, and an
`.emit()` that carries the rule's identity and the fields it looked at. A
correlation rule becomes what VPL has natively instead of a search pipeline:

* `temporal_ordered` is a sequence, `A as a -> B where host == a.host as b`,
  judged in the time the events carry (`.within()`);
* `temporal` (any order) is the same sequence in every order of its rules;
* `event_count` and `value_count` are a windowed aggregate per group.

String matching is case-insensitive unless the rule says `|cased`, as Sigma
specifies: the field is lowered and the value is lowered here. Values are
written as single-quoted VPL strings, which are raw (a backslash is a
backslash, even last, and `''` is one quote), so a Windows path goes through
exactly as the rule wrote it.
"""

from __future__ import annotations

import itertools
import re
from dataclasses import dataclass, field
from typing import Any, ClassVar

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionItem,
    ConditionNOT,
    ConditionOR,
)
from sigma.conversion.base import TextQueryBackend
from sigma.conversion.state import ConversionState
from sigma.correlations import (
    SigmaCorrelationConditionOperator,
    SigmaCorrelationRule,
    SigmaCorrelationType,
)
from sigma.exceptions import SigmaConversionError, SigmaError, SigmaFeatureNotSupportedByBackendError
from sigma.rule import SigmaRule
from sigma.types import (
    CompareOperators,
    SigmaCompareExpression,
    SigmaRegularExpression,
    SigmaRegularExpressionFlag,
    SigmaString,
    SpecialChars,
)

# ---------------------------------------------------------------------------
# Event types
# ---------------------------------------------------------------------------

#: Sysmon categories, named as `varpulis simulate` names Sysmon events it
#: reads from JSON lines (by `EventID` on the Sysmon channel). A category that
#: covers several Sysmon events (`registry_event` is events 12, 13 and 14, as
#: in pySigma's Sysmon pipeline) reads all of their types.
SYSMON_EVENT_TYPES: dict[str, str | tuple[str, ...]] = {
    "process_creation": "SysmonProcessCreate",
    "file_change": "SysmonFileCreateTime",
    "network_connection": "SysmonNetworkConnect",
    "process_termination": "SysmonProcessTerminate",
    "driver_load": "Sysmon6",
    "image_load": "SysmonImageLoad",
    "create_remote_thread": "SysmonCreateRemoteThread",
    "raw_access_thread": "Sysmon9",
    "process_access": "SysmonProcessAccess",
    "file_event": "SysmonFileCreate",
    "registry_add": "SysmonRegistryAddDel",
    "registry_delete": "SysmonRegistryAddDel",
    "registry_set": "SysmonRegistryValueSet",
    "registry_rename": "Sysmon14",
    "registry_event": ("SysmonRegistryAddDel", "SysmonRegistryValueSet", "Sysmon14"),
    "create_stream_hash": "SysmonFileCreateStreamHash",
    "pipe_created": ("SysmonPipeCreated", "SysmonPipeConnected"),
    "wmi_event": ("Sysmon19", "Sysmon20", "Sysmon21"),
    "dns_query": "SysmonDnsQuery",
    "file_delete": "SysmonFileDelete",
    "clipboard_capture": "Sysmon24",
    "process_tampering": "Sysmon25",
    "file_delete_detected": "Sysmon26",
    "file_block_executable": "Sysmon27",
    "file_block_shredding": "Sysmon28",
    "file_executable_detected": "Sysmon29",
    "sysmon_status": ("Sysmon4", "Sysmon16"),
    "sysmon_error": "Sysmon255",
}

#: Windows categories that are one event of a channel, as the Sigma taxonomy
#: defines them: the rule reads the channel's event type (`ps_script` reads
#: `WindowsPowershell`, the type of every line of that channel) and tests the
#: EventID, so a rule written for the channel sees the same lines.
WINDOWS_CHANNEL_EVENTS: dict[str, tuple[str, int]] = {
    "ps_module": ("powershell", 4103),
    "ps_script": ("powershell", 4104),
    "ps_classic_start": ("powershell-classic", 400),
    "ps_classic_provider_start": ("powershell-classic", 600),
    "ps_classic_script": ("powershell-classic", 800),
}

#: Fields an analyst needs to act on an alert, per event type. They are added
#: to the rule's own fields in every `.emit()`; one the event does not carry is
#: left out of the alert, so listing both `Computer` (Windows event logs) and
#: `Hostname` (some exports) costs nothing.
CONTEXT_FIELDS: dict[str, list[str]] = {
    "SysmonProcessCreate": ["Computer", "Hostname", "User", "Image", "CommandLine", "ParentImage", "ParentCommandLine"],
    "SysmonNetworkConnect": ["Computer", "Hostname", "User", "Image", "SourceIp", "DestinationIp", "DestinationPort", "DestinationHostname"],
    "SysmonImageLoad": ["Computer", "Hostname", "Image", "ImageLoaded"],
    "SysmonCreateRemoteThread": ["Computer", "Hostname", "SourceImage", "TargetImage"],
    "SysmonProcessAccess": ["Computer", "Hostname", "SourceImage", "TargetImage", "GrantedAccess"],
    "SysmonFileCreate": ["Computer", "Hostname", "Image", "TargetFilename"],
    "SysmonFileDelete": ["Computer", "Hostname", "Image", "TargetFilename"],
    "SysmonRegistryAddDel": ["Computer", "Hostname", "Image", "TargetObject"],
    "SysmonRegistryValueSet": ["Computer", "Hostname", "Image", "TargetObject", "Details"],
    "SysmonDnsQuery": ["Computer", "Hostname", "Image", "QueryName"],
    "SysmonPipeCreated": ["Computer", "Hostname", "Image", "PipeName"],
    "WindowsSecurity": ["Computer", "EventID", "SubjectUserName", "TargetUserName", "IpAddress", "WorkstationName", "LogonType"],
    "Proxy": ["c-ip", "cs-username", "cs-method", "cs-host", "c-uri", "sc-status", "c-useragent"],
    "Webserver": ["c-ip", "cs-method", "cs-uri-stem", "cs-uri-query", "sc-status", "cs-user-agent"],
}

VPL_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def camel(*words: str | None) -> str:
    """`('windows', 'process_creation')` -> `WindowsProcessCreation`."""
    parts = []
    for word in words:
        if word:
            parts.extend(p for p in re.split(r"[^A-Za-z0-9]+", word) if p)
    name = "".join(p[:1].upper() + p[1:] for p in parts)
    if not name or not name[0].isalpha():
        name = "Event" + name
    return name


def event_types_for(rule: SigmaRule | None) -> list[str]:
    """The VPL event types a rule's log source is read from.

    Windows categories are Sysmon's (the names `varpulis simulate` gives Sysmon
    JSON lines), several of them for a category that covers several Sysmon
    events; the PowerShell categories are their channel. Anything else is the
    log source in CamelCase, product first: `windows`/`security` is
    `WindowsSecurity`, `linux`/`process_creation` is `LinuxProcessCreation`,
    `proxy` is `Proxy`.
    """
    if rule is None:
        return ["Event"]
    ls = rule.logsource
    if ls.product == "windows" and not ls.service:
        if ls.category in SYSMON_EVENT_TYPES:
            types = SYSMON_EVENT_TYPES[ls.category]
            return [types] if isinstance(types, str) else list(types)
        if ls.category in WINDOWS_CHANNEL_EVENTS:
            return [camel("windows", WINDOWS_CHANNEL_EVENTS[ls.category][0])]
    return [camel(ls.product, ls.service or ls.category) if (ls.product or ls.service or ls.category) else "Event"]


def channel_event_id(rule: SigmaRule) -> int | None:
    """The EventID a Windows category stands for within its channel."""
    ls = rule.logsource
    if ls.product == "windows" and not ls.service and ls.category in WINDOWS_CHANNEL_EVENTS:
        return WINDOWS_CHANNEL_EVENTS[ls.category][1]
    return None


#: Where a Windows event happened: `Computer` in Windows event logs, `Hostname`
#: in some exports (NXLog, the OTRF/Mordor datasets). Every alert from a
#: Windows log source carries whichever the event has.
WINDOWS_HOST: list[str] = ["Computer", "Hostname"]


def context_fields(event_types: list[str]) -> list[str]:
    fields: list[str] = []
    for t in event_types:
        if t.startswith(("Windows", "Sysmon")):
            fields += WINDOWS_HOST
        fields += CONTEXT_FIELDS.get(t, [])
    return list(dict.fromkeys(fields))


def vpl_str(text: str) -> str:
    """A raw single-quoted VPL string: nothing escapes, `''` is one quote."""
    return "'" + text.replace("'", "''") + "'"


def vpl_field(name: str) -> str:
    """How an expression reads a field: dots read nested objects, and a part
    that is not an identifier (`cs-uri-query`, W3C web and proxy logs) goes
    between backticks."""
    parts = []
    for part in name.split("."):
        if VPL_IDENTIFIER.match(part):
            parts.append(part)
        elif part and "`" not in part and "\n" not in part:
            parts.append(f"`{part}`")
        else:
            raise SigmaFeatureNotSupportedByBackendError(
                f"field '{name}' cannot be written in VPL: rename it with a processing pipeline"
            )
    return ".".join(parts)


def vpl_key(name: str) -> str:
    """A name the program gives (an emitted field, an aggregate): an
    identifier, so `cs-uri-query` becomes `cs_uri_query`."""
    key = re.sub(r"[^A-Za-z0-9_]", "_", name)
    return key if re.match(r"[A-Za-z_]", key) else "_" + key


# Characters with a meaning in Rust regex syntax. Rust accepts a backslash
# before any ASCII punctuation, so escaping these is always safe.
_RE_META = set("\\.+*?()|[]{}^$#&-~")


def re_escape(text: str) -> str:
    return "".join("\\" + c if c in _RE_META else c for c in text)


# PCRE constructs Rust's regex (linear time, no backtracking) refuses.
_UNSUPPORTED_RE = [
    (re.compile(r"\(\?[=!]"), "look-ahead"),
    (re.compile(r"\(\?<[=!]"), "look-behind"),
    (re.compile(r"(?<!\\)\\[1-9]"), "a back-reference"),
    (re.compile(r"\(\?>"), "an atomic group"),
    (re.compile(r"(?<!\\)[*+?}]\+"), "a possessive quantifier"),
]


def referenced_first(rules: list[Any]) -> list[Any]:
    """The rules in an order where each comes after every rule it refers to: a
    referenced rule moves up to just before the first rule that needs it, and
    the order is otherwise kept.

    pySigma sorts a collection with a comparison that is only a partial order
    ("A is referenced by B"), and a sort does not turn a partial order into a
    topological one: loaded from a directory, in the file system's order, a
    correlation could stay ahead of a rule it refers to, and converting it
    failed with "Conversion result not available" (SigmaHQ/pySigma#552)."""
    # Backreferences cover every way a rule refers to another: a correlation's
    # rules, and the rules an extended condition names.
    refers_to: dict[int, list[Any]] = {}
    for rule in rules:
        for referencing in getattr(rule, "_backreferences", []):
            refers_to.setdefault(id(referencing), []).append(rule)
    ordered: list[Any] = []
    placed: set[int] = set()

    def place(rule: Any) -> None:
        if id(rule) in placed:
            return
        placed.add(id(rule))
        for referenced in refers_to.get(id(rule), []):
            place(referenced)
        ordered.append(rule)

    for rule in rules:
        place(rule)
    return ordered


# ---------------------------------------------------------------------------
# What conversion produces, before it is written out as VPL
# ---------------------------------------------------------------------------


@dataclass
class VplRule:
    """A Sigma rule converted: one stream over one event type."""

    name: str
    title: str
    rule_id: str | None
    level: str | None
    event_types: list[str]
    where: str
    fields: list[str]
    mitre: list[str]
    output: bool = True
    #: The alerts of a correlation that another correlation refers to: its
    #: stream is the correlation's own, already written.
    correlation: bool = False


@dataclass
class VplCorrelation:
    """A correlation rule converted: one or more streams over rule streams."""

    title: str
    rule_id: str | None
    level: str | None
    rules: list[VplRule]
    streams: list[str] = field(default_factory=list)
    output: bool = True
    name: str = ""
    #: The fields its alerts carry besides the rule's identity (group-by keys).
    keys: list[str] = field(default_factory=list)
    #: Streams it reads that are not alerts (a `temporal` marks each rule's events).
    feeders: list[str] = field(default_factory=list)
    #: One sequence, alerting as its last event arrives (`temporal_ordered`).
    sequence: bool = False


# ---------------------------------------------------------------------------
# The backend
# ---------------------------------------------------------------------------


class VarpulisBackend(TextQueryBackend):
    """Convert Sigma rules, correlations included, into a VPL program."""

    name: ClassVar[str] = "Varpulis VPL"
    identifier: ClassVar[str] = "varpulis"
    formats: ClassVar[dict[str, str]] = {
        "default": "A VPL program, one stream per rule, runnable with `varpulis simulate`",
        "vejas": "A VPL program for a Vejas detect unit: log sources and alerts on the NATS bus",
    }
    requires_pipeline: ClassVar[bool] = False
    correlation_methods: ClassVar[dict[str, str]] = {
        "default": "Native VPL: a sequence for temporal rules, a windowed aggregate for counts",
    }
    default_correlation_method: ClassVar[str] = "default"
    # The correlation needs each referenced rule converted whole (its event
    # type, its name), not only its condition.
    finalize_correlation_subqueries: ClassVar[bool] = True

    precedence: ClassVar[tuple[type[ConditionItem], type[ConditionItem], type[ConditionItem]]] = (
        ConditionNOT,
        ConditionAND,
        ConditionOR,
    )
    group_expression: ClassVar[str] = "({expr})"
    token_separator: str = " "
    or_token: ClassVar[str] = "or"
    and_token: ClassVar[str] = "and"
    not_token: ClassVar[str] = "not"
    eq_token: ClassVar[str] = " == "

    wildcard_multi: ClassVar[str] = "*"
    wildcard_single: ClassVar[str] = "?"
    str_quote: ClassVar[str] = "'"
    bool_values: ClassVar[dict[bool, str | None]] = {True: "true", False: "false"}

    field_null_expression: ClassVar[str] = "is_null({field})"
    field_exists_expression: ClassVar[str] = "not is_null({field})"
    field_not_exists_expression: ClassVar[str] = "is_null({field})"
    compare_op_expression: ClassVar[str] = "{field} {operator} {value}"
    compare_operators: ClassVar[dict[CompareOperators, str]] = {
        CompareOperators.LT: "<",
        CompareOperators.LTE: "<=",
        CompareOperators.GT: ">",
        CompareOperators.GTE: ">=",
    }
    field_equals_field_expression: ClassVar[str] = "{field1} == {field2}"
    field_equals_field_startswith_expression: ClassVar[str] = "starts_with({field1}, {field2})"
    field_equals_field_endswith_expression: ClassVar[str] = "ends_with({field1}, {field2})"
    field_equals_field_contains_expression: ClassVar[str] = "contains({field1}, {field2})"
    field_equals_field_escaping_quoting: tuple[bool, bool] = (True, True)

    # No `in` operator: pySigma expands a list into `or`.
    field_in_list_expression: ClassVar[str | None] = None
    # Keyword searches (a value with no field) have no equivalent: an event
    # has no "all fields" string to search.
    unbound_value_str_expression: ClassVar[str | None] = None
    unbound_value_num_expression: ClassVar[str | None] = None
    unbound_value_re_expression: ClassVar[str | None] = None

    def __init__(self, processing_pipeline=None, collect_errors: bool = False, **backend_options: Any):
        super().__init__(processing_pipeline, collect_errors, **backend_options)
        self._names: dict[str, int] = {}

    def convert(self, rule_collection, output_format=None, correlation_method=None, callback=None):
        # pySigma resolves the references and sorts again; a list already in
        # reference order is one ascending run to its sort, so it stays.
        rule_collection.resolve_rule_references()
        rule_collection.rules = referenced_first(rule_collection.rules)
        return super().convert(rule_collection, output_format, correlation_method, callback)

    # --- fields ------------------------------------------------------------

    def escape_and_quote_field(self, field_name: str) -> str:
        return self._field(field_name)

    def _field(self, name: str) -> str:
        """`vpl_field`, except that with `-O dots=flat` a dotted name is one
        flat key (Zeek's JSON writes `id.orig_h` that way), read whole
        between backticks."""
        if str(self.backend_options.get("dots", "nested")) == "flat" and "." in name:
            if "`" in name or "\n" in name:
                raise SigmaFeatureNotSupportedByBackendError(
                    f"field '{name}' cannot be written in VPL: rename it with a processing pipeline"
                )
            return f"`{name}`"
        return vpl_field(name)

    # --- string values -----------------------------------------------------

    def _string_match(self, field_name: str, value: SigmaString, cased: bool) -> str:
        subject = field_name if cased else f"lower({field_name})"
        if not cased:
            value = value.lower()
        parts = []
        for part in value.iter_parts():
            # `**` matches what `*` matches: collapse, so the shape stays simple.
            if part == SpecialChars.WILDCARD_MULTI and parts and parts[-1] == SpecialChars.WILDCARD_MULTI:
                continue
            parts.append(part)
        texts = [p for p in parts if isinstance(p, str)]
        specials = [p for p in parts if not isinstance(p, str)]

        if not specials:
            return f"{subject} == {vpl_str(''.join(texts))}"
        if all(p == SpecialChars.WILDCARD_MULTI for p in specials):
            shape = tuple("*" if p == SpecialChars.WILDCARD_MULTI else "s" for p in parts)
            if shape == ("*",) or shape == ("*", "*"):
                return f"not is_null({field_name})"
            if shape == ("s", "*"):
                return f"starts_with({subject}, {vpl_str(parts[0])})"
            if shape == ("*", "s"):
                return f"ends_with({subject}, {vpl_str(parts[1])})"
            if shape == ("*", "s", "*"):
                return f"contains({subject}, {vpl_str(parts[1])})"
        # Any other shape of wildcards: an anchored regex over the raw field.
        pattern = []
        for p in parts:
            if isinstance(p, str):
                pattern.append(re_escape(p))
            elif p == SpecialChars.WILDCARD_MULTI:
                pattern.append(".*")
            else:
                pattern.append(".")
        flags = "(?s)" if cased else "(?is)"
        return f"regex_match({field_name}, {vpl_str(flags + '^' + ''.join(pattern) + '$')})"

    def convert_condition_field_eq_val_str(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> str:
        return self._string_match(self.escape_and_quote_field(cond.field), cond.value, cased=False)

    def convert_condition_field_eq_val_str_case_sensitive(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> str:
        return self._string_match(self.escape_and_quote_field(cond.field), cond.value, cased=True)

    def convert_condition_field_eq_val_re(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> str:
        regex: SigmaRegularExpression = cond.value
        pattern = str(regex.regexp)
        for check, what in _UNSUPPORTED_RE:
            if check.search(pattern):
                raise SigmaFeatureNotSupportedByBackendError(
                    f"the regular expression uses {what}, which the Varpulis regex engine "
                    f"(Rust regex, linear time) does not support: {pattern}"
                )
        flag_letters = {
            SigmaRegularExpressionFlag.IGNORECASE: "i",
            SigmaRegularExpressionFlag.MULTILINE: "m",
            SigmaRegularExpressionFlag.DOTALL: "s",
        }
        flags = "".join(sorted(flag_letters[f] for f in regex.flags))
        prefix = f"(?{flags})" if flags else ""
        return f"regex_match({self.escape_and_quote_field(cond.field)}, {vpl_str(prefix + pattern)})"

    def convert_condition_field_eq_val_num(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> str:
        return f"{self.escape_and_quote_field(cond.field)} == {cond.value}"

    def convert_condition_field_compare_op_val(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> str:
        value: SigmaCompareExpression = cond.value
        return self.compare_op_expression.format(
            field=self.escape_and_quote_field(cond.field),
            operator=self.compare_operators[value.op],
            value=value.number,
        )

    def _keyword_field(self) -> str:
        name = self.backend_options.get("keyword_field")
        if not name:
            raise SigmaFeatureNotSupportedByBackendError(
                "keyword detection (a value with no field): an event has no text of all its "
                "fields to search; name the field that holds the log line with "
                "-O keyword_field=message"
            )
        return self._field(str(name))

    def convert_condition_val_str(self, cond: Any, state: ConversionState) -> str:
        # A keyword matches anywhere in the line, as Sigma specifies.
        wildcard = SigmaString("*")
        return self._string_match(self._keyword_field(), wildcard + cond.value + wildcard, cased=False)

    def convert_condition_val_num(self, cond: Any, state: ConversionState) -> str:
        return f"contains(to_string({self._keyword_field()}), {vpl_str(str(cond.value))})"

    def convert_condition_val_re(self, cond: Any, state: ConversionState) -> str:
        field_name = self._keyword_field()
        return self.convert_condition_field_eq_val_re(
            ConditionFieldEqualsValueExpression(field_name, cond.value), state
        ).replace(f"regex_match({self._field(field_name)},", f"regex_match({field_name},", 1)

    # --- one rule ----------------------------------------------------------

    def _unique_name(self, wanted: str) -> str:
        n = self._names.get(wanted, 0) + 1
        self._names[wanted] = n
        return wanted if n == 1 else f"{wanted}{n}"

    def _stream_name(self, rule: SigmaRule | SigmaCorrelationRule) -> str:
        return self._unique_name(camel(getattr(rule, "name", None) or rule.title or "SigmaRule"))

    def _event_types(self, rule: SigmaRule) -> list[str]:
        forced = self.backend_options.get("event_type")
        return [str(forced)] if forced else event_types_for(rule)

    @staticmethod
    def _mitre(rule: SigmaRule | SigmaCorrelationRule) -> list[str]:
        return [
            str(t.name).upper()
            for t in rule.tags
            if t.namespace == "attack" and re.fullmatch(r"t\d{4}(\.\d{3})?", str(t.name))
        ]

    @staticmethod
    def _detection_fields(rule: SigmaRule) -> list[str]:
        seen: dict[str, None] = {}

        def walk(item: Any) -> None:
            if isinstance(item, ConditionFieldEqualsValueExpression):
                seen.setdefault(item.field, None)
            for arg in getattr(item, "args", []) or []:
                walk(arg)

        for cond in rule.detection.parsed_condition:
            walk(cond.parsed)
        for f in rule.fields or []:
            seen.setdefault(f, None)
        return [f for f in seen if f and "`" not in f and "\n" not in f]

    def finalize_query_default(
        self, rule: SigmaRule, query: str, index: int, state: ConversionState
    ) -> VplRule:
        event_types = self._event_types(rule)
        event_id = channel_event_id(rule)
        return VplRule(
            name=self._stream_name(rule),
            title=rule.title,
            rule_id=str(rule.id) if rule.id else None,
            level=str(rule.level.name).lower() if rule.level else None,
            event_types=event_types,
            where=query if event_id is None else f"EventID == {event_id} and ({query})",
            fields=list(dict.fromkeys(self._detection_fields(rule) + context_fields(event_types))),
            mitre=self._mitre(rule),
            output=bool(getattr(rule, "_output", True)),
        )

    finalize_query_vejas = finalize_query_default

    # --- correlations ------------------------------------------------------

    def _referenced(self, rule: SigmaCorrelationRule) -> list[VplRule]:
        out = []
        for ref in rule.rules:
            try:
                converted = ref.rule.get_conversion_result()
            except SigmaConversionError:
                converted = None
            if converted and isinstance(converted[0], VplCorrelation):
                # A correlation over a correlation reads the stream of its alerts.
                inner = converted[0]
                if not inner.sequence:
                    raise SigmaFeatureNotSupportedByBackendError(
                        f"correlation '{rule.title}' refers to '{inner.title}', which is not a "
                        "temporal_ordered sequence: the alerts of a windowed correlation leave "
                        "their window when a later event reaches it, too late to be placed in "
                        "the window of another correlation"
                    )
                converted = [
                    VplRule(
                        name=inner.name,
                        title=inner.title,
                        rule_id=inner.rule_id,
                        level=inner.level,
                        event_types=[],
                        where="",
                        fields=[],
                        mitre=[],
                        output=False,
                        correlation=True,
                    )
                ]
            if not converted or not isinstance(converted[0], VplRule):
                raise SigmaFeatureNotSupportedByBackendError(
                    f"correlation '{rule.title}' refers to a rule that did not convert"
                )
            out.append(converted[0])
        return out

    def _field_in(self, rule: SigmaCorrelationRule, group_field: str, referenced: VplRule, ref) -> str:
        """The name a group-by field has in one referenced rule (aliases)."""
        aliases = rule.aliases.aliases if rule.aliases else {}
        alias = aliases.get(group_field)
        if alias is not None:
            for key, name in alias.mapping.items():
                if key.reference == ref.reference:
                    return self.escape_and_quote_field(name)
        return self.escape_and_quote_field(group_field)

    def _group_field(self, rule: SigmaCorrelationRule, group_field: str, referenced: VplRule, ref) -> str:
        """A group-by field as a referenced rule's events carry it; the alerts
        of a correlation carry it under its key."""
        if referenced.correlation:
            return vpl_key(group_field)
        return self._field_in(rule, group_field, referenced, ref)

    def _meta(self, rule: SigmaCorrelationRule | VplRule) -> list[str]:
        if isinstance(rule, VplRule):
            title, rid, level, mitre = rule.title, rule.rule_id, rule.level, rule.mitre
        else:
            title = rule.title
            rid = str(rule.id) if rule.id else None
            level = str(rule.level.name).lower() if rule.level else None
            mitre = self._mitre(rule)
        meta = [f"rule: {vpl_str(title)}"]
        if rid:
            meta.append(f"sigma_id: {vpl_str(rid)}")
        if level:
            meta.append(f"level: {vpl_str(level)}")
        if mitre:
            meta.append(f"mitre: {vpl_str(','.join(mitre))}")
        return meta

    @staticmethod
    def _within(rule: SigmaCorrelationRule) -> str:
        spec = rule.timespan.spec
        if not re.fullmatch(r"\d+[smhd]", spec):
            return f"{rule.timespan.seconds}s"
        return spec

    def _sequence(
        self,
        rule: SigmaCorrelationRule,
        name: str,
        order: list[tuple[Any, VplRule]],
    ) -> str:
        group = list(rule.group_by or [])
        aliases = [chr(ord("a") + i) for i in range(len(order))]
        first_ref, first = order[0]
        lines = [f"stream {name} = {first.name} as {aliases[0]}"]
        for (ref, step), alias in zip(order[1:], aliases[1:]):
            conds = [
                f"{self._group_field(rule, g, step, ref)} == {aliases[0]}.{self._group_field(rule, g, first, first_ref)}"
                for g in group
            ]
            where = f" where {' and '.join(conds)}" if conds else ""
            lines.append(f"    -> {step.name}{where} as {alias}")
        lines.append(f"    .within({self._within(rule)})")
        # partition_by is a speed-up when the group key has the same name in
        # every rule; the equality in each step is what makes it correct.
        if group:
            names = {self._group_field(rule, group[0], r, ref) for ref, r in order}
            if len(names) == 1:
                lines.append(f"    .partition_by({names.pop()})")
        emit = self._meta(rule)
        for g in group:
            emit.append(f"{vpl_key(g)}: {aliases[0]}.{self._group_field(rule, g, first, first_ref)}")
        for (ref, step), alias in zip(order, aliases):
            wanted = context_fields(step.event_types) + step.fields
            for f in list(dict.fromkeys(wanted))[:8]:
                emit.append(f"{step.name}_{vpl_key(f)}: {alias}.{self._field(f)}")
        lines.append("    .emit(\n        " + ",\n        ".join(emit) + "\n    )")
        return "\n".join(lines)

    def _aggregate(self, rule: SigmaCorrelationRule, name: str, source: VplRule, measure: str) -> str:
        group = [self._group_field(rule, g, source, rule.rules[0]) for g in (rule.group_by or [])]
        keys = [vpl_key(g) for g in (rule.group_by or [])]
        cond = rule.condition
        if cond is None or getattr(cond, "op", None) is None:
            raise SigmaFeatureNotSupportedByBackendError(
                f"correlation '{rule.title}': only a single-comparison condition is supported"
            )
        op = {
            SigmaCorrelationConditionOperator.LT: "<",
            SigmaCorrelationConditionOperator.LTE: "<=",
            SigmaCorrelationConditionOperator.GT: ">",
            SigmaCorrelationConditionOperator.GTE: ">=",
            SigmaCorrelationConditionOperator.EQ: "==",
            SigmaCorrelationConditionOperator.NEQ: "!=",
        }[cond.op]
        lines = [f"stream {name} = {source.name}"]
        if len(group) == 1:
            lines.append(f"    .partition_by({group[0]})")
        elif len(group) > 1:
            lines.append("    .partition_by(" + " + '|' + ".join(f"to_string({g})" for g in group) + ")")
        lines.append(f"    .window({self._within(rule)})")
        aggs = [f"{k}: last({g})" for k, g in zip(keys, group)] + [f"n: {measure}"]
        lines.append("    .aggregate(" + ", ".join(aggs) + ")")
        lines.append(f"    .where(n {op} {cond.count})")
        emit = self._meta(rule) + [f"{k}: {k}" for k in keys] + ["count: n"]
        lines.append("    .emit(\n        " + ",\n        ".join(emit) + "\n    )")
        return "\n".join(lines)

    def _temporal(self, rule: SigmaCorrelationRule, name: str, pairs: list[tuple[Any, VplRule]]) -> tuple[list[str], str]:
        """Every rule seen, in any order, within the timespan, over more than
        three rules: each rule's events marked with the rule, merged, and the
        distinct rules counted per group in windows of the timespan (as the
        Splunk and Elasticsearch backends bucket time). Returns the marking
        streams and the correlation."""
        cond = rule.condition
        if getattr(cond, "op", None) is None or getattr(cond, "count", None) is None:
            raise SigmaFeatureNotSupportedByBackendError(
                f"correlation '{rule.title}': a temporal condition other than a count of rules is not supported"
            )
        op = {
            SigmaCorrelationConditionOperator.LT: "<",
            SigmaCorrelationConditionOperator.LTE: "<=",
            SigmaCorrelationConditionOperator.GT: ">",
            SigmaCorrelationConditionOperator.GTE: ">=",
            SigmaCorrelationConditionOperator.EQ: "==",
            SigmaCorrelationConditionOperator.NEQ: "!=",
        }[cond.op]
        group = list(rule.group_by or [])
        keys = [vpl_key(g) for g in group]
        feeders, members = [], []
        for ref, step in pairs:
            member = self._unique_name(f"{name}_{step.name}")
            marks = [f"sigma_rule: {vpl_str(step.name)}"] + [
                f"{k}: {self._group_field(rule, g, step, ref)}" for g, k in zip(group, keys)
            ]
            feeders.append(f"stream {member} = {step.name}\n    .select({', '.join(marks)})")
            members.append(member)
        lines = [f"stream {name} = merge({', '.join(members)})"]
        if len(keys) == 1:
            lines.append(f"    .partition_by({keys[0]})")
        elif len(keys) > 1:
            lines.append("    .partition_by(" + " + '|' + ".join(f"to_string({k})" for k in keys) + ")")
        lines.append(f"    .window({self._within(rule)})")
        lines.append("    .aggregate(" + ", ".join([f"{k}: last({k})" for k in keys] + ["rules: count_distinct(sigma_rule)"]) + ")")
        lines.append(f"    .where(rules {op} {cond.count})")
        emit = self._meta(rule) + [f"{k}: {k}" for k in keys] + ["rules: rules"]
        lines.append("    .emit(\n        " + ",\n        ".join(emit) + "\n    )")
        return feeders, "\n".join(lines)

    def convert_correlation_rule(
        self,
        rule: SigmaCorrelationRule,
        output_format: str | None = None,
        method: str | None = None,
        callback: Any = None,
    ) -> list[VplCorrelation]:
        try:
            result = self._convert_correlation(rule, method)
        except SigmaError as e:
            if self.collect_errors:
                self.errors.append((rule, e))
                return []
            raise
        # A correlation over this one reads its conversion, as over a rule.
        rule.set_conversion_result(result)
        return result

    def _convert_correlation(self, rule: SigmaCorrelationRule, method: str | None) -> list[VplCorrelation]:
        method = method or self.default_correlation_method
        if method not in self.correlation_methods:
            raise SigmaFeatureNotSupportedByBackendError(
                f"correlation method '{method}' is not supported by the Varpulis backend"
            )
        self.last_processing_pipeline.apply(rule)
        referenced = self._referenced(rule)
        pairs = list(zip(rule.rules, referenced))
        name = self._stream_name(rule)
        kind = rule.type
        streams: list[str] = []
        feeders: list[str] = []
        if kind == SigmaCorrelationType.TEMPORAL_ORDERED:
            streams.append(self._sequence(rule, name, pairs))
        elif kind == SigmaCorrelationType.TEMPORAL and len(pairs) <= 3:
            for i, order in enumerate(itertools.permutations(pairs)):
                streams.append(self._sequence(rule, name if i == 0 else f"{name}{i + 1}", list(order)))
        elif kind == SigmaCorrelationType.TEMPORAL:
            # Every order of four rules is 24 sequences, of six 720: count
            # the distinct rules seen in a window instead.
            feeders, stream = self._temporal(rule, name, pairs)
            streams.append(stream)
        elif kind == SigmaCorrelationType.EVENT_COUNT:
            streams.append(self._aggregate(rule, name, referenced[0], "count()"))
        elif kind == SigmaCorrelationType.VALUE_COUNT:
            if not rule.condition or not rule.condition.fieldref:
                raise SigmaFeatureNotSupportedByBackendError("value_count needs condition.field")
            f = self._field_in(rule, rule.condition.fieldref, referenced[0], rule.rules[0])
            streams.append(self._aggregate(rule, name, referenced[0], f"count_distinct({f})"))
        elif kind == SigmaCorrelationType.VALUE_SUM:
            f = self._field_in(rule, rule.condition.fieldref, referenced[0], rule.rules[0])
            streams.append(self._aggregate(rule, name, referenced[0], f"sum({f})"))
        elif kind == SigmaCorrelationType.VALUE_AVG:
            f = self._field_in(rule, rule.condition.fieldref, referenced[0], rule.rules[0])
            streams.append(self._aggregate(rule, name, referenced[0], f"avg({f})"))
        else:
            raise SigmaFeatureNotSupportedByBackendError(
                f"correlation type '{kind.name.lower()}' is not supported by the Varpulis backend"
            )
        return [
            VplCorrelation(
                title=rule.title,
                rule_id=str(rule.id) if rule.id else None,
                level=str(rule.level.name).lower() if rule.level else None,
                rules=referenced,
                streams=streams,
                output=bool(getattr(rule, "_output", True)),
                name=name,
                keys=[vpl_key(g) for g in (rule.group_by or [])],
                feeders=feeders,
                sequence=kind == SigmaCorrelationType.TEMPORAL_ORDERED,
            )
        ]

    # --- the program -------------------------------------------------------

    def _rule_stream(self, rule: VplRule, sources: dict[str, str], alert_to: str | None) -> str:
        head = [f"# {rule.title}"]
        if rule.rule_id or rule.level:
            head.append(
                "# sigma " + " ".join(x for x in [rule.rule_id, f"level {rule.level}" if rule.level else None] if x)
            )
        if len(rule.event_types) == 1:
            source = sources[rule.event_types[0]]
        else:
            source = "merge(" + ", ".join(sources[t] for t in rule.event_types) + ")"
        body = [f"stream {rule.name} = {source}", f"    .where({rule.where})"]
        if rule.output:
            emit = self._meta(rule) + list(
                dict.fromkeys(f"{vpl_key(f)}: {self._field(f)}" for f in rule.fields)
            )
            body.append("    .emit(\n        " + ",\n        ".join(emit) + "\n    )")
            if alert_to:
                body.append(f"    .to(Bus, topic: {alert_to})")
        return "\n".join(head + body)

    def _program(self, queries: list[Any], vejas: bool) -> str:
        rules: dict[str, VplRule] = {}
        correlations: list[VplCorrelation] = []
        for q in queries:
            if isinstance(q, VplRule):
                rules[q.name] = q
            elif isinstance(q, VplCorrelation):
                correlations.append(q)
                for r in q.rules:
                    if not r.correlation:
                        rules.setdefault(r.name, r)
        event_types = sorted({t for r in rules.values() for t in r.event_types})

        out = ["# Converted from Sigma by pySigma-backend-varpulis."]
        sources: dict[str, str] = {t: t for t in event_types}
        alert_to = None
        if vejas:
            prefix = str(self.backend_options.get("subject_prefix", "logs"))
            alert_to = vpl_str(str(self.backend_options.get("alert_subject", "alerts.sigma")))
            out.append('\nconnector Bus = nats (\n    url: "ignored-by-vejas: the bus is NATS_URL"\n)')
            for t in event_types:
                sources[t] = f"{t}Source"
                out.append(f"\nstream {t}Source = {t}\n    .from(Bus, topic: {vpl_str(prefix + '.' + t)})")
        for rule in rules.values():
            out.append("\n" + self._rule_stream(rule, sources, alert_to))
        for corr in correlations:
            head = f"# {corr.title}"
            if corr.rule_id:
                head += f"\n# sigma {corr.rule_id}" + (f" level {corr.level}" if corr.level else "")
            if corr.feeders:
                out.append("\n" + head + "\n" + "\n\n".join(corr.feeders))
            for i, stream in enumerate(corr.streams):
                text = stream + (f"\n    .to(Bus, topic: {alert_to})" if alert_to and corr.output else "")
                out.append("\n" + (head + "\n" if i == 0 and not corr.feeders else "") + text)
        return "\n".join(out) + "\n"

    def finalize_output_default(self, queries: list[Any]) -> str:
        return self._program(queries, vejas=False)

    def finalize_output_vejas(self, queries: list[Any]) -> str:
        return self._program(queries, vejas=True)
