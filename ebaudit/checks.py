"""One pure function per check, over the normalised model.

Every check takes the `Inventory` plus one `Rule` and yields `Finding`s. Nothing
here touches the filesystem or the network, which is the whole point: the audit
runs in CI with no AWS credentials.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterator
from typing import Any

from .model import Finding, Inventory, Rule

CHECKS: dict[str, dict[str, str]] = {
    "NO_TARGETS": {
        "severity": "high",
        "title": "rule has no targets and is therefore inert",
    },
    "RULE_DISABLED": {
        "severity": "medium",
        "title": "rule is DISABLED and fires nothing",
    },
    "TARGET_NO_DLQ": {
        "severity": "high",
        "title": "target has no dead-letter queue, so failed invocations vanish",
    },
    "TARGET_NO_RETRY": {
        "severity": "medium",
        "title": "target has no retry policy, so the default two attempts apply",
    },
    "UNMATCHABLE_PATTERN": {
        "severity": "high",
        "title": "event pattern can never match an event",
    },
    "MALFORMED_PATTERN": {
        "severity": "high",
        "title": "event pattern is not valid JSON",
    },
    "SCHEDULE_AND_PATTERN": {
        "severity": "medium",
        "title": "rule carries both a schedule and an event pattern",
    },
    "BAD_SCHEDULE": {
        "severity": "medium",
        "title": "schedule expression does not mean what it looks like",
    },
    "INPUT_TRANSFORMER_MISMATCH": {
        "severity": "high",
        "title": "input transformer template references an undeclared path",
    },
    "CUSTOM_BUS_NO_ARCHIVE": {
        "severity": "low",
        "title": "custom bus has no archive, so replay is impossible",
    },
    "WILDCARD_RESOURCE_TARGET": {
        "severity": "medium",
        "title": "target ARN contains a wildcard",
    },
    "ORPHAN_TARGET_RULE": {
        "severity": "medium",
        "title": "targets reference a rule that list-rules never returned",
    },
}

#: Match operators are only legal inside a list, never as a bare object value.
MATCH_OPERATORS = frozenset(
    {
        "prefix",
        "suffix",
        "anything-but",
        "numeric",
        "cidr",
        "exists",
        "equals-ignore-case",
        "wildcard",
        "$or",
    }
)

RESERVED_TRANSFORMER_VARS = ("aws.events.",)

_PLACEHOLDER = re.compile(r"<([^<>]+)>")
_RATE = re.compile(r"^rate\(\s*(\d+)\s+(minute|minutes|hour|hours|day|days)\s*\)$")
_CRON = re.compile(r"^cron\((.*)\)$")


def _severity(check: str) -> str:
    return CHECKS[check]["severity"]


def _finding(check: str, rule: Rule, message: str, target: str | None = None) -> Finding:
    return Finding(
        check=check,
        severity=_severity(check),
        rule=rule.name,
        bus=rule.bus,
        target=target,
        message=message,
    )


# --------------------------------------------------------------------------
# rule-level checks
# --------------------------------------------------------------------------


def check_no_targets(inv: Inventory, rule: Rule) -> Iterator[Finding]:
    if not inv.targets_supplied:
        return
    if rule.targets:
        return
    yield _finding("NO_TARGETS", rule, f"rule {rule.name!r} on bus {rule.bus!r} has zero targets")


def check_rule_disabled(inv: Inventory, rule: Rule) -> Iterator[Finding]:
    if not rule.declared or not rule.disabled:
        return
    yield _finding("RULE_DISABLED", rule, f"rule {rule.name!r} is in state {rule.state!r}")


def check_orphan_target_rule(inv: Inventory, rule: Rule) -> Iterator[Finding]:
    if rule.declared:
        return
    yield _finding(
        "ORPHAN_TARGET_RULE",
        rule,
        f"{len(rule.targets)} target(s) point at rule {rule.name!r}, which list-rules did not return",
    )


def check_schedule_and_pattern(inv: Inventory, rule: Rule) -> Iterator[Finding]:
    if rule.schedule and rule.event_pattern:
        yield _finding(
            "SCHEDULE_AND_PATTERN",
            rule,
            f"rule {rule.name!r} sets both ScheduleExpression and EventPattern",
        )


def _describe_bad_schedule(expression: str) -> str | None:
    text = expression.strip()
    rate = _RATE.match(text)
    if rate:
        value, unit = int(rate.group(1)), rate.group(2)
        if value == 0:
            return "rate(0 ...) never fires"
        if value == 1 and unit.endswith("s"):
            return f"rate uses the plural {unit!r} with a value of 1; AWS requires the singular"
        if value > 1 and not unit.endswith("s"):
            return f"rate uses the singular {unit!r} with a value of {value}; AWS requires the plural"
        return None

    cron = _CRON.match(text)
    if cron:
        fields = cron.group(1).split()
        if len(fields) != 6:
            return f"cron has {len(fields)} fields; EventBridge requires 6 (minutes hours day-of-month month day-of-week year)"
        day_of_month, day_of_week = fields[2], fields[4]
        if day_of_month == "*" and day_of_week == "*":
            return "cron sets both day-of-month and day-of-week to '*'; one of them must be '?'"
        if day_of_month == "?" and day_of_week == "?":
            return "cron sets both day-of-month and day-of-week to '?'; one of them must be a value"
        return None

    return f"expression {expression!r} is neither rate(...) nor cron(...)"


def check_bad_schedule(inv: Inventory, rule: Rule) -> Iterator[Finding]:
    if not rule.schedule:
        return
    problem = _describe_bad_schedule(rule.schedule)
    if problem:
        yield _finding("BAD_SCHEDULE", rule, problem)


def _pattern_structure_problems(node: Any, path: str = "") -> list[str]:
    """Walk an event pattern and collect constructs that cannot ever match.

    EventBridge leaves must be arrays. A scalar leaf (`{"source": "aws.ec2"}`),
    an empty array, or a bare operator object (`{"source": {"prefix": "aws."}}`)
    is accepted by the API and matches nothing for the rest of its life.
    """
    problems: list[str] = []
    if isinstance(node, dict):
        if not node:
            problems.append(f"{path or 'pattern'} is an empty object")
            return problems
        operators = [key for key in node if key in MATCH_OPERATORS]
        if operators:
            problems.append(
                f"{path or 'pattern'} uses the match operator {operators[0]!r} outside a list; "
                f"it must be written as [{{{operators[0]!r}: ...}}]"
            )
            return problems
        for key, value in node.items():
            problems.extend(_pattern_structure_problems(value, f"{path}.{key}" if path else key))
        return problems
    if isinstance(node, list):
        if not node:
            problems.append(f"{path or 'pattern'} is an empty list, which matches nothing")
        return problems
    problems.append(f"{path or 'pattern'} is the scalar {node!r}; EventBridge leaves must be lists")
    return problems


def _leaf_values(node: Any, wanted: str, path: tuple[str, ...] = ()) -> list[Any]:
    if isinstance(node, dict):
        out: list[Any] = []
        for key, value in node.items():
            out.extend(_leaf_values(value, wanted, path + (key,)))
        return out
    if path and path[-1] == wanted and isinstance(node, list):
        return [item for item in node if isinstance(item, str)]
    return []


def check_pattern(inv: Inventory, rule: Rule) -> Iterator[Finding]:
    """MALFORMED_PATTERN and UNMATCHABLE_PATTERN share one parse."""
    if not rule.event_pattern:
        return
    raw = rule.event_pattern
    if isinstance(raw, (dict, list)):
        pattern: Any = raw
    else:
        try:
            pattern = json.loads(raw)
        except (json.JSONDecodeError, TypeError) as exc:
            reason = getattr(exc, "msg", str(exc))
            yield _finding(
                "MALFORMED_PATTERN",
                rule,
                f"rule {rule.name!r} has an EventPattern that is not valid JSON: {reason}",
            )
            return

    for problem in _pattern_structure_problems(pattern):
        yield _finding("UNMATCHABLE_PATTERN", rule, f"rule {rule.name!r}: {problem}")

    if not isinstance(pattern, dict):
        return

    if inv.observed_sources:
        sources = _leaf_values(pattern, "source")
        concrete = [s for s in sources if "*" not in s]
        if concrete and not any(s in inv.observed_sources for s in concrete):
            yield _finding(
                "UNMATCHABLE_PATTERN",
                rule,
                f"rule {rule.name!r} matches source {concrete!r}, which is absent from the observed inventory",
            )

    if inv.observed_detail_types:
        detail_types = _leaf_values(pattern, "detail-type")
        concrete = [d for d in detail_types if "*" not in d]
        if concrete and not any(d in inv.observed_detail_types for d in concrete):
            yield _finding(
                "UNMATCHABLE_PATTERN",
                rule,
                f"rule {rule.name!r} matches detail-type {concrete!r}, which is absent from the observed inventory",
            )


def check_custom_bus_no_archive(inv: Inventory, rule: Rule) -> Iterator[Finding]:
    if not inv.archives_supplied:
        return
    bus_names = inv.bus_names()
    if bus_names and rule.bus not in bus_names:
        return
    if rule.bus == "default" or rule.bus.startswith("aws.partner/"):
        return
    if rule.bus in inv.archived_buses():
        return
    yield _finding(
        "CUSTOM_BUS_NO_ARCHIVE",
        rule,
        f"custom bus {rule.bus!r} has no archive, so events delivered to rule {rule.name!r} cannot be replayed",
    )


# --------------------------------------------------------------------------
# target-level checks
# --------------------------------------------------------------------------


def check_target_no_dlq(inv: Inventory, rule: Rule) -> Iterator[Finding]:
    for target in rule.targets:
        if target.dlq_arn:
            continue
        yield _finding(
            "TARGET_NO_DLQ",
            rule,
            f"target {target.label!r} of rule {rule.name!r} has no DeadLetterConfig",
            target=target.label,
        )


def check_target_no_retry(inv: Inventory, rule: Rule) -> Iterator[Finding]:
    for target in rule.targets:
        if target.retry_policy:
            continue
        yield _finding(
            "TARGET_NO_RETRY",
            rule,
            f"target {target.label!r} of rule {rule.name!r} has no RetryPolicy; the default two attempts apply",
            target=target.label,
        )


def check_wildcard_resource_target(inv: Inventory, rule: Rule) -> Iterator[Finding]:
    for target in rule.targets:
        if "*" not in (target.arn or ""):
            continue
        yield _finding(
            "WILDCARD_RESOURCE_TARGET",
            rule,
            f"target {target.label!r} of rule {rule.name!r} has the wildcard ARN {target.arn!r}",
            target=target.label,
        )


def check_input_transformer(inv: Inventory, rule: Rule) -> Iterator[Finding]:
    for target in rule.targets:
        transformer = target.input_transformer
        if not isinstance(transformer, dict):
            continue
        template = transformer.get("InputTemplate") or ""
        declared = set(transformer.get("InputPathsMap") or {})
        referenced = set(_PLACEHOLDER.findall(template))
        missing = sorted(
            name
            for name in referenced
            if name not in declared and not name.startswith(RESERVED_TRANSFORMER_VARS)
        )
        if missing:
            yield _finding(
                "INPUT_TRANSFORMER_MISMATCH",
                rule,
                f"target {target.label!r} of rule {rule.name!r} references {missing!r}, "
                f"absent from InputPathsMap {sorted(declared)!r}",
                target=target.label,
            )


CheckFn = Callable[[Inventory, Rule], Iterator[Finding]]

RULE_CHECKS: list[CheckFn] = [
    check_no_targets,
    check_rule_disabled,
    check_orphan_target_rule,
    check_schedule_and_pattern,
    check_bad_schedule,
    check_pattern,
    check_custom_bus_no_archive,
    check_target_no_dlq,
    check_target_no_retry,
    check_wildcard_resource_target,
    check_input_transformer,
]


def run(
    inv: Inventory,
    *,
    only: set[str] | None = None,
    skip: set[str] | None = None,
    severity_floor: str = "low",
) -> list[Finding]:
    """Run every enabled check over every rule and return the findings, sorted."""
    from .model import severity_at_least

    findings: list[Finding] = []
    for rule in inv.rules:
        for check in RULE_CHECKS:
            for finding in check(inv, rule):
                if only and finding.check not in only:
                    continue
                if skip and finding.check in skip:
                    continue
                if not severity_at_least(finding.severity, severity_floor):
                    continue
                findings.append(finding)

    order = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda f: (order[f.severity], f.bus, f.rule, f.check, f.target or ""))
    return findings


def unknown_check_ids(ids: set[str]) -> list[str]:
    return sorted(i for i in ids if i not in CHECKS)
