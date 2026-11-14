"""Turn the three `aws events list-*` shapes into one rule model.

The AWS CLI hands back a different envelope per call, and nobody stores them the
same way twice: one file per call, a directory of per-rule target dumps, a single
bundle someone built by hand, or a pipe. The loader accepts all of those and
normalises them, so the checks only ever see `Inventory`.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from .model import DEFAULT_BUS, Archive, EventBus, Inventory, InputError, Rule, Target

JSON_SUFFIXES = (".json", ".txt")


def _read_json(path: Path) -> Any:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise InputError(f"cannot read {path}: {exc.strerror or exc}") from exc
    return _parse_json(raw, str(path))


def _parse_json(raw: str, origin: str) -> Any:
    if not raw.strip():
        raise InputError(f"{origin} is empty")
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise InputError(f"{origin} is not valid JSON: {exc.msg} at line {exc.lineno}") from exc


def _iter_paths(target: str) -> list[Path]:
    path = Path(target)
    if not path.exists():
        raise InputError(f"no such file or directory: {target}")
    if path.is_dir():
        found = sorted(p for p in path.rglob("*") if p.is_file() and p.suffix.lower() in JSON_SUFFIXES)
        if not found:
            raise InputError(f"no JSON files under {target}")
        return found
    return [path]


def _bus_from_arn(arn: str | None) -> str | None:
    # arn:aws:events:eu-west-1:1234:rule/my-bus/my-rule -> my-bus
    if not arn:
        return None
    _, _, tail = arn.partition(":rule/")
    if not tail:
        return None
    parts = tail.split("/")
    return parts[0] if len(parts) > 1 else DEFAULT_BUS


def _rule_from_entry(entry: dict[str, Any], bus_hint: str | None = None) -> Rule:
    name = entry.get("Name") or entry.get("RuleName")
    if not name:
        raise InputError("a rule entry has no Name")
    bus = entry.get("EventBusName") or bus_hint or _bus_from_arn(entry.get("Arn")) or DEFAULT_BUS
    return Rule(
        name=str(name),
        bus=str(bus),
        state=str(entry.get("State") or "ENABLED"),
        event_pattern=entry.get("EventPattern"),
        schedule=entry.get("ScheduleExpression"),
        arn=entry.get("Arn"),
        managed_by=entry.get("ManagedBy"),
    )


def _target_from_entry(entry: dict[str, Any], rule: str, bus: str) -> Target:
    arn = entry.get("Arn") or ""
    dlq = (entry.get("DeadLetterConfig") or {}).get("Arn")
    retry = entry.get("RetryPolicy") or None
    return Target(
        id=str(entry.get("Id") or ""),
        arn=str(arn),
        rule=rule,
        bus=bus,
        dlq_arn=dlq,
        retry_policy=retry,
        input_transformer=entry.get("InputTransformer") or None,
    )


class _Collector:
    """Accumulates documents, then resolves rules and targets once at the end."""

    def __init__(self) -> None:
        self.rules: dict[tuple[str, str], Rule] = {}
        self.rule_order: list[tuple[str, str]] = []
        self.targets: list[tuple[str, str | None, dict[str, Any]]] = []
        self.buses: dict[str, EventBus] = {}
        self.archives: list[Archive] = []
        self.observed_sources: set[str] = set()
        self.observed_detail_types: set[str] = set()
        self.targets_supplied = False
        self.archives_supplied = False
        self.saw_eventbridge_shape = False

    # ---- ingest -------------------------------------------------------

    def add_rule(self, entry: dict[str, Any], bus_hint: str | None = None) -> None:
        rule = _rule_from_entry(entry, bus_hint)
        key = (rule.bus, rule.name)
        if key in self.rules:
            return
        self.rules[key] = rule
        self.rule_order.append(key)

    def add_targets(self, entries: list[Any], rule: str, bus: str | None) -> None:
        self.targets_supplied = True
        for entry in entries:
            if isinstance(entry, dict):
                self.targets.append((rule, bus, entry))

    def add_bus(self, entry: dict[str, Any]) -> None:
        name = entry.get("Name")
        if not name:
            return
        self.buses.setdefault(str(name), EventBus(name=str(name), arn=entry.get("Arn")))

    def add_archive(self, entry: dict[str, Any]) -> None:
        self.archives_supplied = True
        name = entry.get("ArchiveName") or entry.get("Name")
        bus = entry.get("EventBusName") or _bus_from_arn_event_source(entry.get("EventSourceArn"))
        if name:
            self.archives.append(Archive(name=str(name), bus=bus))

    def add_observed(self, doc: Any) -> None:
        if isinstance(doc, list):
            self.observed_sources.update(str(x) for x in doc)
            return
        if isinstance(doc, dict):
            for key in ("Sources", "sources", "ObservedSources"):
                for value in doc.get(key, []) or []:
                    self.observed_sources.add(str(value))
            for key in ("DetailTypes", "detail-types", "ObservedDetailTypes"):
                for value in doc.get(key, []) or []:
                    self.observed_detail_types.add(str(value))

    # ---- document dispatch --------------------------------------------

    def ingest(self, doc: Any, origin: str, *, kind: str | None = None, name_hint: str | None = None) -> None:
        if kind == "targets":
            self._ingest_targets_doc(doc, origin, name_hint)
            return
        if kind == "buses":
            self._ingest_buses_doc(doc, origin)
            return
        if kind == "archives":
            self._ingest_archives_doc(doc, origin)
            return
        self._ingest_any(doc, origin, name_hint)

    def _ingest_any(self, doc: Any, origin: str, name_hint: str | None) -> None:
        if isinstance(doc, list):
            if not doc:
                self.saw_eventbridge_shape = True
                return
            if all(isinstance(x, dict) and ("Name" in x or "RuleName" in x) for x in doc):
                self.saw_eventbridge_shape = True
                for entry in doc:
                    self.add_rule(entry)
                return
            raise InputError(f"{origin}: a bare JSON array must be a list of rules")

        if not isinstance(doc, dict):
            raise InputError(f"{origin}: expected a JSON object from an `aws events list-*` call")

        handled = False
        if "Rules" in doc:
            rules = doc.get("Rules")
            if not isinstance(rules, list):
                raise InputError(f"{origin}: Rules must be an array")
            for entry in rules:
                if isinstance(entry, dict):
                    self.add_rule(entry)
            handled = True
        if "EventBuses" in doc:
            self._ingest_buses_doc(doc, origin)
            handled = True
        if "Archives" in doc:
            self._ingest_archives_doc(doc, origin)
            handled = True
        if "Targets" in doc:
            self._ingest_targets_doc(doc, origin, name_hint)
            handled = True
        if any(key in doc for key in ("ObservedSources", "Sources", "ObservedDetailTypes", "DetailTypes")):
            self.add_observed(doc)
            handled = True

        if handled:
            self.saw_eventbridge_shape = True
            return

        # A bundle keyed by rule name: {"my-rule": {"Rule": {...}, "Targets": [...]}}
        if self._ingest_keyed_bundle(doc):
            self.saw_eventbridge_shape = True
            return

        # A single rule object straight out of `aws events describe-rule`.
        if "Name" in doc or "RuleName" in doc:
            self.add_rule(doc)
            self.saw_eventbridge_shape = True
            return

        raise InputError(
            f"{origin}: no Rules, Targets, EventBuses or Archives key — this does not look like EventBridge output"
        )

    def _ingest_keyed_bundle(self, doc: dict[str, Any]) -> bool:
        if not doc:
            return False
        matched = False
        for key, value in doc.items():
            if isinstance(value, dict) and ("Rule" in value or "Targets" in value):
                rule_entry = value.get("Rule")
                bus = None
                if isinstance(rule_entry, dict):
                    entry = dict(rule_entry)
                    entry.setdefault("Name", key)
                    self.add_rule(entry)
                    bus = entry.get("EventBusName")
                targets = value.get("Targets")
                if isinstance(targets, list):
                    self.add_targets(targets, str(key), bus)
                matched = True
            elif isinstance(value, list) and all(isinstance(x, dict) and "Id" in x for x in value) and value:
                self.add_targets(value, str(key), None)
                matched = True
        return matched

    def _ingest_targets_doc(self, doc: Any, origin: str, name_hint: str | None) -> None:
        if isinstance(doc, list):
            if name_hint is None:
                raise InputError(f"{origin}: a bare targets array needs a rule name (use a file named <rule>.json)")
            self.add_targets(doc, name_hint, None)
            return
        if not isinstance(doc, dict):
            raise InputError(f"{origin}: expected targets JSON")
        targets = doc.get("Targets")
        if isinstance(targets, dict):
            for rule_name, entries in targets.items():
                if isinstance(entries, list):
                    self.add_targets(entries, str(rule_name), None)
            return
        if isinstance(targets, list):
            rule_name = doc.get("Rule") or doc.get("RuleName") or name_hint
            if not rule_name:
                raise InputError(f"{origin}: targets listing has no Rule name (use a file named <rule>.json)")
            self.add_targets(targets, str(rule_name), doc.get("EventBusName"))
            return
        if self._ingest_keyed_bundle(doc):
            return
        raise InputError(f"{origin}: no Targets key")

    def _ingest_buses_doc(self, doc: Any, origin: str) -> None:
        entries = doc.get("EventBuses") if isinstance(doc, dict) else doc
        if not isinstance(entries, list):
            raise InputError(f"{origin}: no EventBuses array")
        for entry in entries:
            if isinstance(entry, dict):
                self.add_bus(entry)
        if isinstance(doc, dict) and isinstance(doc.get("Archives"), list):
            self._ingest_archives_doc(doc, origin)

    def _ingest_archives_doc(self, doc: Any, origin: str) -> None:
        entries = doc.get("Archives") if isinstance(doc, dict) else doc
        if not isinstance(entries, list):
            raise InputError(f"{origin}: no Archives array")
        self.archives_supplied = True
        for entry in entries:
            if isinstance(entry, dict):
                self.add_archive(entry)

    # ---- resolve -------------------------------------------------------

    def finish(self) -> Inventory:
        if not self.saw_eventbridge_shape and not self.targets_supplied:
            raise InputError("nothing to audit: no EventBridge rules found in the input")

        by_name: dict[str, list[tuple[str, str]]] = {}
        for bus, name in self.rule_order:
            by_name.setdefault(name, []).append((bus, name))

        for rule_name, bus_hint, entry in self.targets:
            key: tuple[str, str] | None = None
            if bus_hint and (bus_hint, rule_name) in self.rules:
                key = (bus_hint, rule_name)
            elif by_name.get(rule_name):
                key = by_name[rule_name][0]
            if key is None:
                key = (bus_hint or DEFAULT_BUS, rule_name)
                self.rules[key] = Rule(name=rule_name, bus=key[0], declared=False)
                self.rule_order.append(key)
                by_name.setdefault(rule_name, []).append(key)
            rule = self.rules[key]
            rule.targets.append(_target_from_entry(entry, rule.name, rule.bus))

        return Inventory(
            rules=[self.rules[key] for key in self.rule_order],
            buses=list(self.buses.values()),
            archives=self.archives,
            observed_sources=self.observed_sources,
            observed_detail_types=self.observed_detail_types,
            targets_supplied=self.targets_supplied,
            archives_supplied=self.archives_supplied,
        )


def _bus_from_arn_event_source(arn: str | None) -> str | None:
    if not arn:
        return None
    _, _, tail = arn.partition(":event-bus/")
    return tail or None


def load(
    inputs: list[str],
    *,
    targets: list[str] | None = None,
    buses: list[str] | None = None,
    archives: list[str] | None = None,
    observed_sources: list[str] | None = None,
    stdin_text: str | None = None,
) -> Inventory:
    """Load every supplied artefact into one `Inventory`.

    `inputs` may contain `-` for stdin, a file, or a directory. Files handed to
    `targets` are matched to a rule by their `Rule` key, by the bundle key, or by
    the file stem, in that order.
    """
    collector = _Collector()

    for item in inputs or []:
        if item == "-":
            text = stdin_text if stdin_text is not None else sys.stdin.read()
            collector.ingest(_parse_json(text, "stdin"), "stdin")
            continue
        for path in _iter_paths(item):
            collector.ingest(_read_json(path), str(path), name_hint=path.stem)

    for item in targets or []:
        for path in _iter_paths(item):
            collector.ingest(_read_json(path), str(path), kind="targets", name_hint=path.stem)

    for item in buses or []:
        for path in _iter_paths(item):
            collector.ingest(_read_json(path), str(path), kind="buses")

    for item in archives or []:
        for path in _iter_paths(item):
            collector.ingest(_read_json(path), str(path), kind="archives")

    for item in observed_sources or []:
        path = Path(item)
        if path.exists():
            collector.add_observed(_read_json(path))
        else:
            collector.observed_sources.update(part.strip() for part in item.split(",") if part.strip())

    return collector.finish()
