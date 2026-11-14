"""Normalised EventBridge model shared by the loader, the checks and the renderer."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SEVERITIES = ("low", "medium", "high")
SEVERITY_ORDER = {name: index for index, name in enumerate(SEVERITIES)}

DEFAULT_BUS = "default"


class InputError(Exception):
    """Raised when the supplied JSON is unreadable or is not EventBridge output."""


@dataclass
class Target:
    """One entry of `aws events list-targets-by-rule`."""

    id: str
    arn: str
    rule: str
    bus: str
    dlq_arn: str | None = None
    retry_policy: dict[str, Any] | None = None
    input_transformer: dict[str, Any] | None = None

    @property
    def label(self) -> str:
        return self.id or self.arn or "<unnamed target>"


@dataclass
class Rule:
    """One entry of `aws events list-rules`, joined with its targets."""

    name: str
    bus: str = DEFAULT_BUS
    state: str = "ENABLED"
    event_pattern: str | None = None
    schedule: str | None = None
    arn: str | None = None
    managed_by: str | None = None
    targets: list[Target] = field(default_factory=list)
    declared: bool = True
    """False when the rule only showed up in a targets listing, never in list-rules."""

    @property
    def disabled(self) -> bool:
        return (self.state or "").upper() != "ENABLED"


@dataclass
class EventBus:
    """One entry of `aws events list-event-buses`."""

    name: str
    arn: str | None = None

    @property
    def custom(self) -> bool:
        return self.name != DEFAULT_BUS and not self.name.startswith("aws.partner/")


@dataclass
class Archive:
    """One entry of `aws events list-archives`."""

    name: str
    bus: str | None = None


@dataclass
class Inventory:
    """Everything the checks are allowed to look at."""

    rules: list[Rule] = field(default_factory=list)
    buses: list[EventBus] = field(default_factory=list)
    archives: list[Archive] = field(default_factory=list)
    observed_sources: set[str] = field(default_factory=set)
    observed_detail_types: set[str] = field(default_factory=set)

    targets_supplied: bool = False
    """True when at least one targets listing was loaded.

    Without it an empty target list means "not asked for", not "nothing attached",
    so the target-level checks stay quiet instead of firing on every rule.
    """

    archives_supplied: bool = False
    """True when archive data was loaded, for the same reason."""

    def bus_names(self) -> set[str]:
        return {bus.name for bus in self.buses}

    def archived_buses(self) -> set[str]:
        return {archive.bus for archive in self.archives if archive.bus}


@dataclass
class Finding:
    check: str
    severity: str
    rule: str
    message: str
    bus: str = DEFAULT_BUS
    target: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "check": self.check,
            "severity": self.severity,
            "rule": self.rule,
            "bus": self.bus,
            "target": self.target or "",
            "message": self.message,
        }


def severity_at_least(severity: str, floor: str) -> bool:
    return SEVERITY_ORDER[severity] >= SEVERITY_ORDER[floor]
