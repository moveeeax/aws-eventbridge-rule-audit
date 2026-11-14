"""Table, JSON and CSV output."""

from __future__ import annotations

import csv
import io
import json
from collections import Counter

from .model import Finding

COLUMNS = ("SEVERITY", "CHECK", "BUS", "RULE", "TARGET", "DETAIL")


def _rows(findings: list[Finding]) -> list[tuple[str, ...]]:
    return [
        (f.severity.upper(), f.check, f.bus, f.rule, f.target or "-", f.message)
        for f in findings
    ]


def as_table(findings: list[Finding]) -> str:
    if not findings:
        return "No findings."
    rows = _rows(findings)
    widths = [max(len(COLUMNS[i]), *(len(row[i]) for row in rows)) for i in range(len(COLUMNS))]
    # The detail column is last, so let it run to its natural width.
    lines = ["  ".join(COLUMNS[i].ljust(widths[i]) for i in range(len(COLUMNS))).rstrip()]
    lines.append("  ".join("-" * widths[i] for i in range(len(COLUMNS))).rstrip())
    for row in rows:
        lines.append("  ".join(row[i].ljust(widths[i]) for i in range(len(COLUMNS))).rstrip())
    counts = Counter(f.severity for f in findings)
    summary = ", ".join(f"{counts[name]} {name}" for name in ("high", "medium", "low") if counts[name])
    lines.append("")
    lines.append(f"{len(findings)} finding(s): {summary}")
    return "\n".join(lines)


def as_json(findings: list[Finding], *, rules_audited: int) -> str:
    counts = Counter(f.severity for f in findings)
    payload = {
        "summary": {
            "rules_audited": rules_audited,
            "findings": len(findings),
            "high": counts["high"],
            "medium": counts["medium"],
            "low": counts["low"],
        },
        "findings": [f.as_dict() for f in findings],
    }
    return json.dumps(payload, indent=2, sort_keys=False)


def as_csv(findings: list[Finding]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow([c.lower() for c in COLUMNS])
    for row in _rows(findings):
        writer.writerow(row)
    return buffer.getvalue().rstrip("\n")


def render(findings: list[Finding], fmt: str, *, rules_audited: int) -> str:
    if fmt == "json":
        return as_json(findings, rules_audited=rules_audited)
    if fmt == "csv":
        return as_csv(findings)
    return as_table(findings)
