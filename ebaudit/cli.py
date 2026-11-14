"""Command line entrypoint for aws-eventbridge-rule-audit."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from . import __version__, checks, loader, render
from .model import SEVERITIES, InputError, severity_at_least

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_INPUT = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aws-eventbridge-rule-audit",
        description=(
            "Audit EventBridge rules offline from `aws events list-rules`, "
            "`list-targets-by-rule` and `list-event-buses` output. Makes no AWS API calls."
        ),
        epilog="Exit 0 = clean, 1 = findings at or above --fail-on, 2 = unreadable input.",
    )
    parser.add_argument(
        "--input",
        "-i",
        action="append",
        metavar="PATH",
        help="list-rules JSON, a bundle, a directory of either, or '-' for stdin. Repeatable.",
    )
    parser.add_argument(
        "--targets",
        action="append",
        metavar="PATH",
        help="list-targets-by-rule JSON, or a directory of <rule>.json dumps. Repeatable.",
    )
    parser.add_argument("--buses", action="append", metavar="PATH", help="list-event-buses JSON. Repeatable.")
    parser.add_argument("--archives", action="append", metavar="PATH", help="list-archives JSON. Repeatable.")
    parser.add_argument(
        "--observed-sources",
        action="append",
        metavar="PATH|CSV",
        help="inventory of event sources (and detail-types) seen in the account, "
        "as a JSON file or a comma-separated list. Enables UNMATCHABLE_PATTERN source checks.",
    )
    parser.add_argument("--format", choices=("table", "json", "csv"), default="table", help="output format")
    parser.add_argument("--severity", choices=SEVERITIES, default="low", help="report findings at this severity or above")
    parser.add_argument("--only", metavar="IDS", help="comma-separated check ids to run exclusively")
    parser.add_argument("--skip", metavar="IDS", help="comma-separated check ids to exclude")
    parser.add_argument(
        "--fail-on",
        choices=(*SEVERITIES, "none"),
        default="low",
        help="exit 1 when a finding at this severity or above is reported (default: low)",
    )
    parser.add_argument("--list-checks", action="store_true", help="print the check ids with their severity and exit")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _ids(value: str | None) -> set[str]:
    if not value:
        return set()
    return {part.strip().upper() for part in value.split(",") if part.strip()}


def main(argv: Sequence[str] | None = None, *, stdin_text: str | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_checks:
        width = max(len(name) for name in checks.CHECKS)
        for name, meta in checks.CHECKS.items():
            print(f"{name.ljust(width)}  {meta['severity'].ljust(6)}  {meta['title']}")
        return EXIT_CLEAN

    if not args.input and not args.targets:
        parser.error("nothing to audit: pass --input (or --targets)")

    only, skip = _ids(args.only), _ids(args.skip)
    unknown = checks.unknown_check_ids(only | skip)
    if unknown:
        print(
            f"aws-eventbridge-rule-audit: unknown check id(s): {', '.join(unknown)}\n"
            "run --list-checks to see the available ids",
            file=sys.stderr,
        )
        return EXIT_INPUT

    try:
        inventory = loader.load(
            args.input or [],
            targets=args.targets,
            buses=args.buses,
            archives=args.archives,
            observed_sources=args.observed_sources,
            stdin_text=stdin_text,
        )
    except InputError as exc:
        print(f"aws-eventbridge-rule-audit: {exc}", file=sys.stderr)
        return EXIT_INPUT

    findings = checks.run(inventory, only=only or None, skip=skip or None, severity_floor=args.severity)
    print(render.render(findings, args.format, rules_audited=len(inventory.rules)))

    if args.fail_on == "none":
        return EXIT_CLEAN
    if any(severity_at_least(f.severity, args.fail_on) for f in findings):
        return EXIT_FINDINGS
    return EXIT_CLEAN


def run() -> None:  # console_scripts entrypoint
    sys.exit(main())


if __name__ == "__main__":  # pragma: no cover
    run()
