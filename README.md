# aws-eventbridge-rule-audit

[![ci](https://github.com/moveeeax/aws-eventbridge-rule-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/aws-eventbridge-rule-audit/actions/workflows/ci.yml)
[![python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue)](https://www.python.org/)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Audit AWS EventBridge rules **offline**, from the JSON you already have. It finds the rules
that look healthy in the console and fire nothing: zero-target rules, rules left `DISABLED`
after an incident, targets with no dead-letter queue, event patterns that can never match a
single event, and schedule expressions that quietly mean something else.

No AWS API calls, no credentials, no network. Feed it `aws events list-*` output and it runs
anywhere, including CI on a pull request.

## Why

An EventBridge rule fails open. A rule with no targets is valid, deployable and completely
inert. A rule in `DISABLED` state looks identical to one that was parked on purpose. A target
with no `DeadLetterConfig` and no `RetryPolicy` drops failed invocations after two attempts and
tells nobody. And a pattern written as `{"source": "aws.ec2"}` instead of
`{"source": ["aws.ec2"]}` is accepted by the API and matches nothing for the rest of its life.

Everything needed to catch those is static JSON.

## Install

```console
$ pip install git+https://github.com/moveeeax/aws-eventbridge-rule-audit
```

Python 3.11+, standard library only.

## Usage

Dump what you have, then audit it:

```console
$ aws events list-rules > rules.json
$ mkdir -p targets
$ for r in $(jq -r '.Rules[].Name' rules.json); do
    aws events list-targets-by-rule --rule "$r" > "targets/$r.json"
  done
$ aws events list-event-buses > buses.json
$ aws events list-archives > archives.json

$ aws-eventbridge-rule-audit --input rules.json --targets targets/ --buses buses.json --archives archives.json
```

Against the bundled fixtures:

```console
$ aws-eventbridge-rule-audit \
    --input examples/rules.json \
    --targets examples/targets \
    --buses examples/buses.json \
    --archives examples/archives.json \
    --observed-sources examples/observed-sources.json

SEVERITY  CHECK                       BUS          RULE                   TARGET        DETAIL
--------  --------------------------  -----------  ---------------------  ------------  -------------------------------------------------------------------
HIGH      UNMATCHABLE_PATTERN         billing-bus  typo-in-source         -             rule 'typo-in-source': source is the scalar 'aws.s3'; EventBridge leaves must be lists
HIGH      MALFORMED_PATTERN           default      broken-pattern         -             rule 'broken-pattern' has an EventPattern that is not valid JSON: Expecting ',' delimiter
HIGH      NO_TARGETS                  default      orphaned-cleanup       -             rule 'orphaned-cleanup' on bus 'default' has zero targets
HIGH      INPUT_TRANSFORMER_MISMATCH  default      nightly-report         build-report  target 'build-report' of rule 'nightly-report' references ['window'], absent from InputPathsMap ['time']
HIGH      TARGET_NO_DLQ               default      parked-after-incident  page-oncall   target 'page-oncall' of rule 'parked-after-incident' has no DeadLetterConfig
MEDIUM    BAD_SCHEDULE                default      half-hourly-sync       -             rate uses the plural 'hours' with a value of 1; AWS requires the singular
MEDIUM    RULE_DISABLED               default      parked-after-incident  -             rule 'parked-after-incident' is in state 'DISABLED'
LOW       CUSTOM_BUS_NO_ARCHIVE       billing-bus  typo-in-source         -             custom bus 'billing-bus' has no archive, so events delivered to rule 'typo-in-source' cannot be replayed

15 finding(s): 9 high, 5 medium, 1 low
```

Other shapes it accepts: a single bundle file, a directory of any of the above, or stdin.

```console
$ aws-eventbridge-rule-audit --input bundle.json --format json --fail-on high
$ aws-eventbridge-rule-audit --input bundle.json --only NO_TARGETS,TARGET_NO_DLQ --severity medium
$ aws events list-rules | aws-eventbridge-rule-audit --input - --skip TARGET_NO_RETRY
```

A bundle is one object with any of `Rules`, `Targets` (a map of rule name to target list),
`EventBuses`, `Archives`, `Sources` and `DetailTypes`.

## Checks

| id | severity | what it means |
| --- | --- | --- |
| `NO_TARGETS` | high | the rule has zero targets and is decorative |
| `TARGET_NO_DLQ` | high | no `DeadLetterConfig`, so failed invocations vanish |
| `UNMATCHABLE_PATTERN` | high | a scalar leaf, an empty list, a bare match operator, or a `source`/`detail-type` absent from the observed inventory |
| `MALFORMED_PATTERN` | high | `EventPattern` is not valid JSON |
| `INPUT_TRANSFORMER_MISMATCH` | high | `InputTemplate` references a placeholder missing from `InputPathsMap` |
| `RULE_DISABLED` | medium | the rule is in `DISABLED` state |
| `TARGET_NO_RETRY` | medium | no `RetryPolicy`, so the default two attempts apply |
| `BAD_SCHEDULE` | medium | `rate(1 hours)`, a 5-field `cron(...)`, `*` in both day fields, and friends |
| `SCHEDULE_AND_PATTERN` | medium | both a schedule and an event pattern are set |
| `WILDCARD_RESOURCE_TARGET` | medium | the target ARN contains a `*` |
| `ORPHAN_TARGET_RULE` | medium | targets point at a rule `list-rules` never returned |
| `CUSTOM_BUS_NO_ARCHIVE` | low | a custom bus with no archive, so replay is impossible |

`aws-eventbridge-rule-audit --list-checks` prints the same list.

Two checks are deliberately **data-gated**, so a partial dump cannot produce a wall of false
positives:

- `NO_TARGETS`, `TARGET_NO_DLQ`, `TARGET_NO_RETRY`, `WILDCARD_RESOURCE_TARGET` and
  `INPUT_TRANSFORMER_MISMATCH` run only when at least one targets listing was supplied.
  Without `--targets`, an empty target list means "not asked for", not "nothing attached".
- `CUSTOM_BUS_NO_ARCHIVE` runs only when archive data was supplied via `--archives`.
- The `source` and `detail-type` half of `UNMATCHABLE_PATTERN` runs only when
  `--observed-sources` is given. Structural pattern problems are always checked.

## How it works

Three stages, each small enough to read in one sitting:

1. `loader.py` normalises every `aws events list-*` envelope — plus per-rule target dumps,
   hand-built bundles and stdin — into one `Inventory` of rules, targets, buses and archives.
   A rule that appears only in a targets listing is kept and reported, never silently dropped.
2. `checks.py` holds one pure function per check over `(Inventory, Rule)`. No I/O, so each is
   trivially table-testable.
3. `render.py` emits a table, JSON or CSV.

## Exit codes

| code | meaning |
| --- | --- |
| `0` | nothing at or above `--fail-on` |
| `1` | at least one finding at or above `--fail-on` (default floor: `low`) |
| `2` | unreadable input, non-EventBridge JSON, or an unknown check id |

A malformed event pattern is a finding, not a crash: the remaining rules are still audited.

## In CI

```yaml
- name: Audit EventBridge
  run: |
    aws events list-rules > rules.json
    mkdir -p targets
    for r in $(jq -r '.Rules[].Name' rules.json); do
      aws events list-targets-by-rule --rule "$r" > "targets/$r.json"
    done
    aws-eventbridge-rule-audit --input rules.json --targets targets/ --fail-on high
```

## Development

```console
$ python3 -m venv .venv && . .venv/bin/activate
$ pip install -e '.[dev]'
$ pytest -q
```

## License

MIT
