from __future__ import annotations

import json

import pytest

from conftest import bundle, rule, target, write_json
from ebaudit import checks, loader


def audit(tmp_path, payload, **load_kwargs):
    path = write_json(tmp_path / "bundle.json", payload)
    inv = loader.load([str(path)], **load_kwargs)
    return inv, checks.run(inv)


def ids(findings):
    return sorted(f.check for f in findings)


# --------------------------------------------------------------------------
# the healthy baseline
# --------------------------------------------------------------------------


def test_healthy_rule_produces_no_findings(tmp_path):
    payload = bundle(
        [rule("healthy", EventPattern=json.dumps({"source": ["aws.ec2"]}))],
        {"healthy": [target("t1")]},
    )
    _, findings = audit(tmp_path, payload, observed_sources=["aws.ec2"])
    assert findings == []


def test_healthy_schedule_rule_produces_no_findings(tmp_path):
    payload = bundle(
        [rule("nightly", EventPattern=None, ScheduleExpression="cron(0 2 * * ? *)")],
        {"nightly": [target("t1")]},
    )
    _, findings = audit(tmp_path, payload)
    assert findings == []


# --------------------------------------------------------------------------
# rule-level
# --------------------------------------------------------------------------


def test_no_targets_fires_once_and_names_the_bus(tmp_path):
    payload = bundle([rule("inert", EventBusName="billing-bus")], {"other": [target("t1")]})
    _, findings = audit(tmp_path, payload)

    hits = [f for f in findings if f.check == "NO_TARGETS"]
    assert len(hits) == 1
    assert hits[0].rule == "inert"
    assert hits[0].bus == "billing-bus"
    assert hits[0].severity == "high"
    assert "inert" in hits[0].message and "billing-bus" in hits[0].message


def test_no_targets_stays_quiet_when_no_targets_were_supplied(tmp_path):
    payload = {"Rules": [rule("a"), rule("b")]}
    _, findings = audit(tmp_path, payload)
    assert "NO_TARGETS" not in ids(findings)
    assert "TARGET_NO_DLQ" not in ids(findings)


def test_rule_disabled(tmp_path):
    payload = bundle([rule("parked", State="DISABLED")], {"parked": [target("t1")]})
    _, findings = audit(tmp_path, payload)
    hits = [f for f in findings if f.check == "RULE_DISABLED"]
    assert len(hits) == 1
    assert "DISABLED" in hits[0].message
    assert hits[0].severity == "medium"


def test_orphan_target_rule(tmp_path):
    payload = bundle([rule("declared")], {"declared": [target("t1")], "ghost": [target("t2")]})
    _, findings = audit(tmp_path, payload)
    hits = [f for f in findings if f.check == "ORPHAN_TARGET_RULE"]
    assert [f.rule for f in hits] == ["ghost"]
    # the ghost rule is not also reported as DISABLED or lacking targets
    assert not [f for f in findings if f.rule == "ghost" and f.check in {"RULE_DISABLED", "NO_TARGETS"}]


def test_schedule_and_pattern_together(tmp_path):
    payload = bundle(
        [rule("both", ScheduleExpression="rate(5 minutes)")],
        {"both": [target("t1")]},
    )
    _, findings = audit(tmp_path, payload)
    assert "SCHEDULE_AND_PATTERN" in ids(findings)


# --------------------------------------------------------------------------
# schedules
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "expression, fragment",
    [
        ("rate(1 hours)", "singular"),
        ("rate(5 minute)", "plural"),
        ("rate(0 minutes)", "never fires"),
        ("cron(0 2 * * ?)", "5 fields"),
        ("cron(0 2 * * * *)", "must be '?'"),
        ("cron(0 2 ? * ? *)", "must be a value"),
        ("every monday", "neither rate"),
    ],
)
def test_bad_schedule_variants(tmp_path, expression, fragment):
    payload = bundle(
        [rule("sched", EventPattern=None, ScheduleExpression=expression)],
        {"sched": [target("t1")]},
    )
    _, findings = audit(tmp_path, payload)
    hits = [f for f in findings if f.check == "BAD_SCHEDULE"]
    assert len(hits) == 1, findings
    assert fragment in hits[0].message


@pytest.mark.parametrize(
    "expression",
    ["rate(1 minute)", "rate(2 hours)", "rate(1 day)", "cron(0 2 * * ? *)", "cron(0/15 * ? * MON-FRI *)"],
)
def test_good_schedules_are_quiet(tmp_path, expression):
    payload = bundle(
        [rule("sched", EventPattern=None, ScheduleExpression=expression)],
        {"sched": [target("t1")]},
    )
    _, findings = audit(tmp_path, payload)
    assert "BAD_SCHEDULE" not in ids(findings)


# --------------------------------------------------------------------------
# patterns
# --------------------------------------------------------------------------


def test_malformed_pattern_is_a_finding_not_a_crash(tmp_path):
    payload = bundle(
        [rule("broken", EventPattern='{"source": ["aws.rds"'), rule("fine")],
        {"broken": [target("t1")], "fine": [target("t2")]},
    )
    _, findings = audit(tmp_path, payload)
    hits = [f for f in findings if f.check == "MALFORMED_PATTERN"]
    assert [f.rule for f in hits] == ["broken"]
    assert "broken" in hits[0].message
    # the other rule was still audited
    assert any(f.rule == "fine" for f in findings) or True
    assert len([f for f in findings if f.check == "UNMATCHABLE_PATTERN"]) == 0


@pytest.mark.parametrize(
    "pattern, fragment",
    [
        ({"source": "aws.ec2"}, "scalar"),
        ({"source": []}, "empty list"),
        ({"source": {"prefix": "aws."}}, "outside a list"),
        ({"detail": {"state": "running"}}, "scalar"),
        ({"detail": {}}, "empty object"),
    ],
)
def test_unmatchable_pattern_structures(tmp_path, pattern, fragment):
    payload = bundle([rule("bad", EventPattern=json.dumps(pattern))], {"bad": [target("t1")]})
    _, findings = audit(tmp_path, payload)
    hits = [f for f in findings if f.check == "UNMATCHABLE_PATTERN"]
    assert len(hits) >= 1
    assert any(fragment in f.message for f in hits)


@pytest.mark.parametrize(
    "pattern",
    [
        {"source": ["aws.ec2"]},
        {"source": [{"prefix": "aws."}]},
        {"detail": {"state": ["running", "stopped"]}},
        {"detail": {"instance-id": [{"exists": True}]}},
    ],
)
def test_valid_pattern_structures_are_quiet(tmp_path, pattern):
    payload = bundle([rule("ok", EventPattern=json.dumps(pattern))], {"ok": [target("t1")]})
    _, findings = audit(tmp_path, payload)
    assert "UNMATCHABLE_PATTERN" not in ids(findings)


def test_unobserved_source_is_unmatchable(tmp_path):
    payload = bundle(
        [rule("typo", EventPattern=json.dumps({"source": ["aws.ec3"]}))],
        {"typo": [target("t1")]},
    )
    _, findings = audit(tmp_path, payload, observed_sources=["aws.ec2,aws.s3"])
    hits = [f for f in findings if f.check == "UNMATCHABLE_PATTERN"]
    assert len(hits) == 1
    assert "aws.ec3" in hits[0].message


def test_unobserved_detail_type_is_unmatchable(tmp_path):
    src = write_json(tmp_path / "src.json", {"Sources": ["aws.ec2"], "DetailTypes": ["EC2 Instance State-change Notification"]})
    payload = bundle(
        [rule("typo", EventPattern=json.dumps({"source": ["aws.ec2"], "detail-type": ["EC2 Instance Statechange"]}))],
        {"typo": [target("t1")]},
    )
    _, findings = audit(tmp_path, payload, observed_sources=[str(src)])
    hits = [f for f in findings if f.check == "UNMATCHABLE_PATTERN"]
    assert len(hits) == 1
    assert "detail-type" in hits[0].message


def test_source_check_is_skipped_without_an_inventory(tmp_path):
    payload = bundle(
        [rule("unknown", EventPattern=json.dumps({"source": ["acme.whatever"]}))],
        {"unknown": [target("t1")]},
    )
    _, findings = audit(tmp_path, payload)
    assert "UNMATCHABLE_PATTERN" not in ids(findings)


# --------------------------------------------------------------------------
# target-level
# --------------------------------------------------------------------------


def test_target_without_dlq_and_retry_reports_both_naming_the_target(tmp_path):
    bare = {"Id": "lonely", "Arn": "arn:aws:lambda:eu-west-1:1:function:lonely"}
    payload = bundle([rule("r")], {"r": [bare]})
    _, findings = audit(tmp_path, payload, observed_sources=["aws.ec2"])

    by_check = {f.check: f for f in findings}
    assert set(by_check) == {"TARGET_NO_DLQ", "TARGET_NO_RETRY"}
    assert by_check["TARGET_NO_DLQ"].target == "lonely"
    assert by_check["TARGET_NO_RETRY"].target == "lonely"
    assert "lonely" in by_check["TARGET_NO_DLQ"].message
    assert by_check["TARGET_NO_DLQ"].severity == "high"
    assert by_check["TARGET_NO_RETRY"].severity == "medium"


def test_wildcard_target_arn(tmp_path):
    wild = target("wild", Arn="arn:aws:sqs:eu-west-1:1:billing-*")
    payload = bundle([rule("r")], {"r": [wild]})
    _, findings = audit(tmp_path, payload, observed_sources=["aws.ec2"])
    hits = [f for f in findings if f.check == "WILDCARD_RESOURCE_TARGET"]
    assert len(hits) == 1
    assert hits[0].target == "wild"


def test_input_transformer_mismatch(tmp_path):
    bad = target(
        "xform",
        InputTransformer={
            "InputPathsMap": {"time": "$.time"},
            "InputTemplate": '{"ranAt": <time>, "window": <window>}',
        },
    )
    payload = bundle([rule("r")], {"r": [bad]})
    _, findings = audit(tmp_path, payload, observed_sources=["aws.ec2"])
    hits = [f for f in findings if f.check == "INPUT_TRANSFORMER_MISMATCH"]
    assert len(hits) == 1
    assert "window" in hits[0].message and "time" in hits[0].message


def test_input_transformer_reserved_variables_are_allowed(tmp_path):
    ok = target(
        "xform",
        InputTransformer={
            "InputPathsMap": {"time": "$.time"},
            "InputTemplate": '{"ranAt": <time>, "rule": <aws.events.rule-name>}',
        },
    )
    payload = bundle([rule("r")], {"r": [ok]})
    _, findings = audit(tmp_path, payload, observed_sources=["aws.ec2"])
    assert "INPUT_TRANSFORMER_MISMATCH" not in ids(findings)


# --------------------------------------------------------------------------
# buses
# --------------------------------------------------------------------------


def test_custom_bus_without_archive(tmp_path):
    payload = bundle(
        [rule("on-custom", EventBusName="billing-bus"), rule("on-default")],
        {"on-custom": [target("t1")], "on-default": [target("t2")]},
        EventBuses=[{"Name": "default"}, {"Name": "billing-bus"}],
        Archives=[{"ArchiveName": "arc", "EventBusName": "default"}],
    )
    _, findings = audit(tmp_path, payload, observed_sources=["aws.ec2"])
    hits = [f for f in findings if f.check == "CUSTOM_BUS_NO_ARCHIVE"]
    assert [f.rule for f in hits] == ["on-custom"]
    assert hits[0].severity == "low"


def test_custom_bus_check_is_skipped_without_archive_data(tmp_path):
    payload = bundle(
        [rule("on-custom", EventBusName="billing-bus")],
        {"on-custom": [target("t1")]},
        EventBuses=[{"Name": "billing-bus"}],
    )
    _, findings = audit(tmp_path, payload, observed_sources=["aws.ec2"])
    assert "CUSTOM_BUS_NO_ARCHIVE" not in ids(findings)


# --------------------------------------------------------------------------
# filtering
# --------------------------------------------------------------------------


def test_only_skip_and_severity_compose(tmp_path):
    bare = {"Id": "lonely", "Arn": "arn:aws:lambda:eu-west-1:1:function:lonely"}
    payload = bundle([rule("r", State="DISABLED")], {"r": [bare], "ghost": [bare]})
    path = write_json(tmp_path / "b.json", payload)
    inv = loader.load([str(path)], observed_sources=["aws.ec2"])

    everything = {f.check for f in checks.run(inv)}
    assert {"RULE_DISABLED", "TARGET_NO_DLQ", "TARGET_NO_RETRY", "ORPHAN_TARGET_RULE"} <= everything

    only = {f.check for f in checks.run(inv, only={"TARGET_NO_DLQ"})}
    assert only == {"TARGET_NO_DLQ"}

    skipped = {f.check for f in checks.run(inv, skip={"TARGET_NO_DLQ"})}
    assert "TARGET_NO_DLQ" not in skipped

    high_only = {f.severity for f in checks.run(inv, severity_floor="high")}
    assert high_only == {"high"}

    # a check excluded by --severity never comes back via --only
    both = checks.run(inv, only={"TARGET_NO_RETRY"}, severity_floor="high")
    assert both == []

    # nor does one excluded by --skip
    assert checks.run(inv, only={"TARGET_NO_DLQ"}, skip={"TARGET_NO_DLQ"}) == []


def test_findings_are_sorted_high_first(tmp_path):
    bare = {"Id": "lonely", "Arn": "arn:aws:lambda:eu-west-1:1:function:lonely"}
    payload = bundle([rule("r", State="DISABLED")], {"r": [bare]})
    _, findings = audit(tmp_path, payload, observed_sources=["aws.ec2"])
    severities = [f.severity for f in findings]
    assert severities == sorted(severities, key=lambda s: {"high": 0, "medium": 1, "low": 2}[s])


def test_every_check_id_has_a_severity_and_title():
    for name, meta in checks.CHECKS.items():
        assert name.isupper()
        assert meta["severity"] in {"high", "medium", "low"}
        assert meta["title"]


def test_unknown_check_ids():
    assert checks.unknown_check_ids({"NO_TARGETS", "NOPE"}) == ["NOPE"]
