from __future__ import annotations

import json

import pytest

from conftest import bundle, rule, target, write_json
from ebaudit import cli


def run(argv, capsys, **kwargs):
    code = cli.main(argv, **kwargs)
    out, err = capsys.readouterr()
    return code, out, err


def test_healthy_input_exits_zero(tmp_path, capsys):
    path = write_json(
        tmp_path / "b.json",
        bundle([rule("healthy")], {"healthy": [target("t1")]}),
    )
    code, out, _ = run(["--input", str(path), "--observed-sources", "aws.ec2"], capsys)
    assert code == 0
    assert "No findings." in out


def test_zero_target_rule_exits_one_under_default_fail_on(tmp_path, capsys):
    path = write_json(tmp_path / "b.json", bundle([rule("inert")], {"other": [target("t1")]}))
    code, out, _ = run(["--input", str(path), "--observed-sources", "aws.ec2"], capsys)
    assert code == 1
    assert "NO_TARGETS" in out
    assert "inert" in out


def test_fail_on_none_always_exits_zero(tmp_path, capsys):
    path = write_json(tmp_path / "b.json", bundle([rule("inert")], {"inert": []}))
    code, out, _ = run(["--input", str(path), "--fail-on", "none"], capsys)
    assert code == 0
    assert "NO_TARGETS" in out


def test_fail_on_high_ignores_medium_findings(tmp_path, capsys):
    path = write_json(
        tmp_path / "b.json",
        bundle([rule("parked", State="DISABLED")], {"parked": [target("t1")]}),
    )
    code, out, _ = run(["--input", str(path), "--fail-on", "high", "--observed-sources", "aws.ec2"], capsys)
    assert code == 0
    assert "RULE_DISABLED" in out


def test_json_output_shape(tmp_path, capsys):
    path = write_json(tmp_path / "b.json", bundle([rule("inert")], {"inert": []}))
    code, out, _ = run(["--input", str(path), "--format", "json"], capsys)
    assert code == 1
    payload = json.loads(out)
    assert payload["summary"]["rules_audited"] == 1
    assert payload["summary"]["findings"] == len(payload["findings"])
    assert payload["findings"][0]["check"] == "NO_TARGETS"
    assert set(payload["findings"][0]) == {"check", "severity", "rule", "bus", "target", "message"}


def test_csv_output_has_a_header(tmp_path, capsys):
    path = write_json(tmp_path / "b.json", bundle([rule("inert")], {"inert": []}))
    code, out, _ = run(["--input", str(path), "--format", "csv"], capsys)
    assert code == 1
    lines = out.strip().splitlines()
    assert lines[0] == "severity,check,bus,rule,target,detail"
    assert lines[1].startswith("HIGH,NO_TARGETS,")


def test_stdin_input(capsys):
    text = json.dumps(bundle([rule("inert")], {"inert": []}))
    code, out, _ = run(["--input", "-"], capsys, stdin_text=text)
    assert code == 1
    assert "NO_TARGETS" in out


def test_unreadable_input_exits_two_with_one_line(tmp_path, capsys):
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    code, out, err = run(["--input", str(path)], capsys)
    assert code == 2
    assert err.strip().count("\n") == 0
    assert "Traceback" not in err
    assert err.startswith("aws-eventbridge-rule-audit:")


def test_non_eventbridge_input_exits_two(tmp_path, capsys):
    path = write_json(tmp_path / "ecs.json", {"clusterArns": ["arn:aws:ecs:::cluster/x"]})
    code, _, err = run(["--input", str(path)], capsys)
    assert code == 2
    assert "EventBridge" in err


def test_unknown_check_id_exits_two(tmp_path, capsys):
    path = write_json(tmp_path / "b.json", bundle([rule("a")], {"a": [target("t1")]}))
    code, _, err = run(["--input", str(path), "--only", "NOPE"], capsys)
    assert code == 2
    assert "NOPE" in err


def test_only_and_skip_compose_with_severity(tmp_path, capsys):
    bare = {"Id": "lonely", "Arn": "arn:aws:lambda:eu-west-1:1:function:lonely"}
    path = write_json(tmp_path / "b.json", bundle([rule("r", State="DISABLED")], {"r": [bare]}))

    _, out, _ = run(["--input", str(path), "--only", "TARGET_NO_DLQ", "--observed-sources", "aws.ec2"], capsys)
    assert "TARGET_NO_DLQ" in out and "RULE_DISABLED" not in out

    _, out, _ = run(["--input", str(path), "--skip", "TARGET_NO_DLQ", "--observed-sources", "aws.ec2"], capsys)
    assert "TARGET_NO_DLQ" not in out and "RULE_DISABLED" in out

    code, out, _ = run(
        ["--input", str(path), "--only", "TARGET_NO_RETRY", "--severity", "high", "--observed-sources", "aws.ec2"],
        capsys,
    )
    assert code == 0
    assert "No findings." in out


def test_list_checks(capsys):
    code, out, _ = run(["--list-checks"], capsys)
    assert code == 0
    assert "NO_TARGETS" in out
    assert "CUSTOM_BUS_NO_ARCHIVE" in out


def test_no_input_is_a_usage_error(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main([])
    assert exc.value.code == 2


def test_end_to_end_over_the_examples(examples, capsys):
    argv = [
        "--input",
        str(examples / "rules.json"),
        "--targets",
        str(examples / "targets"),
        "--buses",
        str(examples / "buses.json"),
        "--archives",
        str(examples / "archives.json"),
        "--observed-sources",
        str(examples / "observed-sources.json"),
        "--format",
        "json",
    ]
    code, out, _ = run(argv, capsys)
    assert code == 1
    payload = json.loads(out)
    found = {f["check"] for f in payload["findings"]}
    assert {
        "NO_TARGETS",
        "RULE_DISABLED",
        "TARGET_NO_DLQ",
        "TARGET_NO_RETRY",
        "UNMATCHABLE_PATTERN",
        "MALFORMED_PATTERN",
        "BAD_SCHEDULE",
        "INPUT_TRANSFORMER_MISMATCH",
        "CUSTOM_BUS_NO_ARCHIVE",
        "WILDCARD_RESOURCE_TARGET",
        "ORPHAN_TARGET_RULE",
    } <= found
    # the healthy rule never appears
    assert "healthy-ec2-state-change" not in {f["rule"] for f in payload["findings"]}
