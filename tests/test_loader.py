from __future__ import annotations

import json

import pytest

from conftest import bundle, rule, target, write_json
from ebaudit import loader
from ebaudit.model import InputError


def test_loads_list_rules_envelope(tmp_path):
    path = write_json(tmp_path / "rules.json", {"Rules": [rule("a"), rule("b")]})
    inv = loader.load([str(path)])
    assert [r.name for r in inv.rules] == ["a", "b"]
    assert inv.targets_supplied is False


def test_joins_targets_directory_by_file_stem(tmp_path):
    rules = write_json(tmp_path / "rules.json", {"Rules": [rule("a"), rule("b")]})
    write_json(tmp_path / "targets" / "a.json", {"Targets": [target("t1"), target("t2")]})
    write_json(tmp_path / "targets" / "b.json", {"Targets": []})

    inv = loader.load([str(rules)], targets=[str(tmp_path / "targets")])

    by_name = {r.name: r for r in inv.rules}
    assert [t.id for t in by_name["a"].targets] == ["t1", "t2"]
    assert by_name["b"].targets == []
    assert inv.targets_supplied is True


def test_targets_rule_key_beats_file_stem(tmp_path):
    rules = write_json(tmp_path / "rules.json", {"Rules": [rule("real-name")]})
    write_json(tmp_path / "t" / "whatever.json", {"Rule": "real-name", "Targets": [target("t1")]})

    inv = loader.load([str(rules)], targets=[str(tmp_path / "t")])

    assert [t.id for t in inv.rules[0].targets] == ["t1"]


def test_bundle_with_targets_mapping(tmp_path):
    path = write_json(
        tmp_path / "bundle.json",
        bundle([rule("a")], {"a": [target("t1")]}),
    )
    inv = loader.load([str(path)])
    assert inv.targets_supplied is True
    assert inv.rules[0].targets[0].dlq_arn.endswith(":dlq")


def test_bundle_keyed_by_rule_name(tmp_path):
    path = write_json(
        tmp_path / "bundle.json",
        {"my-rule": {"Rule": rule("my-rule"), "Targets": [target("t1")]}},
    )
    inv = loader.load([str(path)])
    assert [r.name for r in inv.rules] == ["my-rule"]
    assert [t.id for t in inv.rules[0].targets] == ["t1"]


def test_reads_stdin(tmp_path):
    text = json.dumps({"Rules": [rule("from-stdin")]})
    inv = loader.load(["-"], stdin_text=text)
    assert [r.name for r in inv.rules] == ["from-stdin"]


def test_bus_is_derived_from_rule_arn_when_absent(tmp_path):
    path = write_json(
        tmp_path / "rules.json",
        {
            "Rules": [
                {"Name": "on-bus", "Arn": "arn:aws:events:eu-west-1:1:rule/billing-bus/on-bus"},
                {"Name": "on-default", "Arn": "arn:aws:events:eu-west-1:1:rule/on-default"},
            ]
        },
    )
    inv = loader.load([str(path)])
    assert {r.name: r.bus for r in inv.rules} == {"on-bus": "billing-bus", "on-default": "default"}


def test_rule_only_in_targets_is_kept_not_dropped(tmp_path):
    rules = write_json(tmp_path / "rules.json", {"Rules": [rule("declared")]})
    write_json(tmp_path / "t" / "ghost.json", {"Targets": [target("t1")]})

    inv = loader.load([str(rules)], targets=[str(tmp_path / "t")])

    ghost = next(r for r in inv.rules if r.name == "ghost")
    assert ghost.declared is False
    assert len(ghost.targets) == 1


def test_buses_and_archives(tmp_path):
    rules = write_json(tmp_path / "rules.json", {"Rules": [rule("a")]})
    buses = write_json(tmp_path / "buses.json", {"EventBuses": [{"Name": "default"}, {"Name": "billing-bus"}]})
    archives = write_json(
        tmp_path / "archives.json",
        {"Archives": [{"ArchiveName": "arc", "EventSourceArn": "arn:aws:events:eu-west-1:1:event-bus/default"}]},
    )

    inv = loader.load([str(rules)], buses=[str(buses)], archives=[str(archives)])

    assert inv.bus_names() == {"default", "billing-bus"}
    assert inv.archived_buses() == {"default"}
    assert inv.archives_supplied is True


def test_observed_sources_from_csv_and_file(tmp_path):
    rules = write_json(tmp_path / "rules.json", {"Rules": [rule("a")]})
    inv = loader.load([str(rules)], observed_sources=["aws.ec2,acme.billing"])
    assert inv.observed_sources == {"aws.ec2", "acme.billing"}

    src = write_json(tmp_path / "src.json", {"Sources": ["aws.s3"], "DetailTypes": ["Object Created"]})
    inv = loader.load([str(rules)], observed_sources=[str(src)])
    assert inv.observed_sources == {"aws.s3"}
    assert inv.observed_detail_types == {"Object Created"}


@pytest.mark.parametrize(
    "payload, fragment",
    [
        ("not json at all", "not valid JSON"),
        ("", "is empty"),
        ('{"Clusters": []}', "does not look like EventBridge output"),
        ('"a string"', "expected a JSON object"),
        ('{"Rules": "nope"}', "Rules must be an array"),
    ],
)
def test_unreadable_input_raises_inputerror(tmp_path, payload, fragment):
    path = tmp_path / "bad.json"
    path.write_text(payload, encoding="utf-8")
    with pytest.raises(InputError) as exc:
        loader.load([str(path)])
    assert fragment in str(exc.value)


def test_missing_path_raises_inputerror(tmp_path):
    with pytest.raises(InputError) as exc:
        loader.load([str(tmp_path / "nope.json")])
    assert "no such file" in str(exc.value)


def test_list_rules_without_rules_key_is_an_error(tmp_path):
    path = write_json(tmp_path / "empty.json", {"NextToken": "abc"})
    with pytest.raises(InputError):
        loader.load([str(path)])


def test_empty_rules_array_is_accepted(tmp_path):
    path = write_json(tmp_path / "rules.json", {"Rules": []})
    inv = loader.load([str(path)])
    assert inv.rules == []


def test_rule_entry_without_name_is_rejected(tmp_path):
    path = write_json(tmp_path / "rules.json", {"Rules": [{"Arn": "arn:aws:events:::rule/x"}]})
    with pytest.raises(InputError) as exc:
        loader.load([str(path)])
    assert "no Name" in str(exc.value)


def test_example_fixtures_load(examples):
    inv = loader.load(
        [str(examples / "rules.json")],
        targets=[str(examples / "targets")],
        buses=[str(examples / "buses.json")],
        archives=[str(examples / "archives.json")],
        observed_sources=[str(examples / "observed-sources.json")],
    )
    assert len(inv.rules) == 8  # 7 declared + the orphaned deleted-rule
    assert inv.targets_supplied and inv.archives_supplied
