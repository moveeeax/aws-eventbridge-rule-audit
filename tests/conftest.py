from __future__ import annotations

import json
from pathlib import Path

import pytest

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


@pytest.fixture
def examples() -> Path:
    return EXAMPLES


def write_json(path: Path, payload: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def rule(name: str, **overrides: object) -> dict:
    """A healthy rule entry, overridable per test."""
    entry: dict = {
        "Name": name,
        "Arn": f"arn:aws:events:eu-west-1:123456789012:rule/{name}",
        "EventPattern": json.dumps({"source": ["aws.ec2"]}),
        "State": "ENABLED",
        "EventBusName": "default",
    }
    entry.update(overrides)
    return entry


def target(target_id: str = "t1", **overrides: object) -> dict:
    """A healthy target entry: DLQ set, retry policy set, concrete ARN."""
    entry: dict = {
        "Id": target_id,
        "Arn": f"arn:aws:lambda:eu-west-1:123456789012:function:{target_id}",
        "DeadLetterConfig": {"Arn": "arn:aws:sqs:eu-west-1:123456789012:dlq"},
        "RetryPolicy": {"MaximumRetryAttempts": 4},
    }
    entry.update(overrides)
    return entry


def bundle(rules: list[dict], targets: dict[str, list[dict]] | None = None, **extra: object) -> dict:
    payload: dict = {"Rules": rules}
    if targets is not None:
        payload["Targets"] = targets
    payload.update(extra)
    return payload
