"""Shared field-policy vectors and parser hardening."""

import json
from pathlib import Path

import pytest

from loguard._capture import CapturePolicy

VECTORS = json.loads(
    (Path(__file__).parents[1] / "contracts/http-capture-v1.json").read_text()
)


@pytest.mark.parametrize("vector", VECTORS["cases"], ids=lambda v: v["name"])
def test_shared_capture_vectors(vector):
    assert (
        CapturePolicy().body(vector["body"].encode(), vector["content_type"])
        == vector["expected_meta"]
    )


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_nonstandard_json_constants_are_rejected(constant):
    assert CapturePolicy().body(
        ('{"q":' + constant + "}").encode(), "application/json"
    ) == {"body_parse_error": True}


def test_form_budget_truncates_without_losing_the_entire_capture():
    raw = "&".join(["password=secret"] + [f"q{i}=test" for i in range(100)]).encode()
    meta = CapturePolicy().body(raw, "application/x-www-form-urlencoded")
    assert "body_parse_error" not in meta
    assert len(meta["body"]) == 63
    assert "secret" not in json.dumps(meta)
