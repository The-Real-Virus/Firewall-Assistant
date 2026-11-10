"""Lexical budgets include primitives without double-counting separators."""

import pytest

from wfdiag.storage.json_input import checked_json


@pytest.mark.parametrize("value", [b'[{"key":"value"}]', b"[1,true,null]", b'[[],{},"x"]'])
def test_exact_token_budget_and_one_less(value: bytes) -> None:
    # Four tokens: outer array and three values, or array/object/key/string.
    checked_json(value, byte_limit=1024, max_values=4)
    with pytest.raises(ValueError, match="value count"):
        checked_json(value, byte_limit=1024, max_values=3)


def test_escaped_punctuation_is_not_structure_or_primitive() -> None:
    raw = b'{"key":"123,tfn [\\"nested\\"] -42"}'
    assert checked_json(raw, byte_limit=1024, max_values=3) == {"key": '123,tfn ["nested"] -42'}


@pytest.mark.parametrize("retain", [True, False])
@pytest.mark.parametrize(
    "raw",
    [b'{"a":{"x":1,"x":2}}', b'{"a":1,"a":null}', b"[1,NaN]", b"[1e9999]", b"[[[[0]]]]", b"[01]"],
)
def test_discard_mode_retains_syntax_depth_numeric_duplicate_checks(
    raw: bytes, retain: bool
) -> None:
    with pytest.raises(ValueError):
        checked_json(raw, byte_limit=1024, max_depth=3, retain_objects=retain)


def test_discard_mode_drops_only_constructed_objects() -> None:
    raw = b'[{"a":[{"b":2}]}]'
    assert checked_json(raw, byte_limit=1024, retain_objects=False) == [None]
    assert checked_json(raw, byte_limit=1024) == [{"a": [{"b": 2}]}]
