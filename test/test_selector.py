import pytest
from typing import Any, Dict, List
from nuc.selector import MalformedSelectorException, Selector


class TestSelector:
    @pytest.mark.parametrize(
        "input,expected",
        [
            (".", []),
            (".foo", ["foo"]),
            (".foo.bar", ["foo", "bar"]),
            (
                ".abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_",
                ["abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"],
            ),
        ],
    )
    def test_parse_valid(self, input: str, expected: List[str]):
        selector = Selector.parse(input)
        assert selector.path == expected

    @pytest.mark.parametrize(
        "input",
        ["", "A", ".#", ".🚀", ".A.", ".A..B"],
    )
    def test_parse_invalid(self, input: str):
        with pytest.raises(MalformedSelectorException):
            Selector.parse(input)

    @pytest.mark.parametrize(
        "expression,input,expected",
        [
            (".", {"foo": 42}, {"foo": 42}),
            (".foo", {"foo": 42}, 42),
            (".foo.bar", {"foo": {"bar": 42}}, 42),
            (".foo", {"bar": 42}, None),
        ],
    )
    def test_lookup(self, expression: str, input: Dict[str, Any], expected: Any):
        selector = Selector.parse(expression)
        assert selector.apply(input) == expected
