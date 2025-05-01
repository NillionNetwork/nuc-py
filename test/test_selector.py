import pytest
from typing import Any, Dict, List
from nuc.selector import MalformedSelectorException, Selector, SelectorTarget


class TestSelector:
    @pytest.mark.parametrize(
        "input,path,target",
        [
            (".", [], SelectorTarget.TOKEN),
            (".foo", ["foo"], SelectorTarget.TOKEN),
            ("$.foo", ["foo"], SelectorTarget.CONTEXT),
            (".foo.bar", ["foo", "bar"], SelectorTarget.TOKEN),
            ("$.foo.bar", ["foo", "bar"], SelectorTarget.CONTEXT),
            (
                ".abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_",
                ["abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"],
                SelectorTarget.TOKEN,
            ),
        ],
    )
    def test_parse_valid(self, input: str, path: List[str], target: SelectorTarget):
        selector = Selector.parse(input)
        assert selector.path == path
        assert selector.target == target
        assert str(selector) == input

    @pytest.mark.parametrize(
        "input",
        ["", "$", "$.", "A", ".#", ".🚀", "$.#", "$.$", ".A.", ".A..B", "$.A..B"],
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
    def test_lookup_token(self, expression: str, input: Dict[str, Any], expected: Any):
        selector = Selector.parse(expression)
        assert selector.apply(input, {}) == expected

    @pytest.mark.parametrize(
        "expression,expected",
        [
            ("$.req", {"foo": 42, "bar": "zar"}),
            ("$.other", 1337),
            ("$.req.foo", 42),
            ("$.foo", None),
            ("$.req.choochoo", None),
            ("$.bool", False),
        ],
    )
    def test_lookup_context(self, expression: str, expected: Any):
        selector = Selector.parse(expression)
        context = {"req": {"foo": 42, "bar": "zar"}, "other": 1337, "bool": False}
        assert selector.apply({}, context) == expected
