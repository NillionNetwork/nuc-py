from copy import deepcopy
import pytest
from typing import Any, List

from nuc.policy import MalformedPolicyException, Policy


class TestPolicy:
    @pytest.mark.parametrize(
        "input,expected",
        [
            (["==", ".foo", {"bar": 42}], Policy.equals(".foo", {"bar": 42})),
            (["!=", ".foo", {"bar": 42}], Policy.not_equals(".foo", {"bar": 42})),
            (["anyOf", ".foo", [42, "hi"]], Policy.any_of(".foo", [42, "hi"])),
            (["anyOf", ".foo", [{"foo": 42}]], Policy.any_of(".foo", [{"foo": 42}])),
            (
                ["and", [["==", ".foo", 42], ["!=", ".bar", False]]],
                Policy.and_(
                    [Policy.equals(".foo", 42), Policy.not_equals(".bar", False)]
                ),
            ),
            (
                ["or", [["==", ".foo", 42], ["!=", ".bar", False]]],
                Policy.or_(
                    [Policy.equals(".foo", 42), Policy.not_equals(".bar", False)]
                ),
            ),
            (
                ["not", ["==", ".foo", 42]],
                Policy.not_(Policy.equals(".foo", 42)),
            ),
            (
                [
                    "or",
                    [
                        ["==", ".foo", 42],
                        ["and", [["!=", ".bar", 1337], ["not", ["==", ".tar", True]]]],
                    ],
                ],
                Policy.or_(
                    [
                        Policy.equals(".foo", 42),
                        Policy.and_(
                            [
                                Policy.not_equals(".bar", 1337),
                                Policy.not_(Policy.equals(".tar", True)),
                            ]
                        ),
                    ]
                ),
            ),
        ],
    )
    def test_parse_valid(self, input: List[Any], expected: Policy):
        parsed = Policy.parse(deepcopy(input))
        assert parsed == expected

        # Also ensure we can go back to the original input
        assert parsed.serialize() == input

    @pytest.mark.parametrize(
        "input",
        [
            [],
            ["=="],
            ["hi", ".foo", []],
            ["==", ".foo"],
            ["!=", ".foo"],
            ["anyOf", ".foo"],
            ["anyOf", ".foo", 42],
            ["and"],
            ["or"],
            ["not"],
            ["and", 42],
            ["and", [42]],
            ["and", ["hi"]],
            ["and", [["hi"]]],
            ["and", [[42]]],
            ["not", "hi"],
            ["not", 42],
        ],
    )
    def test_parse_invalid(self, input: List[Any]):
        with pytest.raises(MalformedPolicyException):
            Policy.parse(input)

    @pytest.mark.parametrize(
        "policy",
        [
            Policy.equals(".name.first", "bob"),
            Policy.not_equals(".name.first", "john"),
            Policy.equals(".name", {"first": "bob", "last": "smith"}),
            Policy.equals("$.req.foo", 42),
            Policy.equals("$.other", 1337),
            Policy.equals(".", {"name": {"first": "bob", "last": "smith"}, "age": 42}),
            Policy.not_equals(".age", 150),
            Policy.any_of(".name.first", ["john", "bob"]),
            Policy.and_(
                [Policy.equals(".age", 42), Policy.equals(".name.first", "bob")]
            ),
            Policy.or_([Policy.equals(".age", 42), Policy.equals(".age", 150)]),
            Policy.or_([Policy.equals(".age", 150), Policy.equals(".age", 42)]),
        ],
    )
    def test_evaluation_matches(self, policy: Policy):
        value = {"name": {"first": "bob", "last": "smith"}, "age": 42}
        context = {"req": {"foo": 42, "bar": "zar"}, "other": 1337}
        assert policy.matches(value, context)

    @pytest.mark.parametrize(
        "policy",
        [
            Policy.equals(".name.first", "john"),
            Policy.not_equals(".name.first", "bob"),
            Policy.equals(".name", {"first": "john", "last": "smith"}),
            Policy.equals("$.req.foo", 43),
            Policy.not_equals("$.other", 1337),
            Policy.equals(
                ".", {"name": {"first": "john", "last": "smith"}, "age": 100}
            ),
            Policy.not_(Policy.equals(".age", 42)),
            Policy.any_of(".name.first", ["john", "jack"]),
            Policy.and_(
                [Policy.equals(".age", 150), Policy.equals(".name.first", "bob")]
            ),
            Policy.and_(
                [Policy.equals(".age", 42), Policy.equals(".name.first", "john")]
            ),
            Policy.and_([]),
            Policy.or_([]),
            Policy.or_([Policy.equals(".age", 101), Policy.equals(".age", 100)]),
        ],
    )
    def test_evaluation_does_not_match(self, policy: Policy):
        value = {"name": {"first": "bob", "last": "smith"}, "age": 42}
        context = {"req": {"foo": 42, "bar": "zar"}, "other": 1337}
        assert not policy.matches(value, context)
