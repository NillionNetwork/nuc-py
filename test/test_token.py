from datetime import datetime, timezone
import pytest
from typing import List
from nuc.policy import Policy
from nuc.token import (
    Command,
    DelegationBody,
    Did,
    InvocationBody,
    MalformedCommandException,
    MalformedDidException,
    MalformedNucTokenException,
    NucToken,
)


class TestCommand:
    @pytest.mark.parametrize(
        "input,expected",
        [
            ("/", []),
            ("/nil", ["nil"]),
            ("/nil/bar", ["nil", "bar"]),
        ],
    )
    def test_parse_valid(self, input: str, expected: List[str]):
        command = Command.parse(input)
        assert command.segments == expected

    @pytest.mark.parametrize(
        "input",
        [
            "",
            "//",
            "/nil/",
            "/nil//a",
        ],
    )
    def test_parse_invalid(self, input: str):
        with pytest.raises(MalformedCommandException):
            Command.parse(input)

    @pytest.mark.parametrize(
        "left,right,expected",
        [
            ([], [], True),
            (["nil"], [], True),
            (["nil"], ["nil"], True),
            (["nil", "bar"], ["nil"], True),
            (["nil"], ["nil", "bar"], False),
            (["nil", "bar"], ["nil", "foo"], False),
            (["nil", "bar", "a"], ["nil", "bar", "b"], False),
            (["nil"], ["bar"], False),
        ],
    )
    def test_is_attenuation(self, left: List[str], right: List[str], expected: bool):
        left_cmd = Command(left)
        right_cmd = Command(right)
        assert left_cmd.is_attenuation_of(right_cmd) == expected


class TestDid:
    def test_parse_valid(self):
        did = Did.parse(
            "did:nil:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        )
        assert (
            did.public_key
            == b"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        )

    @pytest.mark.parametrize(
        "input",
        [
            "foo:bar:aa",
            "did:bar",
            "did:bar:aa:",
            "did:bar:lol",
            "did:test:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ],
    )
    def test_parse_invalid(self, input: str):
        with pytest.raises(MalformedDidException):
            Did.parse(input)


class TestNucToken:
    def test_parse_minimal_delegation(self):
        data = """
{
    "iss": "did:nil:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aud": "did:nil:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "sub": "did:nil:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    "cmd": "/nil/db/read",
    "pol": [
        ["==", ".foo", 42]
    ],
    "nonce": "beef"
}
"""
        token = NucToken.parse(data)
        expected = NucToken(
            issuer=Did.nil(bytes([0xAA] * 33)),
            audience=Did.nil(bytes([0xBB] * 33)),
            subject=Did.nil(bytes([0xCC] * 33)),
            not_before=None,
            expires_at=None,
            command=Command(["nil", "db", "read"]),
            body=DelegationBody([Policy.equals(".foo", 42)]),
            meta=None,
            nonce=bytes([0xBE, 0xEF]),
            proofs=[],
        )
        assert token == expected
        assert NucToken.parse(str(expected)) == expected

    def test_parse_full_delegation(self):
        data = """
{
    "iss": "did:nil:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aud": "did:nil:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "sub": "did:nil:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    "cmd": "/nil/db/read",
    "nbf": 1740494955,
    "exp": 1740495955,
    "pol": [
        ["==", ".foo", 42]
    ],
    "meta": {
        "name": "bob"
    },
    "nonce": "beef",
    "prf": ["f4f04af6a832bcd8a6855df5d0242c9a71e9da17faeb2d33b30c8903f1b5a944"]
}
"""
        token = NucToken.parse(data)
        expected = NucToken(
            issuer=Did.nil(bytes([0xAA] * 33)),
            audience=Did.nil(bytes([0xBB] * 33)),
            subject=Did.nil(bytes([0xCC] * 33)),
            not_before=datetime.fromtimestamp(1740494955, timezone.utc),
            expires_at=datetime.fromtimestamp(1740495955, timezone.utc),
            command=Command(["nil", "db", "read"]),
            body=DelegationBody([Policy.equals(".foo", 42)]),
            meta={"name": "bob"},
            nonce=bytes([0xBE, 0xEF]),
            proofs=[
                b"\xf4\xf0J\xf6\xa82\xbc\xd8\xa6\x85]\xf5\xd0$,\x9aq\xe9\xda\x17\xfa\xeb-3\xb3\x0c\x89\x03\xf1\xb5\xa9D"
            ],
        )
        assert token == expected
        assert NucToken.parse(str(expected)) == expected

    def test_parse_minimal_invocation(self):
        data = """
{
    "iss": "did:nil:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aud": "did:nil:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "sub": "did:nil:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    "cmd": "/nil/db/read",
    "args": {
       "bar": 42
    },
    "nonce": "beef"
}
"""
        token = NucToken.parse(data)
        expected = NucToken(
            issuer=Did.nil(bytes([0xAA] * 33)),
            audience=Did.nil(bytes([0xBB] * 33)),
            subject=Did.nil(bytes([0xCC] * 33)),
            not_before=None,
            expires_at=None,
            command=Command(["nil", "db", "read"]),
            body=InvocationBody({"bar": 42}),
            meta=None,
            nonce=bytes([0xBE, 0xEF]),
            proofs=[],
        )
        assert token == expected
        assert NucToken.parse(str(expected)) == expected

    def test_parse_full_invocation(self):
        data = """
{
    "iss": "did:nil:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aud": "did:nil:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "sub": "did:nil:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    "cmd": "/nil/db/read",
    "nbf": 1740494955,
    "exp": 1740495955,
    "args": {
       "bar": 42
    },
    "meta": {
        "name": "bob"
    },
    "nonce": "beef",
    "prf": ["f4f04af6a832bcd8a6855df5d0242c9a71e9da17faeb2d33b30c8903f1b5a944"]
}
"""
        token = NucToken.parse(data)
        expected = NucToken(
            issuer=Did.nil(bytes([0xAA] * 33)),
            audience=Did.nil(bytes([0xBB] * 33)),
            subject=Did.nil(bytes([0xCC] * 33)),
            not_before=datetime.fromtimestamp(1740494955, timezone.utc),
            expires_at=datetime.fromtimestamp(1740495955, timezone.utc),
            command=Command(["nil", "db", "read"]),
            body=InvocationBody({"bar": 42}),
            meta={"name": "bob"},
            nonce=bytes([0xBE, 0xEF]),
            proofs=[
                b"\xf4\xf0J\xf6\xa82\xbc\xd8\xa6\x85]\xf5\xd0$,\x9aq\xe9\xda\x17\xfa\xeb-3\xb3\x0c\x89\x03\xf1\xb5\xa9D"
            ],
        )
        assert token == expected
        assert NucToken.parse(str(expected)) == expected

    def test_parse_mixed_delegation_invocation(self):
        data = """
{
    "iss": "did:nil:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aud": "did:nil:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "sub": "did:nil:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    "cmd": "/nil/db/read",
    "args": {
       "bar": 42
    },
    "pol": [["==", "foo", 42]],
    "nonce": "beef"
}
"""
        with pytest.raises(MalformedNucTokenException):
            NucToken.parse(data)

    def test_parse_no_delegation_invocation(self):
        data = """
{
    "iss": "did:nil:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aud": "did:nil:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "sub": "did:nil:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    "cmd": "/nil/db/read",
    "nonce": "beef"
}
"""
        with pytest.raises(MalformedNucTokenException):
            NucToken.parse(data)
