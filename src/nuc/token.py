"""
NUC tokens.
"""

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List

from .policy import Policy

_DID_PATTERN = re.compile("did:nil:([a-zA-Z0-9]{66})")
_HEX_PATTERN = re.compile("[a-zA-Z0-9]+")


@dataclass
class Did:
    """
    A class representing a Decentralized Identifier (DID).
    """

    public_key: bytes

    @staticmethod
    def nil(public_key: bytes) -> "Did":
        """
        Construct a new DID for the "nil" method.
        """

        return Did(public_key)

    @staticmethod
    def parse(data: str) -> "Did":
        """
        Parse a DID from a string.
        """
        matches = _DID_PATTERN.findall(data)
        if not matches:
            raise MalformedDidException("invalid DID")

        public_key = matches[0]
        try:
            public_key = bytes.fromhex(public_key)
        except Exception as ex:
            raise MalformedDidException("invalid hex public key") from ex
        return Did(public_key)

    def __str__(self) -> str:
        return f"did:nil:{self.public_key.hex()}"


@dataclass
class Command:
    """
    A command to be invoked.
    """

    segments: List[str]

    @staticmethod
    def parse(data: str) -> "Command":
        """
        Parse a command from a string.
        """

        if not data.startswith("/"):
            raise MalformedCommandException("commands must start with '/'")
        data = data[1:]
        if not data:
            return Command([])
        segments = []
        for segment in data.split("/"):
            if not segment:
                raise MalformedCommandException("empty segment")
            segments.append(segment)
        return Command(segments)

    def __str__(self) -> str:
        return "/" + "/".join(self.segments)


@dataclass
class InvocationBody:
    """
    The body of an invocation.
    """

    args: Dict[str, Any]


@dataclass
class DelegationBody:
    """
    The body of a delegation.
    """

    policies: List[Policy]


# pylint: disable=R0902
@dataclass
class NucToken:
    """
    A class representing a NUC token.
    """

    issuer: Did
    audience: Did
    subject: Did
    not_before: datetime | None
    expires_at: datetime | None
    command: Command
    body: InvocationBody | DelegationBody
    meta: Dict[str, Any] | None
    nonce: bytes
    proofs: List[bytes]

    @staticmethod
    def parse(raw_json: str | bytes) -> "NucToken":
        """
        Parse a NUC token from a string.
        """
        try:
            data = json.loads(raw_json)
        except Exception as ex:
            raise MalformedNucTokenException(f"invalid JSON: {ex}") from ex

        token = _safe_cast(data, dict)
        issuer = Did.parse(_safe_get(token, "iss", str))
        audience = Did.parse(_safe_get(token, "aud", str))
        subject = Did.parse(_safe_get(token, "sub", str))
        not_before = _safe_optional_get(token, "nbf", int)
        expires_at = _safe_optional_get(token, "exp", int)
        command = Command.parse(_safe_get(token, "cmd", str))

        args = _safe_optional_get(token, "args", dict)
        policies = _safe_optional_get(token, "pol", list)
        match (args, policies):
            case (None, None):
                raise MalformedNucTokenException("one of 'args' and 'pol' must bet set")
            case (dict(), None):
                body = InvocationBody(args)
            case (None, list()):
                body = DelegationBody([Policy.parse(p) for p in policies])
            case (dict(), list()):
                raise MalformedNucTokenException("'args' and 'pol' can't both be set")
        meta = _safe_optional_get(token, "meta", dict)
        nonce = _parse_hex(_safe_get(token, "nonce", str), "nonce")
        proofs = [
            _parse_hex(p, "prf") for p in _safe_optional_get(token, "prf", list) or []
        ]
        if data:
            raise MalformedNucTokenException(
                f"unexpected keys found in token: {data.keys()}"
            )
        return NucToken(
            issuer,
            audience,
            subject,
            datetime.fromtimestamp(not_before, timezone.utc) if not_before else None,
            datetime.fromtimestamp(expires_at, timezone.utc) if expires_at else None,
            command,
            body,
            meta,
            nonce,
            proofs,
        )

    def __str__(self) -> str:
        match self.body:
            case InvocationBody(args):
                body = {"args": args}
            case DelegationBody(policies):
                body = {"pol": [policy.serialize() for policy in policies]}
        d = {
            "iss": str(self.issuer),
            "aud": str(self.audience),
            "sub": str(self.subject),
            **({"nbf": int(self.not_before.timestamp())} if self.not_before else {}),
            **({"exp": int(self.expires_at.timestamp())} if self.expires_at else {}),
            "cmd": str(self.command),
            **body,
            **({"meta": self.meta} if self.meta else {}),
            "nonce": self.nonce.hex(),
            **({"prf": [proof.hex() for proof in self.proofs]} if self.proofs else {}),
        }
        return json.dumps(d)


class MalformedDidException(Exception):
    """
    An exception raised when a malformed DID is parsed.
    """


class MalformedCommandException(Exception):
    """
    An exception raised when a malformed command is parsed.
    """


class MalformedNucTokenException(Exception):
    """
    An exception raised when a malformed NUC token is parsed.
    """


def _safe_cast[T](data: Any, ty: type[T]) -> T:
    if not isinstance(data, ty):
        raise MalformedNucTokenException(f"expected {ty.__name__}")
    return data


def _safe_optional_get[T](d: Dict, key: str, ty: type[T]) -> T | None:
    value = d.pop(key, None)
    if value is None:
        return None

    if not isinstance(value, ty):
        raise MalformedNucTokenException(f"expected {ty.__name__} for key {key}")
    return value


def _safe_get[T](d: Dict, key: str, ty: type[T]) -> T:
    value = _safe_optional_get(d, key, ty)
    if value is None:
        raise MalformedNucTokenException(f"expected {ty.__name__} for key {key}")
    return value


def _parse_hex(data: str, field: str) -> bytes:
    # bytes.fromhex accepts newlines and whitespaces...
    if not _HEX_PATTERN.match(data):
        raise MalformedNucTokenException(f"invalid hex in {field}")
    try:
        return bytes.fromhex(data)
    except Exception as ex:
        raise MalformedNucTokenException(f"invalid hex in {field}") from ex
