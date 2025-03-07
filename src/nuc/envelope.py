"""
NUC envelope.
"""

import base64
import json
from dataclasses import dataclass
from typing import List

from secp256k1 import PublicKey

from nuc.token import NucToken


@dataclass
class DecodedNucToken:
    """
    A decoded NUC token.
    """

    raw_header: str
    raw_payload: str
    signature: bytes
    token: NucToken

    @staticmethod
    def parse(data: str) -> "DecodedNucToken":
        """
        Parse a token from its serialized JWT form.
        """

        parts = data.split(".", 2)
        if len(parts) != 3:
            raise MalformedNucJwtException("invalid JWT structure")
        (raw_header, raw_payload, signature) = parts
        header = _base64_decode(raw_header)
        try:
            header = json.loads(header)
        except Exception as ex:
            raise MalformedNucJwtException("invalid header") from ex
        if not isinstance(header, dict):
            raise MalformedNucJwtException(
                f"invalid JWT header type: {type(header).__name__}"
            )
        if header.get("alg") != "ES256K":
            raise MalformedNucJwtException("invalid JWT algorithm")
        if len(header) != 1:
            raise MalformedNucJwtException("unexpected keys in header")

        payload = _base64_decode(raw_payload)
        token = NucToken.parse(payload)

        signature = _base64_decode(signature)

        return DecodedNucToken(raw_header, raw_payload, signature, token)

    def validate_signature(self):
        """
        Validate the signature in this token.
        """

        public_key = PublicKey(self.token.issuer.public_key, raw=True)
        payload = f"{self.raw_header}.{self.raw_payload}".encode("utf8")
        signature = public_key.ecdsa_deserialize_compact(self.signature)
        if not public_key.ecdsa_verify(payload, signature):
            raise InvalidSignatureException("signature verification failed")


class NucTokenEnvelope:
    """
    A NUC token envelope, containing a parsed token along with all its proofs
    """

    def __init__(self, token: DecodedNucToken, proofs: List[DecodedNucToken]) -> None:
        self._token = token
        self._proofs = proofs

    @staticmethod
    def parse(data: str) -> "NucTokenEnvelope":
        """
        Parse a NUC token envelope from its serialized JWT form.

        Note that this only parses the envelope and ensures it is structurally correct. This does not perform
        any form of signature validation.
        """

        tokens = data.split("/")
        if len(tokens) == 0:
            raise MalformedNucJwtException("no tokens found")
        token = DecodedNucToken.parse(tokens[0])
        proofs = [DecodedNucToken.parse(token) for token in tokens[1:]]
        return NucTokenEnvelope(token, proofs)

    def validate_signatures(self):
        """
        Validate the signature in this envelope.
        """

        for token in [self._token, *self._proofs]:
            token.validate_signature()

    def token(self) -> NucToken:
        """
        Get the token in this envelope.
        """

        return self._token.token

    def proofs(self) -> List[NucToken]:
        """
        Get the proofs in this envelope.
        """

        return [proof.token for proof in self._proofs]


class MalformedNucJwtException(Exception):
    """
    An exception thrown when a malformed NUC JWT is parsed.
    """


class InvalidSignatureException(Exception):
    """
    An exception thrown when signature verification fails.
    """


def _base64_decode(data: str) -> bytes:
    padding = 4 - (len(data) % 4)
    data = data + ("=" * padding)
    try:
        return base64.urlsafe_b64decode(data)
    except Exception as ex:
        raise MalformedNucJwtException("invalid base64") from ex
