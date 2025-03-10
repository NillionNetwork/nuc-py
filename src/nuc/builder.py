"""
NUC builder.
"""

import secrets
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict

from secp256k1 import PrivateKey

from nuc.envelope import NucTokenEnvelope, urlsafe_base64_encode
from nuc.token import Command, DelegationBody, Did, InvocationBody, NucToken

_DEFAULT_NONCE_LENGTH: int = 16


@dataclass()
class NucTokenBuilder:
    """
    A builder for a NUC token.
    """

    # pylint: disable=R0902
    def __init__(
        self,
        body: InvocationBody | DelegationBody,
        audience: Did | None = None,
        subject: Did | None = None,
        not_before: datetime | None = None,
        expires_at: datetime | None = None,
        command: Command | None = None,
        meta: Dict[str, Any] | None = None,
        nonce: bytes | None = None,
        proof: NucTokenEnvelope | None = None,
    ) -> None:
        self._body = body
        self._audience = audience
        self._subject = subject
        self._not_before = not_before
        self._expires_at = expires_at
        self._command = command
        self._meta = meta
        self._nonce = nonce
        self._proof = proof

    @staticmethod
    def delegation(body: DelegationBody) -> "NucTokenBuilder":
        """
        Create a new token builder for a delegation.
        """

        return NucTokenBuilder(body=body)

    @staticmethod
    def invocation(body: InvocationBody) -> "NucTokenBuilder":
        """
        Create a new token builder for an invocation.
        """

        return NucTokenBuilder(body=body)

    @staticmethod
    def extending(envelope: NucTokenEnvelope) -> "NucTokenBuilder":
        """
        Create a token that pulls basic properties from another one.
        """

        token = envelope.token.token
        if isinstance(token.body, InvocationBody):
            raise TokenBuildException("cannot extend an invocation")
        return NucTokenBuilder(
            body=token.body,
            proof=envelope,
            command=token.command,
            subject=token.subject,
        )

    def audience(self, audience: Did) -> "NucTokenBuilder":
        """
        Set the audience for the token to be built.
        """

        self._audience = audience
        return self

    def subject(self, subject: Did) -> "NucTokenBuilder":
        """
        Set the subject for the token to be built.
        """

        self._subject = subject
        return self

    def not_before(self, not_before: datetime) -> "NucTokenBuilder":
        """
        Set the `not before` date for the token to be built.
        """

        self._not_before = not_before
        return self

    def expires_at(self, expires_at: datetime) -> "NucTokenBuilder":
        """
        Set the `expires at` date for the token to be built.
        """

        self._expires_at = expires_at
        return self

    def command(self, command: Command) -> "NucTokenBuilder":
        """
        Set the command for the token to be built.
        """

        self._command = command
        return self

    def meta(self, meta: Dict[str, Any]) -> "NucTokenBuilder":
        """
        Set the metadata for the token to be built.
        """

        self._meta = meta
        return self

    def nonce(self, nonce: bytes) -> "NucTokenBuilder":
        """
        Set the nonce for the token to be built.
        """

        self._nonce = nonce
        return self

    def proof(self, proof: NucTokenEnvelope) -> "NucTokenBuilder":
        """
        Set the proof for the token to be built.
        """

        self._proof = proof
        return self

    def build(self, key: PrivateKey) -> str:
        """
        Build the token, signing it using the given private key.
        """

        body = self._body
        issuer = Did(key.pubkey.serialize())  # type: ignore
        audience = self._get(self._audience, "audience")
        subject = self._get(self._subject, "subject")
        not_before = self._not_before
        expires_at = self._expires_at
        command = self._get(self._command, "command")
        meta = self._meta
        nonce = (
            self._nonce if self._nonce else secrets.token_bytes(_DEFAULT_NONCE_LENGTH)
        )
        proof = self._proof
        if proof:
            proof.validate_signatures()
        proof_hashes = [proof.token.compute_hash()] if proof else []
        token = NucToken(
            issuer,
            audience,
            subject,
            not_before,
            expires_at,
            command,
            body,
            meta,
            nonce,
            proof_hashes,
        )
        token = str(token).encode("utf8")
        header = '{"alg":"ES256K"}'.encode("utf8")
        token = f"{urlsafe_base64_encode(header)}.{urlsafe_base64_encode(token)}"
        signature = key.ecdsa_serialize_compact(key.ecdsa_sign(token.encode("utf8")))
        token = f"{token}.{urlsafe_base64_encode(signature)}"
        if self._proof:
            all_proofs = [self._proof.token] + self._proof.proofs
            proofs = "/".join([str(proof) for proof in all_proofs])
            token = f"{token}/{proofs}"
        return token

    def _get[T](self, field: T | None, name: str) -> T:
        match field:
            case None:
                raise TokenBuildException(f"field {name} not set")
            case _:
                return field


class TokenBuildException(Exception):
    """
    An exception raised when building a token.
    """
