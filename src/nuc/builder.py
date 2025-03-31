"""
NUC builder.
"""

import secrets
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List
from typing_extensions import Self

from secp256k1 import PrivateKey

from nuc.envelope import NucTokenEnvelope, urlsafe_base64_encode
from nuc.policy import Policy
from nuc.token import Command, DelegationBody, Did, InvocationBody, NucToken

_DEFAULT_NONCE_LENGTH: int = 16


@dataclass()
class NucTokenBuilder:
    """
    A builder for a NUC token.

    Example
    -------

    .. code-block:: py3

        from secp256k1 import PrivateKey
        from nuc.builder NucTokenBuilder
        from nuc.token import Did, Command
        from nuc.policy import Policy

        # Create a key to sign the generated token.
        key = PrivateKey()

        # Create a token.
        token = NucTokenBuilder.delegation([Policy.equals(".args.foo", 42)])
            .audience(Did(bytes([0xBB] * 33)))
            .subject(Did(bytes([0xCC] * 33)))
            .command(Command(["nil", "db", "read"]))
            .build(key)
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
    def delegation(policies: List[Policy]) -> "NucTokenBuilder":
        """
        Create a new token builder for a delegation.

        Arguments
        ---------

        policies
            The policies to use in the delegation.
        """

        return NucTokenBuilder(body=DelegationBody(policies))

    @staticmethod
    def invocation(args: Dict[str, Any]) -> "NucTokenBuilder":
        """
        Create a new token builder for an invocation.

        Arguments
        ---------

        args
            The arguments to use in the invocation.

        """

        return NucTokenBuilder(body=InvocationBody(args))

    @staticmethod
    def extending(envelope: NucTokenEnvelope) -> "NucTokenBuilder":
        """
        Create a token that pulls basic properties from another one.

        This pulls the following properties from the given envelope:

        * command
        * subject

        The given token will be used as a proof for this one so there's no need to call anything else to link them.

        Arguments
        ---------

        envelope
            The envelope to extend.
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

    def body(self, body: InvocationBody | DelegationBody) -> "NucTokenBuilder":
        """
        Set the body for the token being built.

        Arguments
        ---------

        body
            The body for the token.
        """

        self._body = body
        return self

    def audience(self, audience: Did) -> Self:
        """
        Set the audience for the token to be built.

        The audience must be the entity this token is going to be sent to.

        Arguments
        ---------

        audience
            The audience of the token.
        """

        self._audience = audience
        return self

    def subject(self, subject: Did) -> Self:
        """
        Set the subject for the token to be built.

        Arguments
        ---------

        subject
            The subject of the token.
        """

        self._subject = subject
        return self

    def not_before(self, not_before: datetime) -> Self:
        """
        Set the `not before` date for the token to be built.

        Arguments
        ---------

        not_before
            The timestamp at which the token will become valid.
        """

        self._not_before = not_before
        return self

    def expires_at(self, expires_at: datetime) -> Self:
        """
        Set the `expires at` date for the token to be built.

        Arguments
        ---------

        expires_at
            The timestamp at which the token will expire.
        """

        self._expires_at = expires_at
        return self

    def command(self, command: Command) -> Self:
        """
        Set the command for the token to be built.

        Arguments
        ---------

        command
            The command for the token to be built.
        """

        self._command = command
        return self

    def meta(self, meta: Dict[str, Any]) -> Self:
        """
        Set the metadata for the token to be built.

        Arguments
        ---------

        meta
            The metadata for the built token.
        """

        self._meta = meta
        return self

    def nonce(self, nonce: bytes) -> Self:
        """
        Set the nonce for the token to be built.

        Arguments
        ---------

        nonce
            The nonce to be set.

        .. note:: The nonce doesn't have to be explicitly set and it will default to
            a random 16 byte long bytestring if not set.
        """

        self._nonce = nonce
        return self

    def proof(self, proof: NucTokenEnvelope) -> Self:
        """
        Set the proof for the token to be built.

        It's recommended to call :meth:`NucTokenBuilder.extending` which also takes care of pulling
        other important fields.

        Arguments
        ---------

        proof
            The token to be used as proof.
        """

        self._proof = proof
        return self

    def build(self, key: PrivateKey) -> str:
        """
        Build the token, signing it using the given private key.

        Arguments
        ---------

        key
            The key to use to sign the token.
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
            proofs = "/".join([proof.serialize() for proof in all_proofs])
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
