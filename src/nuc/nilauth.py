"""
nilauth client.
"""

import logging
import hashlib
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass
import secrets
import json
from typing import List
import requests
from secp256k1 import PrivateKey, PublicKey

from nuc.payer import Payer
from nuc.envelope import NucTokenEnvelope
from nuc.builder import NucTokenBuilder
from nuc.token import Command, Did, InvocationBody

logger = logging.getLogger(__name__)


DEFAULT_REQUEST_TIMEOUT: float = 10


@dataclass
class NilauthAbout:
    """
    Information about a nilauth server.
    """

    public_key: PublicKey
    """
    The server's public key.
    """


@dataclass
class RevokedToken:
    """
    A revoked token.
    """

    token_hash: bytes
    revoked_at: datetime


class NilauthClient:
    """
    A class to interact with nilauth.

    Example
    -------

    .. code-block:: py3

        from secp256k1 import PrivateKey
        from nuc.nilauth import NilauthClient

        # Create a client to talk to nilauth at the given url.
        client = NilauthClient(base_url)

        # Create a private key.
        key = PrivateKey()

        # Request a token for it.
        token = client.request_token(key)
    """

    def __init__(self, base_url: str, timeout_seconds=DEFAULT_REQUEST_TIMEOUT) -> None:
        """
        Construct a new client to talk to nilauth.

        Arguments
        ---------

        base_url
            nilauth's URL.
        timeout_seconds
            The timeout to use for all requests.
        """

        self._base_url = base_url
        self._timeout_seconds = timeout_seconds

    def request_token(self, key: PrivateKey) -> str:
        """
        Request a token, issued to the public key tied to the given private key.

        Arguments
        ---------

        key
            The key for which the token should be issued to.

        .. note:: The private key is only used to sign a payload to prove ownership and is
            never transmitted anywhere.
        """

        public_key = self.about().public_key

        expires_at = datetime.now(timezone.utc) + timedelta(minutes=1)
        payload = json.dumps(
            {
                "nonce": secrets.token_bytes(16).hex(),
                "target_public_key": public_key.serialize().hex(),
                "expires_at": int(expires_at.timestamp()),
            }
        ).encode("utf8")
        signature = key.ecdsa_serialize_compact(key.ecdsa_sign(payload))
        request = {
            "public_key": key.pubkey.serialize().hex(),  # type: ignore
            "signature": signature.hex(),
            "payload": payload.hex(),
        }
        response = requests.post(
            f"{self._base_url}/api/v1/nucs/create",
            json=request,
            timeout=self._timeout_seconds,
        )
        response.raise_for_status()
        response = response.json()
        return response["token"]

    def pay_subscription(
        self,
        our_public_key: PublicKey,
        payer: Payer,
    ) -> None:
        """
        Pay for a subscription.

        Arguments
        ---------

        our_public_key
            The public key the subscription is for.
        payer
            The payer that will be used.
        """
        public_key = self.about().public_key.serialize()
        cost = self.subscription_cost()
        payload = json.dumps(
            {
                "nonce": secrets.token_bytes(16).hex(),
                "service_public_key": public_key.hex(),
            }
        ).encode("utf8")
        # Note: add proper value later on
        tx_hash = payer.pay(hashlib.sha256(payload).digest(), amount_unil=cost)

        request = {
            "tx_hash": tx_hash,
            "payload": payload.hex(),
            "public_key": our_public_key.serialize().hex(),
        }

        response = requests.post(
            f"{self._base_url}/api/v1/payments/validate",
            json=request,
            timeout=self._timeout_seconds,
        )
        response.raise_for_status()

    def about(self) -> NilauthAbout:
        """
        Get information about the nilauth server.
        """
        response = requests.get(
            f"{self._base_url}/about", timeout=self._timeout_seconds
        )
        response.raise_for_status()
        about = response.json()
        raw_public_key = bytes.fromhex(about["public_key"])
        public_key = PublicKey(raw_public_key, raw=True)
        return NilauthAbout(public_key=public_key)

    def subscription_cost(self) -> int:
        """
        Get the subscription cost in unils.
        """

        response = requests.get(
            f"{self._base_url}/api/v1/payments/cost", timeout=self._timeout_seconds
        )
        response.raise_for_status()
        response = response.json()
        return response["cost_unils"]

    def revoke_token(self, token: NucTokenEnvelope, key: PrivateKey) -> None:
        """
        Revoke a token.

        Arguments
        ---------

        token
            The token to be revoked.
        key
            The private key to use to mint the token.
        """
        about = self.about()
        serialized_token = token.serialize()
        auth_token = self.request_token(key)
        auth_token = NucTokenEnvelope.parse(auth_token)
        auth_token.validate_signatures()
        args = {"token": serialized_token}
        invocation = (
            NucTokenBuilder.extending(auth_token)
            .body(InvocationBody(args))
            .command(Command(["nuc", "revoke"]))
            .audience(Did(about.public_key.serialize()))
            .build(key)
        )
        response = requests.post(
            f"{self._base_url}/api/v1/revocations/revoke",
            headers={"Authorization": f"Bearer {invocation}"},
            timeout=self._timeout_seconds,
        )
        response.raise_for_status()

    def lookup_revoked_tokens(self, envelope: NucTokenEnvelope) -> List[RevokedToken]:
        """
        Lookup revoked tokens that would invalidate the given token.

        Arguments
        ---------

        envelope
            The token envelope to do lookups for.
        """

        hashes = [t.compute_hash().hex() for t in (envelope.token, *envelope.proofs)]
        request = {"hashes": hashes}
        response = requests.post(
            f"{self._base_url}/api/v1/revocations/lookup",
            json=request,
            timeout=self._timeout_seconds,
        )
        response.raise_for_status()
        return [RevokedToken(**t) for t in response.json()["revoked"]]
