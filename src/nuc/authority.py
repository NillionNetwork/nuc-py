"""
Authority service APIs.
"""

import logging
import hashlib
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass
import secrets
import json
import requests
from secp256k1 import PrivateKey, PublicKey

from nuc.payer import Payer

logger = logging.getLogger(__name__)


DEFAULT_REQUEST_TIMEOUT: float = 10


@dataclass()
class AuthorityServiceAbout:
    """
    Information about the authority service.
    """

    public_key: PublicKey
    """
    The authority service's public key.
    """


class AuthorityServiceClient:
    """
    A class to interact with the authority service.

    Example
    -------

    .. code-block:: py3

        from secp256k1 import PrivateKey
        from nuc.authority import AuthorityServiceClient

        # Create a client to talk to the authority service at the given url.
        client = AuthorityServiceClient(base_url)

        # Create a private key.
        key = PrivateKey()

        # Request a token for it.
        token = client.request_token(key)
    """

    def __init__(self, base_url: str, timeout_seconds=DEFAULT_REQUEST_TIMEOUT) -> None:
        """
        Construct a new client to talk to the authority service.

        Arguments
        ---------

        base_url
            The authority service URL.
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
        payload = json.dumps(
            {
                "nonce": secrets.token_bytes(16).hex(),
                "service_public_key": public_key.hex(),
            }
        ).encode("utf8")
        # Note: add proper value later on
        tx_hash = payer.pay(hashlib.sha256(payload).digest(), amount_unil=1)

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

    def about(self) -> AuthorityServiceAbout:
        """
        Get information about the authority service.
        """
        response = requests.get(
            f"{self._base_url}/about", timeout=self._timeout_seconds
        )
        response.raise_for_status()
        about = response.json()
        raw_public_key = bytes.fromhex(about["public_key"])
        public_key = PublicKey(raw_public_key, raw=True)
        return AuthorityServiceAbout(public_key=public_key)
