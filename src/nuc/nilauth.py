"""
nilauth client.
"""

import logging
import hashlib
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass
import secrets
import json
from time import sleep
from typing import Any, Dict, List
import requests
from secp256k1 import PrivateKey, PublicKey

from nuc.payer import Payer
from nuc.envelope import NucTokenEnvelope
from nuc.builder import NucTokenBuilder
from nuc.token import Command, Did, InvocationBody

logger = logging.getLogger(__name__)


DEFAULT_REQUEST_TIMEOUT: float = 10
PAYMENT_TX_RETRIES: List[int] = [1, 2, 3, 5, 10, 10, 10]
TX_NOT_COMMITTED_ERROR_CODE: str = "TRANSACTION_NOT_COMMITTED"


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
class Subscription:
    """
    Information about a subscription.
    """

    expires_at: datetime
    """
    The timestamp at which this subscription expires.
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
        payload = {
            "nonce": secrets.token_bytes(16).hex(),
            "target_public_key": public_key.serialize().hex(),
            "expires_at": int(expires_at.timestamp()),
        }
        request = self._create_signed_request(payload, key)
        response = self._post(
            f"{self._base_url}/api/v1/nucs/create",
            request,
        )
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
        logger.info("Submitting payment to nilauth with tx hash %s", tx_hash)

        request = {
            "tx_hash": tx_hash,
            "payload": payload.hex(),
            "public_key": our_public_key.serialize().hex(),
        }

        for sleep_time in PAYMENT_TX_RETRIES:
            try:
                return self._post(
                    f"{self._base_url}/api/v1/payments/validate",
                    request,
                )
            except RequestException as e:
                if e.error_code == TX_NOT_COMMITTED_ERROR_CODE:
                    logger.warning(
                        "Server couldn't process payment transaction, retrying in %s",
                        sleep_time,
                    )
                    sleep(sleep_time)
                else:
                    raise
        raise PaymentValidationException(tx_hash, payload)

    def subscription_status(self, key: PrivateKey) -> Subscription | None:
        """
        Get the status of a subscription.

        Arguments
        ---------

        key
            The key for which to get the subscription information.

        .. note:: The private key is only used to sign a payload to prove ownership and is
            never transmitted anywhere.
        """

        expires_at = datetime.now(timezone.utc) + timedelta(minutes=1)
        payload = {
            "nonce": secrets.token_bytes(16).hex(),
            "expires_at": int(expires_at.timestamp()),
        }
        request = self._create_signed_request(payload, key)
        response = self._post(
            f"{self._base_url}/api/v1/subscriptions/status",
            request,
        )
        subscription = response["subscription"]
        if not subscription:
            return None
        return Subscription(
            datetime.fromtimestamp(subscription["expires_at"], timezone.utc)
        )

    def about(self) -> NilauthAbout:
        """
        Get information about the nilauth server.
        """
        about = self._get(f"{self._base_url}/about")
        raw_public_key = bytes.fromhex(about["public_key"])
        public_key = PublicKey(raw_public_key, raw=True)
        return NilauthAbout(public_key=public_key)

    def subscription_cost(self) -> int:
        """
        Get the subscription cost in unils.
        """

        response = self._get(f"{self._base_url}/api/v1/payments/cost")
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
        self._post(
            f"{self._base_url}/api/v1/revocations/revoke",
            {},
            headers={"Authorization": f"Bearer {invocation}"},
        )

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
        response = self._post(
            f"{self._base_url}/api/v1/revocations/lookup",
            request,
        )
        return [RevokedToken(**t) for t in response["revoked"]]

    def _get(self, url: str, **kwargs) -> Any:
        response = requests.get(url, timeout=self._timeout_seconds, **kwargs)
        return self._response_as_json(response)

    def _post(self, url: str, body: Any, **kwargs) -> Any:
        response = requests.post(
            url, timeout=self._timeout_seconds, json=body, **kwargs
        )
        return self._response_as_json(response)

    @staticmethod
    def _response_as_json(response: requests.Response) -> Any:
        body_json = response.json()
        code = response.status_code
        if 200 <= code < 300:
            return body_json
        message = body_json.get("message")
        error_code = body_json.get("error_code")
        if not message or not error_code:
            raise RequestException(
                "server did not reply with any error messages", "UNKNOWN"
            )
        raise RequestException(message, error_code)

    @staticmethod
    def _create_signed_request(payload: Any, key: PrivateKey) -> Dict[str, Any]:
        payload = json.dumps(payload).encode("utf8")
        signature = key.ecdsa_serialize_compact(key.ecdsa_sign(payload))
        return {
            "public_key": key.pubkey.serialize().hex(),  # type: ignore
            "signature": signature.hex(),
            "payload": payload.hex(),
        }


class RequestException(Exception):
    """
    An exception raised when a request fails.
    """

    message: str
    error_code: str

    def __init__(self, message: str, error_code: str) -> None:
        super().__init__(self, f"{error_code}: {message}")
        self.message = message
        self.error_code = error_code


class PaymentValidationException(Exception):
    """
    An exception raised when the validation for a payment fails.
    """

    tx_hash: str
    payload: bytes

    def __init__(self, tx_hash: str, payload: bytes) -> None:
        super().__init__(
            self,
            f"failed to validate payment: tx_hash='{tx_hash}', payload='{payload.hex()}'",
        )
        self.tx_hash = tx_hash
        self.payload = payload
