"""
Authority service APIs.
"""

from dataclasses import dataclass
import secrets
import json
import requests
from secp256k1 import PrivateKey


DEFAULT_REQUEST_TIMEOUT: float = 10


@dataclass()
class AuthorityServiceAbout:
    """
    Information about the authority service.
    """

    public_key: bytes


class AuthorityService:
    """
    A class to interact with the authority service.
    """

    def __init__(self, base_url: str, timeout_seconds=DEFAULT_REQUEST_TIMEOUT) -> None:
        self._base_url = base_url
        self._timeout_seconds = timeout_seconds

    def request_token(self, key: PrivateKey) -> str:
        """
        Request a token, issued to the public key tied to the given private key.
        """

        payload = json.dumps(
            {
                "nonce": list(secrets.token_bytes(16)),
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

    def about(self) -> AuthorityServiceAbout:
        """
        Get information about the authority service.
        """
        response = requests.get(
            f"{self._base_url}/about", timeout=self._timeout_seconds
        )
        response.raise_for_status()
        about = response.json()
        return AuthorityServiceAbout(public_key=bytes.fromhex(about["public_key"]))
