from unittest.mock import patch
from secp256k1 import PrivateKey, PublicKey

from nuc.builder import NucTokenBuilder
from nuc.authority import AuthorityServiceClient
from nuc.policy import Policy
from nuc.token import Command, Did


class TestAuthorityService:
    @patch("requests.post")
    @patch("requests.get")
    def test_request_token(self, mock_get, mock_post):
        base_url = "http://127.0.0.1"
        service = AuthorityServiceClient(base_url)
        root_key = PrivateKey()

        # Pretend like we get back a public key
        mock_get.return_value.json.return_value = {
            "public_key": PrivateKey().pubkey.serialize().hex()  # type: ignore
        }

        response_token = (
            NucTokenBuilder.delegation([Policy.equals(".foo", 42)])
            .audience(Did(bytes([0xBB] * 33)))
            .subject(Did(bytes([0xCC] * 33)))
            .command(Command(["nil", "db", "read"]))
            .build(root_key)
        )
        mock_post.return_value.json.return_value = {"token": response_token}

        key = PrivateKey()
        token = service.request_token(key)
        assert token == response_token

        invocation = mock_post.call_args_list[0]
        assert invocation.args == (f"{base_url}/api/v1/nucs/create",)

        pub_key: PublicKey = key.pubkey  # type: ignore
        params = invocation.kwargs.pop("json")
        assert params["public_key"] == pub_key.serialize().hex()
        assert pub_key.ecdsa_verify(
            bytes.fromhex(params["payload"]),
            key.ecdsa_deserialize_compact(bytes.fromhex(params["signature"])),
        )
