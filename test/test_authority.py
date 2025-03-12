from unittest.mock import patch
from secp256k1 import PrivateKey, PublicKey

from nuc.builder import NucTokenBuilder
from nuc.authority import AuthorityService
from nuc.envelope import NucTokenEnvelope
from nuc.policy import Policy
from nuc.token import Command, Did


class TestAuthorityService:
    @patch("requests.post")
    def test_request_token(self, mock_post):
        base_url = "http://127.0.0.1"
        service = AuthorityService(base_url)
        root_key = PrivateKey()

        response_token = (
            NucTokenBuilder.delegation([Policy.equals(".foo", 42)])
            .audience(Did(bytes([0xBB] * 33)))
            .subject(Did(bytes([0xCC] * 33)))
            .command(Command(["nil", "db", "read"]))
            .build(root_key)
        )
        mock_post.return_value.json.return_value = {"token": response_token}

        key = PrivateKey()
        envelope = service.request_token(key)
        assert envelope.token == NucTokenEnvelope.parse(response_token).token

        invocation = mock_post.call_args_list[0]
        assert invocation.args == (f"{base_url}/api/v1/nucs/create",)

        pub_key: PublicKey = key.pubkey  # type: ignore
        params = invocation.kwargs.pop("json")
        assert params["public_key"] == pub_key.serialize().hex()
        assert pub_key.ecdsa_verify(
            bytes.fromhex(params["payload"]),
            key.ecdsa_deserialize_compact(bytes.fromhex(params["signature"])),
        )
