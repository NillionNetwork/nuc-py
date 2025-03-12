from datetime import UTC, datetime
import json

from secp256k1 import PrivateKey
from nuc.builder import NucTokenBuilder
from nuc.envelope import NucTokenEnvelope, urlsafe_base64_decode
from nuc.policy import Policy
from nuc.token import Command, DelegationBody, Did, NucToken


class TestNucTokenBuilder:
    def test_extend(self):
        key = PrivateKey()
        base = (
            NucTokenBuilder.delegation([Policy.equals(".foo", 42)])
            .audience(Did(bytes([0xBB] * 33)))
            .subject(Did(bytes([0xCC] * 33)))
            .command(Command(["nil", "db", "read"]))
            .build(key)
        )
        base = NucTokenEnvelope.parse(base)

        ext = (
            NucTokenBuilder.extending(base).audience(Did(bytes([0xDD] * 33))).build(key)
        )
        ext = NucTokenEnvelope.parse(ext)

        assert ext.token.token.command == base.token.token.command
        assert ext.token.token.subject == base.token.token.subject

        proofs = ext.proofs
        assert len(proofs) == 1
        assert proofs[0] == base.token

    def test_encode_decode(self):
        key = PrivateKey()
        token = (
            NucTokenBuilder.delegation([])
            .audience(Did(bytes([0xBB] * 33)))
            .subject(Did(bytes([0xCC] * 33)))
            .command(Command(["nil", "db", "read"]))
            .not_before(datetime.fromtimestamp(1740494955, tz=UTC))
            .expires_at(datetime.fromtimestamp(1740495955, tz=UTC))
            .nonce(bytes([1, 2, 3]))
            .meta({"name": "bob"})
            .build(key)
        )
        envelope = NucTokenEnvelope.parse(token)
        envelope.validate_signatures()

        [header, _] = token.split(".", 1)
        assert json.loads(urlsafe_base64_decode(header)) == json.loads(
            '{"alg": "ES256K"}'
        )

        expected_token = NucToken(
            issuer=Did(key.pubkey.serialize()),  # type: ignore
            audience=Did(bytes([0xBB] * 33)),
            subject=Did(bytes([0xCC] * 33)),
            command=Command(["nil", "db", "read"]),
            not_before=datetime.fromtimestamp(1740494955, tz=UTC),
            expires_at=datetime.fromtimestamp(1740495955, tz=UTC),
            nonce=bytes([1, 2, 3]),
            meta={"name": "bob"},
            body=DelegationBody([]),
            proofs=[],
        )
        assert envelope.token.token == expected_token

    def test_chain(self):
        # Build a root NUC
        root_key = PrivateKey()
        root = (
            NucTokenBuilder.delegation([Policy.equals(".foo", 42)])
            .audience(Did(bytes([0xBB] * 33)))
            .subject(Did(bytes([0xCC] * 33)))
            .command(Command(["nil", "db", "read"]))
            .build(root_key)
        )
        root = NucTokenEnvelope.parse(root)
        root.validate_signatures()

        # Build a delegation using the above proof
        other_key = PrivateKey()
        delegation = (
            NucTokenBuilder.delegation([Policy.equals(".foo", 42)])
            .audience(Did(bytes([0xBB] * 33)))
            .subject(Did(bytes([0xCC] * 33)))
            .command(Command(["nil", "db", "read"]))
            .proof(root)
            .build(other_key)
        )
        delegation = NucTokenEnvelope.parse(delegation)
        delegation.validate_signatures()

        # Ensure the tokens are linked
        assert delegation.token.token.proofs == [root.token.compute_hash()]
        assert len(delegation.proofs) == 1
        assert delegation.proofs[0] == root.token

        # Build an invocation using the above proof
        yet_another_key = PrivateKey()
        invocation = (
            NucTokenBuilder.invocation({"beep": 42})
            .audience(Did(bytes([0xBB] * 33)))
            .subject(Did(bytes([0xCC] * 33)))
            .command(Command(["nil", "db", "read"]))
            .proof(delegation)
            .build(yet_another_key)
        )
        invocation = NucTokenEnvelope.parse(invocation)
        invocation.validate_signatures()

        # Ensure both delegations are included as proof
        assert invocation.token.token.proofs == [delegation.token.compute_hash()]
        proofs = invocation.proofs
        assert len(proofs) == 2
        assert proofs[0] == delegation.token
        assert proofs[1] == root.token

    def decode_specific(self):
        token = "eyJhbGciOiJFUzI1NksifQ.eyJpc3MiOiJkaWQ6bmlsOjAyMjZhNGQ0YTRhNWZhZGUxMmM1ZmYwZWM5YzQ3MjQ5ZjIxY2Y3N2EyMDI3NTFmOTU5ZDVjNzc4ZjBiNjUyYjcxNiIsImF1ZCI6ImRpZDpuaWw6YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiIiwic3ViIjoiZGlkOm5pbDpjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2MiLCJjbWQiOiIvbmlsL2RiL3JlYWQiLCJhcmdzIjp7ImZvbyI6NDJ9LCJub25jZSI6IjAxMDIwMyIsInByZiI6WyJjOTA0YzVhMWFiMzY5YWVhMWI0ZDlkMTkwMmE0NmU2ZWY5NGFhYjk2OTY0YmI1MWQ2MWE2MWIwM2UyM2Q1ZGZmIl19.ufDYxqoSVNVETrVKReu0h_Piul5c6RoC_VnGGLw04mkyn2OMrtQjK92sGXNHCjlp7T9prIwxX14ZB_N3gx7hPg/eyJhbGciOiJFUzI1NksifQ.eyJpc3MiOiJkaWQ6bmlsOjAzNmY3MDdmYmVmMGI3NTIxMzgwOGJiYmY1NGIxODIxNzZmNTMyMGZhNTIwY2I4MTlmMzViNWJhZjIzMjM4YTAxNSIsImF1ZCI6ImRpZDpuaWw6YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiIiwic3ViIjoiZGlkOm5pbDpjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2MiLCJjbWQiOiIvbmlsL2RiL3JlYWQiLCJwb2wiOltbIj09IiwiLmZvbyIsNDJdXSwibm9uY2UiOiIwMTAyMDMiLCJwcmYiOlsiODZjZGI1ZjZjN2M3NDFkMDBmNmI4ODMzZDI0ZjdlY2Y5MWFjOGViYzI2MzA3MmZkYmU0YTZkOTQ5NzIwMmNiNCJdfQ.drGzkA0hYP8h62GxNN3fhi9bKjYgjpSy4cM52-9RsyB7JD6O6K1wRsg_x1hv8ladPmChpwDVVXOzjNr2NRVntA/eyJhbGciOiJFUzI1NksifQ.eyJpc3MiOiJkaWQ6bmlsOjAzOTU5MGNjYWYxMDI0ZjQ5YzljZjc0M2Y4YTZlZDQyMDNlNzgyZThlZTA5YWZhNTNkMWI1NzY0OTg0NjEyMzQyNSIsImF1ZCI6ImRpZDpuaWw6YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiIiwic3ViIjoiZGlkOm5pbDpjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2MiLCJjbWQiOiIvbmlsL2RiL3JlYWQiLCJwb2wiOltbIj09IiwiLmZvbyIsNDJdXSwibm9uY2UiOiIwMTAyMDMiLCJwcmYiOltdfQ.o3lnQxCjDCW10UuRABrHp8FpB_C6q1xgEGvfuXTb7Epp63ry8R2h0wHjToDKDFmkmUmO2jcBkrttuy8kftV6og"

        # this is a token generated by the above function
        NucTokenEnvelope.parse(token).validate_signatures()
