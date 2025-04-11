from datetime import datetime, timezone
import pytest
import itertools
from dataclasses import dataclass
from typing import List

from secp256k1 import PrivateKey

from nuc.builder import NucTokenBuilder
from nuc.envelope import NucTokenEnvelope, urlsafe_base64_decode, urlsafe_base64_encode
from nuc.policy import Policy
from nuc.token import Command, Did
from nuc.validate import (
    DelegationRequirement,
    InvocationRequirement,
    NucTokenValidator,
    PolicyTreeProperties,
    ValidationException,
    ValidationKind,
    ValidationParameters,
)

ROOT_KEYS: List[PrivateKey] = [PrivateKey()]
ROOT_DIDS: List[Did] = [Did(key.pubkey.serialize()) for key in ROOT_KEYS]  # type: ignore


@dataclass
class SignableNucTokenBuilder:
    signing_key: PrivateKey
    builder: NucTokenBuilder

    def build(self) -> str:
        return self.builder.build(self.signing_key)

    @staticmethod
    def issued_by_root(builder: NucTokenBuilder) -> "SignableNucTokenBuilder":
        return SignableNucTokenBuilder(ROOT_KEYS[0], builder)


class Chainer:
    def __init__(self, chain_issuer_audience: bool = True) -> None:
        self._chain_issuer_audience = chain_issuer_audience

    def chain(self, builders: List[SignableNucTokenBuilder]) -> NucTokenEnvelope:
        if self._chain_issuer_audience:
            for previous, current in itertools.pairwise(builders):
                issuer_key = current.signing_key.pubkey.serialize()  # type: ignore
                previous.builder = previous.builder.audience(Did(issuer_key))

        # Chain tokens based on their hash
        iterator = iter(builders)
        envelope = NucTokenEnvelope.parse(next(iterator).build())
        for builder in iterator:
            builder.builder = builder.builder.proof(envelope)
            envelope = NucTokenEnvelope.parse(builder.build())
        return envelope


class Asserter:
    def __init__(
        self, parameters: ValidationParameters = ValidationParameters.default()
    ) -> None:
        self._parameters = parameters
        self._root_dids = ROOT_DIDS

    def assert_failure(
        self, envelope: NucTokenEnvelope, expected_failure: ValidationKind
    ) -> None:
        self._log_tokens(envelope)
        validator = NucTokenValidator(self._root_dids)
        try:
            validator.validate(envelope, self._parameters)
            raise Exception("validation did not fail")
        except ValidationException as ex:
            assert ex.kind == expected_failure

    def assert_success(self, envelope: NucTokenEnvelope):
        self._log_tokens(envelope)
        validator = NucTokenValidator(self._root_dids)
        validator.validate(envelope, self._parameters)

    @staticmethod
    def _log_tokens(envelope: NucTokenEnvelope) -> None:
        print(f"token being asserted: {envelope.token.token.to_json()}")
        print(f"proofs for it: {[proof.token.to_json() for proof in envelope.proofs]}")


def _did_from_private_key(key: PrivateKey) -> Did:
    return Did(key.pubkey.serialize())  # type: ignore


def delegation(subject_key: PrivateKey) -> NucTokenBuilder:
    return (
        NucTokenBuilder.delegation([])
        .audience(Did(bytes([0xDE] * 33)))
        .subject(_did_from_private_key(subject_key))
    )


def invocation(subject_key: PrivateKey) -> NucTokenBuilder:
    return (
        NucTokenBuilder.invocation({})
        .audience(Did(bytes([0xDE] * 33)))
        .subject(_did_from_private_key(subject_key))
    )


class TestTokenValidator:
    @pytest.mark.parametrize(
        "policy,expected",
        [
            (
                Policy.equals(".field", 42),
                PolicyTreeProperties(max_depth=1, max_policy_width=1),
            ),
            (
                Policy.any_of(".field", [42, 1337]),
                PolicyTreeProperties(max_depth=1, max_policy_width=2),
            ),
            (
                Policy.not_(Policy.equals(".field", 42)),
                PolicyTreeProperties(max_depth=2, max_policy_width=1),
            ),
            (
                Policy.and_([Policy.equals(".field", 42)]),
                PolicyTreeProperties(max_depth=2, max_policy_width=1),
            ),
            (
                Policy.or_([Policy.equals(".field", 42)]),
                PolicyTreeProperties(max_depth=2, max_policy_width=1),
            ),
            (
                Policy.and_([Policy.equals(".field", 42), Policy.equals(".field", 42)]),
                PolicyTreeProperties(max_depth=2, max_policy_width=2),
            ),
            (
                Policy.or_([Policy.equals(".field", 42), Policy.equals(".field", 42)]),
                PolicyTreeProperties(max_depth=2, max_policy_width=2),
            ),
            (
                Policy.and_(
                    [
                        Policy.not_(Policy.equals(".field", 42)),
                        Policy.any_of(".field", [42, 1337]),
                    ]
                ),
                PolicyTreeProperties(max_depth=3, max_policy_width=2),
            ),
        ],
    )
    def test_policy_properties(self, policy: Policy, expected: PolicyTreeProperties):
        properties = PolicyTreeProperties.from_policy(policy)
        assert properties == expected

    def test_unlinked_chain(self):
        key = PrivateKey()
        base = delegation(key).command(Command(["nil"]))
        # Chain 2
        envelope = (
            Chainer()
            .chain(
                [
                    SignableNucTokenBuilder.issued_by_root(base),
                    SignableNucTokenBuilder(key, base),
                ]
            )
            .serialize()
        )

        # Now chain an extra one that nobody refers to.
        last = SignableNucTokenBuilder.issued_by_root(base).build()
        token = f"{envelope}/{last}"
        envelope = NucTokenEnvelope.parse(token)
        Asserter().assert_failure(envelope, ValidationKind.UNCHAINED_PROOFS)

    def test_chain_too_long(self):
        key = PrivateKey()
        base = delegation(key).command(Command(["nil"]))
        envelope = Chainer().chain(
            [
                SignableNucTokenBuilder.issued_by_root(base),
                SignableNucTokenBuilder(key, base),
                SignableNucTokenBuilder(key, base),
            ]
        )
        parameters = ValidationParameters.default()
        parameters.max_chain_length = 2
        Asserter(parameters).assert_failure(envelope, ValidationKind.CHAIN_TOO_LONG)

    def test_command_not_attenuated(self):
        key = PrivateKey()
        root = delegation(key).command(Command(["nil"]))
        last = delegation(key).command(Command(["bar"]))
        envelope = Chainer().chain(
            [
                SignableNucTokenBuilder.issued_by_root(root),
                SignableNucTokenBuilder(key, last),
            ]
        )
        Asserter().assert_failure(envelope, ValidationKind.COMMAND_NOT_ATTENUATED)

    def test_different_subjects(self):
        key1 = PrivateKey()
        key2_bytes = bytearray(bytes.fromhex(key1.serialize()))
        key2_bytes[0] ^= 1
        key2 = PrivateKey(bytes(key2_bytes))

        root = delegation(key1).command(Command(["nil"]))
        last = delegation(key2).command(Command(["nil"]))
        envelope = Chainer().chain(
            [
                SignableNucTokenBuilder.issued_by_root(root),
                SignableNucTokenBuilder(key2, last),
            ]
        )
        Asserter().assert_failure(envelope, ValidationKind.DIFFERENT_SUBJECTS)

    def test_audience_mismatch(self):
        key = PrivateKey()
        root = (
            delegation(key).command(Command(["nil"])).audience(Did(bytes([0xAA] * 33)))
        )
        last = delegation(key).command(Command(["nil"]))
        envelope = Chainer(chain_issuer_audience=False).chain(
            [
                SignableNucTokenBuilder.issued_by_root(root),
                SignableNucTokenBuilder(key, last),
            ]
        )
        Asserter().assert_failure(envelope, ValidationKind.ISSUER_AUDIENCE_MISMATCH)

    def test_invalid_audience_invocation(self):
        key = PrivateKey()
        expected_did = Did(bytes([0xAA] * 33))
        actual_did = Did(bytes([0xBB] * 33))
        root = delegation(key).command(Command(["nil"]))
        last = invocation(key).command(Command(["nil"])).audience(actual_did)
        envelope = Chainer().chain(
            [
                SignableNucTokenBuilder.issued_by_root(root),
                SignableNucTokenBuilder(key, last),
            ]
        )
        parameters = ValidationParameters.default()
        parameters.token_requirements = InvocationRequirement(expected_did)
        Asserter(parameters).assert_failure(envelope, ValidationKind.INVALID_AUDIENCE)

    def test_invalid_audience_delegation(self):
        key = PrivateKey()
        expected_did = Did(bytes([0xAA] * 33))
        actual_did = Did(bytes([0xBB] * 33))
        root = delegation(key).command(Command(["nil"]))
        last = delegation(key).command(Command(["nil"])).audience(actual_did)
        envelope = Chainer().chain(
            [
                SignableNucTokenBuilder.issued_by_root(root),
                SignableNucTokenBuilder(key, last),
            ]
        )
        parameters = ValidationParameters.default()
        parameters.token_requirements = DelegationRequirement(expected_did)
        Asserter(parameters).assert_failure(envelope, ValidationKind.INVALID_AUDIENCE)

    def test_invalid_signature(self):
        key = PrivateKey()
        root = delegation(key).command(Command(["nil"]))
        envelope = Chainer().chain(
            [
                SignableNucTokenBuilder.issued_by_root(root),
            ]
        )
        envelope = envelope.serialize()
        (header, payload, signature) = envelope.split(".")
        print(len(signature))
        signature = bytearray(urlsafe_base64_decode(signature))
        signature[0] ^= 1
        envelope = f"{header}.{payload}.{urlsafe_base64_encode(bytes(signature))}"
        envelope = NucTokenEnvelope.parse(envelope)

        asserter = Asserter()
        asserter._root_dids = []
        asserter.assert_failure(envelope, ValidationKind.INVALID_SIGNATURES)

    def test_missing_proof(self):
        key = PrivateKey()
        base = delegation(key).command(Command(["nil"]))
        envelope = (
            Chainer()
            .chain(
                [
                    SignableNucTokenBuilder.issued_by_root(base),
                    SignableNucTokenBuilder(key, base),
                ]
            )
            .serialize()
        )
        # Keep the token without its proof
        envelope = NucTokenEnvelope.parse(envelope.split("/")[0])
        Asserter().assert_failure(envelope, ValidationKind.MISSING_PROOF)

    def test_need_delegation(self):
        key = PrivateKey()
        root = delegation(key).command(Command(["nil"]))
        last = invocation(key).command(Command(["nil"]))
        envelope = Chainer().chain(
            [
                SignableNucTokenBuilder.issued_by_root(root),
                SignableNucTokenBuilder(key, last),
            ]
        )
        parameters = ValidationParameters.default()
        parameters.token_requirements = DelegationRequirement(Did(bytes([0xAA] * 33)))
        Asserter(parameters).assert_failure(envelope, ValidationKind.NEED_DELEGATION)

    def test_need_invocation(self):
        key = PrivateKey()
        root = delegation(key).command(Command(["nil"]))
        last = delegation(key).command(Command(["nil"]))
        envelope = Chainer().chain(
            [
                SignableNucTokenBuilder.issued_by_root(root),
                SignableNucTokenBuilder(key, last),
            ]
        )
        parameters = ValidationParameters.default()
        parameters.token_requirements = InvocationRequirement(Did(bytes([0xAA] * 33)))
        Asserter(parameters).assert_failure(envelope, ValidationKind.NEED_INVOCATION)

    def test_not_before_backwards(self):
        now = datetime.fromtimestamp(0, timezone.utc)
        root_not_before = datetime.fromtimestamp(5, timezone.utc)
        last_not_before = datetime.fromtimestamp(3, timezone.utc)
        key = PrivateKey()
        root = delegation(key).command(Command(["nil"])).not_before(root_not_before)
        last = delegation(key).command(Command(["nil"])).not_before(last_not_before)
        envelope = Chainer().chain(
            [
                SignableNucTokenBuilder.issued_by_root(root),
                SignableNucTokenBuilder(key, last),
            ]
        )
        parameters = ValidationParameters.default()
        parameters.current_time = now
        Asserter(parameters).assert_failure(
            envelope, ValidationKind.NOT_BEFORE_BACKWARDS
        )

    def test_proof_not_before_not_met(self):
        now = datetime.fromtimestamp(0, timezone.utc)
        not_before = datetime.fromtimestamp(10, timezone.utc)
        key = PrivateKey()
        root = delegation(key).command(Command(["nil"])).not_before(not_before)
        last = delegation(key).command(Command(["nil"]))
        envelope = Chainer().chain(
            [
                SignableNucTokenBuilder.issued_by_root(root),
                SignableNucTokenBuilder(key, last),
            ]
        )
        parameters = ValidationParameters.default()
        parameters.current_time = now
        Asserter(parameters).assert_failure(envelope, ValidationKind.NOT_BEFORE_NOT_MET)

    def test_root_policy_not_met(self):
        key = PrivateKey()
        subject = _did_from_private_key(key)
        root = (
            NucTokenBuilder.delegation([Policy.equals(".foo", 42)])
            .subject(subject)
            .command(Command(["nil"]))
        )
        last = (
            NucTokenBuilder.invocation({"bar": 1337})
            .subject(subject)
            .audience(Did(bytes([0xAA] * 33)))
            .command(Command(["nil"]))
        )
        envelope = Chainer().chain(
            [
                SignableNucTokenBuilder.issued_by_root(root),
                SignableNucTokenBuilder(key, last),
            ]
        )
        Asserter().assert_failure(envelope, ValidationKind.POLICY_NOT_MET)

    def test_last_policy_not_met(self):
        key = PrivateKey()
        subject = _did_from_private_key(key)
        root = NucTokenBuilder.delegation([]).subject(subject).command(Command(["nil"]))
        intermediate = (
            NucTokenBuilder.delegation([Policy.equals(".foo", 42)])
            .subject(subject)
            .command(Command(["nil"]))
        )
        last = (
            NucTokenBuilder.invocation({"bar": 1337})
            .subject(subject)
            .audience(Did(bytes([0xAA] * 33)))
            .command(Command(["nil"]))
        )
        envelope = Chainer().chain(
            [
                SignableNucTokenBuilder.issued_by_root(root),
                SignableNucTokenBuilder(key, intermediate),
                SignableNucTokenBuilder(key, last),
            ]
        )
        Asserter().assert_failure(envelope, ValidationKind.POLICY_NOT_MET)

    def test_policy_too_deep(self):
        policy = Policy.equals(".foo", 42)
        max_depth = 10
        for _ in range(max_depth + 1):
            policy = Policy.not_(policy)

        key = PrivateKey()
        subject = _did_from_private_key(key)
        root = (
            NucTokenBuilder.delegation([policy])
            .subject(subject)
            .command(Command(["nil"]))
        )
        last = delegation(key).command(Command(["nil"]))
        envelope = Chainer().chain(
            [
                SignableNucTokenBuilder.issued_by_root(root),
                SignableNucTokenBuilder(key, last),
            ]
        )
        parameters = ValidationParameters.default()
        parameters.max_policy_depth = max_depth
        Asserter(parameters).assert_failure(envelope, ValidationKind.POLICY_TOO_DEEP)

    def test_policy_too_wide(self):
        max_width = 10
        key = PrivateKey()
        subject = _did_from_private_key(key)
        root = (
            NucTokenBuilder.delegation([Policy.equals(".foo", 42)] * (max_width + 1))
            .subject(subject)
            .command(Command(["nil"]))
        )
        last = delegation(key).command(Command(["nil"]))
        envelope = Chainer().chain(
            [
                SignableNucTokenBuilder.issued_by_root(root),
                SignableNucTokenBuilder(key, last),
            ]
        )
        parameters = ValidationParameters.default()
        parameters.max_policy_width = max_width
        Asserter(parameters).assert_failure(envelope, ValidationKind.POLICY_TOO_WIDE)

    def test_proofs_must_be_delegations(self):
        key = PrivateKey()
        subject = _did_from_private_key(key)
        root = NucTokenBuilder.invocation({}).subject(subject).command(Command(["nil"]))
        last = (
            NucTokenBuilder.invocation({"bar": 1337})
            .subject(subject)
            .audience(Did(bytes([0xAA] * 33)))
            .command(Command(["nil"]))
        )
        envelope = Chainer().chain(
            [
                SignableNucTokenBuilder.issued_by_root(root),
                SignableNucTokenBuilder(key, last),
            ]
        )
        Asserter().assert_failure(envelope, ValidationKind.PROOFS_MUST_BE_DELEGATIONS)

    def test_root_key_signature_missing(self):
        key = PrivateKey()
        root = delegation(key).command(Command(["nil"]))
        last = delegation(key).command(Command(["nil"]))
        envelope = Chainer().chain(
            [
                SignableNucTokenBuilder(key, root),
                SignableNucTokenBuilder(key, last),
            ]
        )
        Asserter().assert_failure(envelope, ValidationKind.ROOT_KEY_SIGNATURE_MISSING)

    def test_subject_not_in_chain(self):
        subject_key = PrivateKey()
        key = PrivateKey()
        root = delegation(subject_key).command(Command(["nil"]))
        last = delegation(subject_key).command(Command(["nil"]))
        envelope = Chainer().chain(
            [
                SignableNucTokenBuilder.issued_by_root(root),
                SignableNucTokenBuilder(key, last),
            ]
        )
        Asserter().assert_failure(envelope, ValidationKind.SUBJECT_NOT_IN_CHAIN)

    def test_root_token_expired(self):
        now = datetime.fromtimestamp(10, timezone.utc)
        expires_at = datetime.fromtimestamp(5, timezone.utc)

        key = PrivateKey()
        root = delegation(key).command(Command(["nil"])).expires_at(expires_at)
        last = delegation(key).command(Command(["nil"]))
        envelope = Chainer().chain(
            [
                SignableNucTokenBuilder.issued_by_root(root),
                SignableNucTokenBuilder(key, last),
            ]
        )
        parameters = ValidationParameters.default()
        parameters.current_time = now
        Asserter(parameters).assert_failure(envelope, ValidationKind.TOKEN_EXPIRED)

    def test_last_token_expired(self):
        now = datetime.fromtimestamp(10, timezone.utc)
        expires_at = datetime.fromtimestamp(5, timezone.utc)

        key = PrivateKey()
        root = delegation(key).command(Command(["nil"]))
        last = delegation(key).command(Command(["nil"])).expires_at(expires_at)
        envelope = Chainer().chain(
            [
                SignableNucTokenBuilder.issued_by_root(root),
                SignableNucTokenBuilder(key, last),
            ]
        )
        parameters = ValidationParameters.default()
        parameters.current_time = now
        Asserter(parameters).assert_failure(envelope, ValidationKind.TOKEN_EXPIRED)

    def test_valid(self):
        subject_key = PrivateKey()
        subject = _did_from_private_key(subject_key)
        rpc_did = Did(bytes([0xAA] * 33))
        root = (
            NucTokenBuilder.delegation([Policy.equals(".args.foo", 42)])
            .subject(subject)
            .command(Command(["nil"]))
        )
        intermediate = (
            NucTokenBuilder.delegation([Policy.equals(".args.bar", 1337)])
            .subject(subject)
            .command(Command(["nil"]))
        )

        invocation_key = PrivateKey()
        invocation = (
            NucTokenBuilder.invocation({"foo": 42, "bar": 1337})
            .subject(subject)
            .audience(rpc_did)
            .command(Command(["nil", "bar", "foo"]))
        )
        envelope = Chainer().chain(
            [
                SignableNucTokenBuilder.issued_by_root(root),
                SignableNucTokenBuilder(subject_key, intermediate),
                SignableNucTokenBuilder(invocation_key, invocation),
            ]
        )
        parameters = ValidationParameters.default()
        parameters.token_requirements = InvocationRequirement(rpc_did)
        Asserter(parameters).assert_success(envelope)
