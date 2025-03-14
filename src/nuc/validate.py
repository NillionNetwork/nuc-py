"""
NUC validation.
"""

import itertools
from enum import Enum
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import Any, Dict, List

from nuc.envelope import DecodedNucToken, InvalidSignatureException, NucTokenEnvelope
from nuc.policy import (
    AndConnector,
    AnyOfOperator,
    EqualsOperator,
    NotConnector,
    NotEqualsOperator,
    OperatorPolicy,
    OrConnector,
    Policy,
)
from nuc.token import DelegationBody, Did, InvocationBody, NucToken


@dataclass
class InvocationRequirement:
    """
    Require an invocation.
    """

    audience: Did


@dataclass
class DelegationRequirement:
    """
    Require a delegation.
    """

    audience: Did


@dataclass
class ValidationParameters:
    """
    Parameters used during token validation.
    """

    current_time: datetime
    max_chain_length: int
    max_policy_width: int
    max_policy_depth: int
    token_requirements: InvocationRequirement | DelegationRequirement | None

    @staticmethod
    def default() -> "ValidationParameters":
        """
        Build the default validation parameters.
        """

        return ValidationParameters(
            current_time=datetime.now(timezone.utc),
            max_chain_length=5,
            max_policy_width=10,
            max_policy_depth=5,
            token_requirements=None,
        )


class NucTokenValidator:
    """
    A validator for NUC tokens.

    Example
    -------

    .. code-block:: py3

        from nuc.validate import NucTokenValidator
        from nuc.token import NucToken


        token = NucToken.parse(
            {
                "iss": "did:nil:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "aud": "did:nil:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "sub": "did:nil:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "cmd": "/nil/db/read",
                "pol": [["==", ".foo", 42]],
                "nonce": "beef",
            }
        )

        validator = NucTokenValidator([])
        validator.validate(token)

    """

    def __init__(self, root_issuers: List[Did]) -> None:
        """
        Construct a new token validator.

        Arguments
        ---------

        root_issuers
            The list of entities that can issue root tokens.
        """
        self._root_issuers = set(root_issuers)

    def validate(
        self,
        envelope: NucTokenEnvelope,
        parameters: ValidationParameters = ValidationParameters.default(),
    ) -> None:
        """
        Validate a NUC token using the given parameters.

        This will raise an exception if validation fails.

        Arguments
        ---------

        envelope
            The token to be validated.
        parameters
            The validation parameters.
        """

        if len(envelope.proofs) + 1 > parameters.max_chain_length:
            raise ValidationException(ValidationKind.CHAIN_TOO_LONG)

        token = envelope.token.token
        match token.proofs:
            case []:
                proofs = []
            case [proof_hash]:
                proofs = self._sort_proofs(proof_hash, envelope.proofs)
            case _:
                raise ValidationException(ValidationKind.TOO_MANY_PROOFS)
        # Build a chain from root token up to the token itself
        token_chain = [token, *proofs]
        token_chain.reverse()
        self._validate_proofs(proofs)
        self._validate_token_chain(token_chain, parameters)
        self._validate_token(token, proofs, parameters.token_requirements)
        try:
            envelope.validate_signatures()
        except InvalidSignatureException as ex:
            raise ValidationException(ValidationKind.INVALID_SIGNATURES) from ex

    def _validate_proofs(self, proofs: List[NucToken]) -> None:
        if not proofs:
            return

        if proofs[-1].issuer not in self._root_issuers:
            raise ValidationException(ValidationKind.ROOT_KEY_SIGNATURE_MISSING)

        for proof in proofs:
            match proof.body:
                case DelegationBody():
                    pass
                case InvocationBody():
                    raise ValidationException(ValidationKind.PROOFS_MUST_BE_DELEGATIONS)

    @staticmethod
    def _validate_token_chain(
        tokens: List[NucToken], parameters: ValidationParameters
    ) -> None:
        for previous, current in itertools.pairwise(tokens):
            NucTokenValidator._validate_relationship_properties(previous, current)
        for token in tokens:
            NucTokenValidator._validate_temporal_properties(
                token, parameters.current_time
            )
        for token in tokens:
            if isinstance(token.body, DelegationBody):
                NucTokenValidator._validate_policies_properties(
                    token.body.policies, parameters
                )
        if len(tokens) >= 2:
            token = tokens[1]
            _validate(
                token.issuer == token.subject, ValidationKind.SUBJECT_NOT_IN_CHAIN
            )

    @staticmethod
    def _validate_relationship_properties(
        previous: NucToken, current: NucToken
    ) -> None:
        _validate(
            previous.audience == current.issuer, ValidationKind.ISSUER_AUDIENCE_MISMATCH
        )
        _validate(
            previous.subject == current.subject, ValidationKind.DIFFERENT_SUBJECTS
        )
        _validate(
            current.command.is_attenuation_of(previous.command),
            ValidationKind.COMMAND_NOT_ATTENUATED,
        )
        if previous.not_before and current.not_before:
            _validate(
                previous.not_before <= current.not_before,
                ValidationKind.NOT_BEFORE_BACKWARDS,
            )

    @staticmethod
    def _validate_temporal_properties(token: NucToken, current_time: datetime) -> None:
        if token.expires_at:
            _validate(token.expires_at >= current_time, ValidationKind.TOKEN_EXPIRED)
        if token.not_before:
            _validate(
                current_time >= token.not_before, ValidationKind.NOT_BEFORE_NOT_MET
            )

    @staticmethod
    def _validate_policies_properties(
        policies: List[Policy], parameters: ValidationParameters
    ) -> None:
        _validate(
            len(policies) <= parameters.max_policy_width, ValidationKind.POLICY_TOO_WIDE
        )
        for policy in policies:
            properties = PolicyTreeProperties.from_policy(policy)
            _validate(
                properties.max_policy_width <= parameters.max_policy_width,
                ValidationKind.POLICY_TOO_WIDE,
            )
            _validate(
                properties.max_depth <= parameters.max_policy_depth,
                ValidationKind.POLICY_TOO_DEEP,
            )

    @staticmethod
    def _validate_token(
        token: NucToken,
        proofs: List[NucToken],
        token_requirements: InvocationRequirement | DelegationRequirement | None,
    ) -> None:
        print(token_requirements)
        match token.body:
            case DelegationBody():
                match token_requirements:
                    case InvocationRequirement():
                        raise ValidationException(ValidationKind.NEED_INVOCATION)
                    case DelegationRequirement(audience):
                        _validate(
                            token.audience == audience, ValidationKind.INVALID_AUDIENCE
                        )
                    case None:
                        pass
            case InvocationBody():
                match token_requirements:
                    case InvocationRequirement(audience):
                        _validate(
                            token.audience == audience, ValidationKind.INVALID_AUDIENCE
                        )
                    case DelegationRequirement(audience):
                        raise ValidationException(ValidationKind.NEED_DELEGATION)
                    case None:
                        pass

                token_json = token.to_json()
                for proof in proofs:
                    NucTokenValidator._validate_policy_matches(proof, token_json)

    @staticmethod
    def _validate_policy_matches(proof: NucToken, token_json: Dict[str, Any]) -> None:
        match proof.body:
            case DelegationBody(policies):
                for policy in policies:
                    if not policy.matches(token_json):
                        raise ValidationException(ValidationKind.POLICY_NOT_MET)
            case InvocationBody():
                raise ValidationException(ValidationKind.PROOFS_MUST_BE_DELEGATIONS)

    @staticmethod
    def _sort_proofs(
        starting_hash: bytes, proofs: List[DecodedNucToken]
    ) -> List[NucToken]:
        indexed_proofs = dict((proof.compute_hash(), proof.token) for proof in proofs)
        sorted_proofs: List[NucToken] = []
        next_hash = starting_hash
        while True:
            next_proof = indexed_proofs.get(next_hash)
            if not next_proof:
                raise ValidationException(ValidationKind.MISSING_PROOF)
            indexed_proofs.pop(next_hash)
            sorted_proofs.append(next_proof)
            match next_proof.proofs:
                case []:
                    break
                case [proof_hash]:
                    next_hash = proof_hash
                case _:
                    raise ValidationException(ValidationKind.TOO_MANY_PROOFS)
        if indexed_proofs:
            raise ValidationException(ValidationKind.UNCHAINED_PROOFS)
        return sorted_proofs


class ValidationKind(Enum):
    """
    The kind of validation that failed.
    """

    CHAIN_TOO_LONG = "token chain is too long"
    COMMAND_NOT_ATTENUATED = "command is not an attenuation"
    DIFFERENT_SUBJECTS = "different subjects in chain"
    INVALID_AUDIENCE = "invalid audience"
    INVALID_SIGNATURES = "invalid signatures"
    ISSUER_AUDIENCE_MISMATCH = "issuer/audience mismatch"
    MISSING_PROOF = "proof is missing"
    NEED_DELEGATION = "token must be a delegation"
    NEED_INVOCATION = "token must be an invocation"
    NOT_BEFORE_BACKWARDS = "`not before` cannot move backwards"
    NOT_BEFORE_NOT_MET = "`not before` date not met"
    POLICY_NOT_MET = "policy not met"
    POLICY_TOO_DEEP = "policy is too deep"
    POLICY_TOO_WIDE = "policy is too wide"
    PROOFS_MUST_BE_DELEGATIONS = "proofs must be delegations"
    ROOT_KEY_SIGNATURE_MISSING = "root NUC is not signed by root keypair"
    SUBJECT_NOT_IN_CHAIN = "subject not in chain"
    TOKEN_EXPIRED = "token is expired"
    TOO_MANY_PROOFS = "up to one `prf` in a token is allowed"
    UNCHAINED_PROOFS = "extra proofs not part of chain provided"


class ValidationException(Exception):
    """
    Token validation failed.
    """

    def __init__(self, kind: ValidationKind) -> None:
        super().__init__(self, f"validation failed: {kind}")
        self.kind = kind


def _validate(condition: bool, validation: ValidationKind) -> None:
    if not condition:
        raise ValidationException(validation)


@dataclass
class PolicyTreeProperties:
    """
    The properties of a policy tree.
    """

    max_depth: int
    max_policy_width: int

    @staticmethod
    def from_policy(root_policy: Policy) -> "PolicyTreeProperties":
        """
        Construct a policy tree properties object from a policy.
        """

        match root_policy.body:
            case AndConnector() | OrConnector():
                properties = PolicyTreeProperties(
                    max_depth=0, max_policy_width=len(root_policy.body.policies)
                )
                for policy in root_policy.body.policies:
                    inner_properties = PolicyTreeProperties.from_policy(policy)
                    properties.max_depth = max(
                        properties.max_depth, inner_properties.max_depth
                    )
                    properties.max_policy_width = max(
                        properties.max_policy_width, inner_properties.max_policy_width
                    )
                properties.max_depth += 1
                return properties
            case NotConnector(policy):
                properties = PolicyTreeProperties.from_policy(policy)
                properties.max_depth += 1
                return properties
            case OperatorPolicy():
                match root_policy.body.operator:
                    case EqualsOperator() | NotEqualsOperator():
                        return PolicyTreeProperties(max_depth=1, max_policy_width=1)
                    case AnyOfOperator(choices):
                        return PolicyTreeProperties(
                            max_depth=1, max_policy_width=len(choices)
                        )
