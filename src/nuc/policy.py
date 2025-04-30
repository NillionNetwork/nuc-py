"""
NUC policy definitions.
"""

from dataclasses import dataclass
from typing import Any, List

from .selector import Selector, SelectorContext


@dataclass
class EqualsOperator:
    """
    An operator that checks for equality.
    """

    arg: Any


@dataclass
class NotEqualsOperator:
    """
    An operator that checks for inequality.
    """

    arg: Any


@dataclass
class AnyOfOperator:
    """
    An operator that checks that a value is within a list of values.
    """

    arg: List[Any]


@dataclass
class OperatorPolicy:
    """
    A policy that applies a selector on the NUC token and applies an operator to it.
    """

    selector: Selector
    operator: EqualsOperator | NotEqualsOperator | AnyOfOperator

    @staticmethod
    def parse(operator: str, data: Any) -> "OperatorPolicy":
        """
        Parse an operator policy.
        """

        keys = _ensure_list(data)
        raw_selector = _pop_next(keys, "selector")
        if not isinstance(raw_selector, str):
            raise MalformedPolicyException("selector must be a string")
        selector = Selector.parse(raw_selector)
        value = _pop_next(keys, "value")
        output = None
        match operator:
            case "==":
                output = EqualsOperator(value)
            case "!=":
                output = NotEqualsOperator(value)
            case "anyOf":
                if not isinstance(value, list):
                    raise MalformedPolicyException("'anyOf' expects list as value")
                output = AnyOfOperator(value)
            case _:
                raise MalformedPolicyException(f"invalid operator '{operator}'")
        return OperatorPolicy(selector, output)

    def serialize(self) -> List[Any]:
        """
        Serialize this policy as a list.
        """

        selector = str(self.selector)
        match self.operator:
            case EqualsOperator(arg):
                return ["==", selector, arg]
            case NotEqualsOperator(arg):
                return ["!=", selector, arg]
            case AnyOfOperator(args):
                return ["anyOf", selector, args]

    def matches(self, value: Any, context: SelectorContext) -> bool:
        """
        Checks whether this policy matches a value.
        """

        value = self.selector.apply(value, context)
        match self.operator:
            case EqualsOperator(arg):
                return arg == value
            case NotEqualsOperator(arg):
                return arg != value
            case AnyOfOperator(args):
                return any(value == arg for arg in args)


@dataclass
class AndConnector:
    """
    A connector that checks that a sequence of policies is valid.
    """

    policies: List["Policy"]


@dataclass
class OrConnector:
    """
    A connector that checks that at least policy in a sequence is valid.
    """

    policies: List["Policy"]


@dataclass
class NotConnector:
    """
    A connector that checks that at a policy is not valid
    """

    policy: "Policy"


type ConnectorPolicy = AndConnector | OrConnector | NotConnector


@dataclass
class Policy:
    """
    A policy that restricts how a NUC can be used.
    """

    body: OperatorPolicy | ConnectorPolicy

    @staticmethod
    def parse(data: Any) -> "Policy":
        """
        Parse a policy.

        Arguments
        ---------

        data
            The raw policy to be parsed.

        Example
        -------

        .. code-block:: py3

            from nuc.policy import Policy

            policy = Policy.parse(["eq", ".foo", 42])
        """

        keys = _ensure_list(data)
        op = _pop_next(keys, "operand")
        body = None
        match op:
            case "==" | "!=" | "anyOf":
                body = OperatorPolicy.parse(op, keys)
            case "and":
                body = AndConnector(_parse_policies(_pop_next(keys, "policies")))
            case "or":
                body = OrConnector(_parse_policies(_pop_next(keys, "policies")))
            case "not":
                body = NotConnector(Policy.parse(_pop_next(keys, "policy")))
            case _:
                raise MalformedPolicyException(f"invalid operator '{op}'")
        return Policy(body)

    def serialize(self) -> List[Any]:
        """
        Serialize this policy as a list.
        """

        match self.body:
            case OperatorPolicy():
                return self.body.serialize()
            case AndConnector(policies):
                return ["and", [policy.serialize() for policy in policies]]
            case OrConnector(policies):
                return ["or", [policy.serialize() for policy in policies]]
            case NotConnector(policy):
                return ["not", policy.serialize()]

    def matches(self, value: Any, context: SelectorContext) -> bool:
        """
        Checks whether this policy matches a value.

        Arguments
        ---------

        value
            The value to be matched.

        Example
        -------

        .. code-block:: py3

            from nuc.policy import Policy

            # Parse a policy
            policy = Policy.parse(["eq", ".foo", 42])

            # Ensure it matches a given value.
            assert policy.matches({ "foo": 42 })
        """

        match self.body:
            case OperatorPolicy():
                return self.body.matches(value, context)
            case AndConnector(policies):
                return bool(policies) and all(
                    policy.matches(value, context) for policy in policies
                )
            case OrConnector(policies):
                return any(policy.matches(value, context) for policy in policies)
            case NotConnector(policy):
                return not policy.matches(value, context)

    @staticmethod
    def equals(selector: str, value: Any) -> "Policy":
        """
        Create a policy that expects a selected value to equal another.

        Arguments
        ---------

        selector
            A jq-like selector.
        value
            The value that the value pointed to by the selector should match.

        Example
        -------

        .. code-block:: py3

            from nuc.policy import Policy

            policy = Policy.equals(".foo", 42)
            assert policy.matches({ "foo": 42 })

        """

        return Policy(OperatorPolicy(Selector.parse(selector), EqualsOperator(value)))

    @staticmethod
    def not_equals(selector: str, value: Any) -> "Policy":
        """
        Create a policy that expects a selected value to be distinct from another.

        Arguments
        ---------

        selector
            A jq-like selector.
        value
            The value that the value pointed to by the selector should not match.

        Example
        -------

        .. code-block:: py3

            from nuc.policy import Policy

            policy = Policy.not_equals(".foo", 42)
            assert policy.matches({ "foo": 1337 })
        """

        return Policy(
            OperatorPolicy(Selector.parse(selector), NotEqualsOperator(value))
        )

    @staticmethod
    def any_of(selector: str, values: List[Any]) -> "Policy":
        """
        Create a policy that expects a selected value to match an element from a list.

        Arguments
        ---------

        selector
            A jq-like selector.
        values
            The values to be checked.

        Example
        -------

        .. code-block:: py3

            from nuc.policy import Policy

            policy = Policy.any_of(".foo", [42, 1337])
            assert policy.matches({ "foo": 42 })
            assert policy.matches({ "foo": 1337 })
        """

        return Policy(OperatorPolicy(Selector.parse(selector), AnyOfOperator(values)))

    @staticmethod
    def and_(policies: List["Policy"]) -> "Policy":
        """
        Create a policy that expects all sub-policies to be valid.

        Arguments
        ---------

        policies
            The policies that must be valid.

        Example
        -------

        .. code-block:: py3

            from nuc.policy import Policy

            policy = Policy.and_([
                Policy.equals(".foo", 42),
                Policy.equals(".bar", 1337)
            ])
            assert policy.matches({ "foo": 42, "bar": 1337 })
        """

        return Policy(AndConnector(policies))

    @staticmethod
    def or_(policies: List["Policy"]) -> "Policy":
        """
        Create a policy that expects at least one sub-policy to be valid.

        Arguments
        ---------

        policies
            The policies to be checked.

        Example
        -------

        .. code-block:: py3

            from nuc.policy import Policy

            policy = Policy.or_([
                Policy.equals(".foo", 42),
                Policy.equals(".bar", 1337)
            ])
            assert policy.matches({ "foo": 42, "bar": 100 })
        """

        return Policy(OrConnector(policies))

    @staticmethod
    def not_(policy: "Policy") -> "Policy":
        """
        Create a policy that expects a policy to be invalid.

        Arguments
        ---------

        policy
            The policy to be checked.

        Example
        -------

        .. code-block:: py3

            from nuc.policy import Policy

            policy = Policy.not_(Policy.equals(".foo", 42))
            assert policy.matches({ "foo": 1337 })
        """

        return Policy(NotConnector(policy))


def _ensure_list(data: Any) -> List[Any]:
    if not isinstance(data, list):
        raise MalformedPolicyException("expected list")
    return data


def _pop_next(keys: Any, expected: str) -> Any:
    if not isinstance(keys, list):
        raise MalformedPolicyException("policy must be a list")
    if not keys:
        raise MalformedPolicyException(f"invalid policy: expected {expected}")
    return keys.pop(0)


def _parse_policies(keys: Any) -> List[Policy]:
    if not isinstance(keys, list):
        raise MalformedPolicyException("expected a list of policies")
    policies = []
    for element in keys:
        if not isinstance(element, list):
            raise MalformedPolicyException("expected a policy list")
        policies.append(Policy.parse(element))
    return policies


class MalformedPolicyException(Exception):
    """
    An exception that indicates a policy was malformed.
    """
