"""
NUC selectors.
"""

from enum import Enum
import re
from dataclasses import dataclass
from typing import Any, Dict, List

_SELECTOR_REGEX: re.Pattern = re.compile("[a-zA-Z0-9_-]+")

type SelectorContext = Dict[str, Dict[str, Any]]
"""
The context for a selector: a key value pair where values are arbitrary dicts.
"""


class SelectorTarget(Enum):
    """
    The target for a selector.
    """

    TOKEN = 0
    """
    The target is the token itself.
    """

    CONTEXT = 1
    """
    The target is the provided context.
    """


@dataclass
class Selector:
    """
    A selector that specifies a path within a JSON object to be matched.
    """

    path: List[str]
    target: SelectorTarget

    @staticmethod
    def parse(selector: str) -> "Selector":
        """
        Parse a selector from a string.

        Arguments
        ---------

        selector
            The selector to be parsed.

        Example
        -------

        .. code-block:: py3

            from nuc.selector import Selector

            selector = Selector.parse(".foo.bar")
        """

        target = SelectorTarget.TOKEN
        if selector.startswith("$"):
            target = SelectorTarget.CONTEXT
            selector = selector[1:]

        if not selector.startswith("."):
            raise MalformedSelectorException("selectors must start with '.' or '$.'")

        selector = selector[1:]
        if not selector:
            match target:
                case SelectorTarget.TOKEN:
                    return Selector([], target)
                case SelectorTarget.CONTEXT:
                    raise MalformedSelectorException("context selector needs path")

        labels = []
        for label in selector.split("."):
            if not label:
                raise MalformedSelectorException("selector segment can't be empty")
            if not _SELECTOR_REGEX.match(label):
                raise MalformedSelectorException("invalid characters found in selector")
            labels.append(label)
        return Selector(labels, target)

    def apply(self, value: Dict[str, Any], context: SelectorContext) -> Any:
        """
        Apply a selector on a value and return the matched value, if any.

        Arguments
        ---------

        value
            The dict that this selector should be applied to.
        """
        match self.target:
            case SelectorTarget.TOKEN:
                return self._apply_on_value(self.path, value)
            case SelectorTarget.CONTEXT:
                if not self.path:
                    return None
                first = self.path[0]
                context_value = context.get(first)
                if not context_value:
                    return None
                return self._apply_on_value(self.path[1:], context_value)

    @staticmethod
    def _apply_on_value(path: List[str], value: Dict[str, Any]) -> Any:
        output = value
        for label in path:
            output = output.get(label)
            if not output:
                return None
        return output

    def __str__(self) -> str:
        match self.target:
            case SelectorTarget.TOKEN:
                prefix = ""
            case SelectorTarget.CONTEXT:
                prefix = "$"
        return f"{prefix}.{'.'.join(self.path)}"


class MalformedSelectorException(Exception):
    """
    An exception that indicates a selector is malformed.
    """
