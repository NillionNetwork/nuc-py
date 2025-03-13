"""
NUC selectors.
"""

import re
from dataclasses import dataclass
from typing import Any, Dict, List

_SELECTOR_REGEX: re.Pattern = re.compile("[a-zA-Z0-9_-]+")


@dataclass
class Selector:
    """
    A selector that specifies a path within a JSON object to be matched.
    """

    path: List[str]

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

        if not selector.startswith("."):
            raise MalformedSelectorException("selectors must start with '.'")

        selector = selector[1:]
        if not selector:
            return Selector([])

        labels = []
        for label in selector.split("."):
            if not label:
                raise MalformedSelectorException("selector segment can't be empty")
            if not _SELECTOR_REGEX.match(label):
                raise MalformedSelectorException("invalid characters found in selector")
            labels.append(label)
        return Selector(labels)

    def apply(self, value: Dict[str, Any]) -> Any:
        """
        Apply a selector on a value and return the matched value, if any.

        Arguments
        ---------

        value
            The dict that this selector should be applied to.
        """

        output = value
        for label in self.path:
            output = output.get(label)
            if not output:
                return None
        return output

    def __str__(self) -> str:
        return "." + ".".join(self.path)


class MalformedSelectorException(Exception):
    """
    An exception that indicates a selector is malformed.
    """
