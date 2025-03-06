"""
Test suite containing functional unit tests of exported functions.
"""
from unittest import TestCase
from importlib import import_module
import pytest

import nuc

class TestAPI(TestCase):
    """
    Test that the exported classes and functions match the expected API.
    """
    def test_exports(self):
        """
        Check that the module exports the expected classes and/or functions.
        """
        module = import_module('nuc.nuc')
        self.assertTrue({
            'example'
        }.issubset(module.__dict__.keys()))

class TestExample(TestCase):
    """
    Tests included as a template/example for developers.
    """
    def test_example(self):
        """
        Test example.
        """
        self.assertEqual(nuc.example(), True)
