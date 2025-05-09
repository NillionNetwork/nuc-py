===
nuc
===

Data structures and functionalities for the Nillion Network user identity and authorization framework.

|pypi| |readthedocs| |actions| |coveralls|

.. |pypi| image:: https://badge.fury.io/py/nuc.svg#
   :target: https://badge.fury.io/py/nuc
   :alt: PyPI version and link.

.. |readthedocs| image:: https://readthedocs.org/projects/nuc/badge/?version=latest
   :target: https://nuc.readthedocs.io/en/latest/?badge=latest
   :alt: Read the Docs documentation status.

.. |actions| image:: https://github.com/nillionnetwork/nuc-py/workflows/lint-test-cover-docs/badge.svg#
   :target: https://github.com/nillionnetwork/nuc-py/actions/workflows/lint-test-cover-docs.yml
   :alt: GitHub Actions status.

.. |coveralls| image:: https://coveralls.io/repos/github/NillionNetwork/nuc-py/badge.svg?branch=main
   :target: https://coveralls.io/github/NillionNetwork/nuc-py?branch=main
   :alt: Coveralls test coverage summary.

Installation and Usage
----------------------
The library can be imported in the usual ways:

.. code-block:: python

    import nuc
    from nuc import *

Development
-----------

This project is managed via `uv <https://github.com/astral-sh/uv>`__. To install dependencies run:

.. code-block:: bash

   uv sync --dev

All installation and development dependencies are fully specified in ``pyproject.toml``. The ``project.optional-dependencies`` object is used to `specify optional requirements <https://peps.python.org/pep-0621>`__ for various development tasks. This makes it possible to specify additional options (such as ``docs``, ``lint``, and so on) when performing installation using `pip <https://pypi.org/project/pip>`__:

.. code-block:: bash

    uv sync --dev --extra docs --extra lint

Documentation
^^^^^^^^^^^^^
The documentation can be generated automatically from the source files using `Sphinx <https://www.sphinx-doc.org>`__:

.. code-block:: bash

    uv sync --extra docs
    cd docs
    uv run sphinx-apidoc -f -E --templatedir=_templates -o _source ../src && uv run make html

Testing and Conventions
^^^^^^^^^^^^^^^^^^^^^^^
All unit tests are executed and their coverage is measured when using `pytest <https://docs.pytest.org>`__ (see the ``pyproject.toml`` file for configuration details):

.. code-block:: bash

    uv sync --extra test
    uv run pytest

The subset of the unit tests included in the module itself and can be executed using `doctest <https://docs.python.org/3/library/doctest.html>`__:

.. code-block:: bash

    python src/nuc/nuc.py -v

Style conventions are enforced using `Pylint <https://pylint.readthedocs.io>`__:

.. code-block:: bash

    uv sync --extra lint
    uv run pylint src/nuc test/test_nuc.py

Type checking is enforced using `Pyright <https://github.com/microsoft/pyright>`__:

.. code-block:: bash

    uv sync --extra lint
    uv run pyright

Contributions
^^^^^^^^^^^^^
In order to contribute to the source code, open an issue or submit a pull request on the `GitHub page <https://github.com/nillionnetwork/nuc-py>`__ for this library.

Versioning
^^^^^^^^^^
The version number format for this library and the changes to the library associated with version number increments conform with `Semantic Versioning 2.0.0 <https://semver.org/#semantic-versioning-200>`__.

Publishing
^^^^^^^^^^
This library can be published as a `package on PyPI <https://pypi.org/project/nuc>`__ via the GitHub Actions workflow found in ``.github/workflows/build-publish-sign-release.yml`` that follows the `recommendations found in the Python Packaging User Guide <https://packaging.python.org/en/latest/guides/publishing-package-distribution-releases-using-github-actions-ci-cd-workflows/>`__.

Ensure that any links in this README document to the Read the Docs documentation of this package (or its dependencies) have appropriate version numbers. Also ensure that the Read the Docs project for this library has an `automation rule <https://docs.readthedocs.io/en/stable/automation-rules.html>`__ that activates and sets as the default all tagged versions.
