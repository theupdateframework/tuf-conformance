import pytest

__version__ = "2.1.0"

# register pytest asserts before the imports happen in conftest.py
pytest.register_assert_rewrite("tuf_conformance.client_runner")
