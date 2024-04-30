import os
import pytest

from tuf_conformance.client_runner import ClientRunner
from tuf_conformance.simulator_server import SimulatorServer

def pytest_addoption(parser) -> None:
    """Add `--entrypoint` flag to CLI."""
    parser.addoption(
        "--entrypoint",
        action="store",
        help="the command to invoke the tuf client under test",
        required=True,
        type=str,
    )

@pytest.fixture
def server():
    """
    Parametrize each test with the server under test.
    """
    server = SimulatorServer()
    yield server
    server.server_close()

@pytest.fixture
def client(pytestconfig, server):
    """
    Parametrize each test with the client under test.
    """
    entrypoint = pytestconfig.getoption("--entrypoint")
    if not os.path.isabs(entrypoint):
        entrypoint = os.path.join(pytestconfig.invocation_params.dir, entrypoint)

    return ClientRunner(entrypoint, server)

    