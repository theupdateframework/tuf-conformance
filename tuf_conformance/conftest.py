import os
from collections.abc import Iterator

import pytest

from tuf_conformance.client_runner import ClientRunner
from tuf_conformance.simulator_server import SimulatorServer


def pytest_addoption(parser: pytest.Parser) -> None:
    """Add `--entrypoint` flag to CLI."""
    parser.addoption(
        "--entrypoint",
        action="store",
        help="the command to invoke the tuf client under test",
        required=True,
        type=str,
    )
    parser.addoption(
        "--expected-failures",
        action="store",
        help="Optional space delimited list of test names expected to fail",
        required=False,
        type=str,
    )
    parser.addoption(
        "--repository-dump-dir",
        action="store",
        help="Optional path to dump repository versions for each test for debugging",
        required=False,
        type=str,
    )


@pytest.fixture
def server(pytestconfig: pytest.Config) -> Iterator[SimulatorServer]:
    """
    Parametrize each test with the server under test.
    """
    dump_dir = pytestconfig.getoption("--repository-dump-dir")
    server = SimulatorServer(dump_dir)
    yield server
    server.server_close()


@pytest.fixture
def client(
    pytestconfig: pytest.Config, server: SimulatorServer, request: pytest.FixtureRequest
) -> ClientRunner:
    """
    Parametrize each test with the client under test.
    """
    entrypoint = pytestconfig.getoption("--entrypoint")
    if not os.path.isabs(entrypoint):
        entrypoint = os.path.join(pytestconfig.invocation_params.dir, entrypoint)

    return ClientRunner(entrypoint, server, request.node.name)


@pytest.fixture(autouse=True)
def conformance_xfail(
    pytestconfig: pytest.Config, request: pytest.FixtureRequest
) -> None:
    xfail_option = pytestconfig.getoption("--expected-failures")
    if xfail_option is None:
        return

    if request.node.originalname in xfail_option.split(" "):
        request.node.add_marker(pytest.mark.xfail(strict=True))
