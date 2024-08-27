import os
from functools import cache

import pytest

from tuf_conformance.client_runner import ClientRunner
from tuf_conformance.simulator_server import SimulatorServer, StaticServer


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
        "--repository-dump-dir",
        action="store",
        help="Optional path to dump repository versions for each test for debugging",
        required=False,
        type=str,
    )


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    _simulator_server("").server_close()
    _static_server().server_close()


@cache
def _simulator_server(dump_dir: str) -> SimulatorServer:
    return SimulatorServer(dump_dir)


@cache
def _static_server() -> StaticServer:
    return StaticServer()


@pytest.fixture
def server(pytestconfig: pytest.Config) -> SimulatorServer:
    """HTTP Server for all simulated repositories"""
    dump_dir = pytestconfig.getoption("--repository-dump-dir")
    return _simulator_server(dump_dir)


@pytest.fixture
def static_server(pytestconfig: pytest.Config) -> StaticServer:
    """HTTP Server for all static repositories"""
    return _static_server()


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


@pytest.fixture
def static_client(
    pytestconfig: pytest.Config,
    static_server: StaticServer,
    request: pytest.FixtureRequest,
) -> ClientRunner:
    """
    Client for running static repository tests.
    """
    entrypoint = pytestconfig.getoption("--entrypoint")
    if not os.path.isabs(entrypoint):
        entrypoint = os.path.join(pytestconfig.invocation_params.dir, entrypoint)

    return ClientRunner(entrypoint, static_server, request.node.name)


@cache
def read_xfails(pytestconfig: pytest.Config) -> list[str]:
    # Find expected failures from .xfails file
    xfail_file = f"{pytestconfig.getoption('--entrypoint')}.xfails"
    if not os.path.isabs(xfail_file):
        xfail_file = os.path.join(pytestconfig.invocation_params.dir, xfail_file)

    try:
        with open(xfail_file) as f:
            return f.read().splitlines()
    except FileNotFoundError:
        return []


@pytest.fixture(autouse=True)
def conformance_xfail(
    pytestconfig: pytest.Config, request: pytest.FixtureRequest
) -> None:
    xfails = read_xfails(pytestconfig)

    if request.node.originalname in xfails or request.node.name in xfails:
        request.node.add_marker(pytest.mark.xfail(strict=True))
