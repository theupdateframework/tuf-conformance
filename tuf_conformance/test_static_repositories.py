import os

import pytest

from tuf_conformance.client_runner import ClientRunner
from tuf_conformance.simulator_server import StaticServer

static_repos = []
for static_dir in os.listdir(os.path.join("tuf_conformance", "static_data")):
    if os.path.isdir(os.path.join("tuf_conformance", "static_data", static_dir)):
        static_repos.append(static_dir)


@pytest.mark.parametrize("static_repo", static_repos)
def test_static_repository(
    static_client: ClientRunner, static_server: StaticServer, static_repo: str
) -> None:
    """Test static repositories stored in tuf_conformance/static_data/

    This test is not a specification compliance test: It tests client compatibility
    with the repository format that a specific repository implementation produces.
    """
    init_data, targetpath = static_server.new_test(static_repo)

    assert static_client.init_client(init_data) == 0
    assert static_client.refresh(init_data) == 0
    assert static_client.download_target(init_data, targetpath) == 0
