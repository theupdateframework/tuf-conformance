import os

import pytest

from tuf_conformance.client_runner import ClientRunner
from tuf_conformance.simulator_server import StaticServer

static_repos = []
for static_dir in os.listdir(os.path.join("tuf_conformance", "static_data")):
    if os.path.isdir(os.path.join("tuf_conformance", "static_data", static_dir)):
        static_repos.append(static_dir)


@pytest.mark.parametrize("static_repo", static_repos)
def test_static_repo(
    static_client: ClientRunner, static_server: StaticServer, static_repo: str
) -> None:
    init_data, targetpath = static_server.new_test(static_repo)

    assert static_client.init_client(init_data) == 0
    assert static_client.refresh(init_data) == 0
    assert static_client.download_target(init_data, targetpath) == 0
