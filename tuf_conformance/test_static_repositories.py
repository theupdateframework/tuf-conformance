import pytest

from tuf_conformance._internal.client_runner import ClientRunner
from tuf_conformance._internal.simulator_server import StaticServer


@pytest.mark.parametrize("static_repo", StaticServer.static_test_names())
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
