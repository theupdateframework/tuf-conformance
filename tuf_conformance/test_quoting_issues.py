from urllib import parse

import pytest
from tuf.api.metadata import DelegatedRole, Targets

from tuf_conformance.client_runner import ClientRunner
from tuf_conformance.simulator_server import SimulatorServer

unusual_role_names = [
    "?",
    "#",
    "/delegatedrole",
    "../delegatedrole",
]


@pytest.mark.parametrize("role", unusual_role_names)
def test_unusual_role_name(
    client: ClientRunner, server: SimulatorServer, role: str
) -> None:
    """Test various unusual rolenames

    Role names are used in http requests and potentially file names:
    verify that both uses seem safe.
    """
    init_data, repo = server.new_test(client.test_name)

    # Add a delegation
    delegated_role = DelegatedRole(role, [], 1, False, ["*"])
    delegated_targets = Targets(1, None, repo.safe_expiry, {}, None)
    repo.add_delegation(Targets.type, delegated_role, delegated_targets)

    # Add signer, add the key to roles delegation
    repo.add_key(role, Targets.type)

    repo.targets.version += 1
    repo.update_snapshot()

    client.init_client(init_data)
    assert client.download_target(init_data, "nonexistent target") == 1

    # Make sure the correctly quoted request was made
    assert (parse.quote(role, ""), 1) in repo.metadata_statistics
    # count trusted roles (don't check name since we do not know how client encodes it)
    assert len(client.trusted_roles()) == 5
