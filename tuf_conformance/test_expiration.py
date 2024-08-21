import datetime
from datetime import timezone

from tuf.api.metadata import Root, Snapshot, Targets, Timestamp

from tuf_conformance import utils
from tuf_conformance.client_runner import ClientRunner
from tuf_conformance.simulator_server import SimulatorServer


def test_root_expired(client: ClientRunner, server: SimulatorServer) -> None:
    """Tests a case where root is expired. The spec (5.3.10)
    says that the root should update, so at the end, this
    test asserts that root updates but no other metadata does"""
    init_data, repo = server.new_test(client.test_name)

    assert client.init_client(init_data) == 0
    assert client.refresh(init_data) == 0

    repo.bump_root_by_one()  # v2
    assert client.refresh(init_data) == 0

    repo.root.expires = utils.get_date_n_days_in_past(1)
    repo.bump_root_by_one()  # v3
    repo.targets.version += 1  # v2

    assert client.refresh(init_data) == 1

    # Clients should check for a freeze attack after persisting (5.3.10),
    # so root should update, but no other MD should update
    assert client.version(Root.type) == 3
    assert client.version(Timestamp.type) == 1
    assert client.version(Snapshot.type) == 1


def test_snapshot_expired(client: ClientRunner, server: SimulatorServer) -> None:
    """Tests a case where the snapshot metadata is expired.

    Assert that client does not accept snapshot metadata that is a newer version but is
    expired
    """
    init_data, repo = server.new_test(client.test_name)

    assert client.init_client(init_data) == 0
    assert client.refresh(init_data) == 0

    repo.snapshot.expires = utils.get_date_n_days_in_past(5)
    repo.update_snapshot()

    assert client.refresh(init_data) == 1

    # Check that the client has not accepted expired snapshot
    assert client.trusted_roles() == [
        (Root.type, 1),
        (Snapshot.type, 1),
        (Targets.type, 1),
        (Timestamp.type, 2),
    ]


def test_targets_expired(client: ClientRunner, server: SimulatorServer) -> None:
    """Ensures that the client does not update the targets
    metadata when the repo has a newer version that is expired."""
    init_data, repo = server.new_test(client.test_name)

    assert client.init_client(init_data) == 0
    assert client.refresh(init_data) == 0

    repo.targets.expires = utils.get_date_n_days_in_past(5)
    repo.update_snapshot()

    assert client.refresh(init_data) == 0

    # Check that the client still has not accepted expired targets
    assert client.trusted_roles() == [
        (Root.type, 1),
        (Snapshot.type, 2),
        (Targets.type, 1),
        (Timestamp.type, 2),
    ]


def test_expired_metadata(client: ClientRunner, server: SimulatorServer) -> None:
    """Verifies that expired local timestamp/snapshot can be used for
    updating from remote.

    The updates and verifications are performed with the following timing:
     - Timestamp v1 expiry set to day 7
     - First updater refresh performed on day 0
     - Repository bumps snapshot and targets to v2 on day 0
     - Timestamp v2 expiry set to day 21
     - Second updater refresh performed on day 18,
       it is successful and timestamp/snaphot final versions are v2"""
    init_data, repo = server.new_test(client.test_name)

    assert client.init_client(init_data) == 0

    now = datetime.datetime.now(timezone.utc)
    repo.timestamp.expires = now + datetime.timedelta(days=7)

    # Refresh
    assert client.refresh(init_data) == 0

    repo.targets.version += 1
    repo.timestamp.expires = now + datetime.timedelta(days=21)
    repo.update_snapshot()

    # Mocking time so that local timestamp has expired
    # but the new timestamp has not
    assert client.refresh(init_data, days_in_future=18) == 0

    # Assert that the final version of timestamp/snapshot is version 2
    # which means a successful refresh is performed
    # with expired local metadata.
    assert client.trusted_roles() == [
        (Root.type, 1),
        (Snapshot.type, 2),
        (Targets.type, 2),
        (Timestamp.type, 2),
    ]


def test_timestamp_expired(client: ClientRunner, server: SimulatorServer) -> None:
    """Tests a case where the timestamp metadata is expired.
    Checks whether the clients updates the timestamp metadata
    if the repo has a newer version, but it is expired"""
    init_data, repo = server.new_test(client.test_name)

    assert client.init_client(init_data) == 0
    assert client.refresh(init_data) == 0

    repo.timestamp.expires = utils.get_date_n_days_in_past(5)
    repo.update_timestamp()  # v2

    # Check that client does not accept expired timestamp
    assert client.refresh(init_data) == 1
    assert client.trusted_roles() == [
        (Root.type, 1),
        (Snapshot.type, 1),
        (Targets.type, 1),
        (Timestamp.type, 1),
    ]
