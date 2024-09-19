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

    repo.publish([Root.type])  # v2
    assert client.refresh(init_data) == 0

    repo.root.expires = utils.get_date_n_days_in_past(1)
    repo.publish([Root.type])  # v3
    repo.targets.version += 1  # v2

    assert client.refresh(init_data) == 1

    # Clients should check for a freeze attack after persisting (5.3.10),
    # so root should update, but no other MD should update
    assert client.version(Root.type) == 3
    assert client.version(Timestamp.type) == 1
    assert client.version(Snapshot.type) == 1


def test_timestamp_expired(client: ClientRunner, server: SimulatorServer) -> None:
    """Ensures that the client does not update the timestamp
    metadata when the repo has a newer version that is expired."""
    init_data, repo = server.new_test(client.test_name)

    assert client.init_client(init_data) == 0
    assert client.refresh(init_data) == 0

    repo.timestamp.expires = utils.get_date_n_days_in_past(5)
    repo.publish([Timestamp.type])  # v2

    # Check that client does not accept expired timestamp
    assert client.refresh(init_data) == 1
    assert client.trusted_roles() == [
        (Root.type, 1),
        (Snapshot.type, 1),
        (Targets.type, 1),
        (Timestamp.type, 1),
    ]


def test_snapshot_expired(client: ClientRunner, server: SimulatorServer) -> None:
    """Ensures that the client does not update the snapshot
    metadata when the repo has a newer version that is expired."""
    init_data, repo = server.new_test(client.test_name)

    assert client.init_client(init_data) == 0
    assert client.refresh(init_data) == 0

    repo.snapshot.expires = utils.get_date_n_days_in_past(5)
    repo.publish([Snapshot.type, Timestamp.type])

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
    repo.publish([Snapshot.type, Timestamp.type])

    assert client.refresh(init_data) == 0

    # Check that the client still has not accepted expired targets
    assert client.trusted_roles() == [
        (Root.type, 1),
        (Snapshot.type, 2),
        (Targets.type, 1),
        (Timestamp.type, 2),
    ]


def test_expired_local_root(client: ClientRunner, server: SimulatorServer) -> None:
    """Ensures that client can update to latest root when the local root is expired.

    The updates and verifications are performed with the following timing:
     - root v2 expiry set to day 7
     - First updater refresh performed on day 0

     - Repository bumps snapshot and targets to v2 on day 0
     - Timestamp v2 expiry set to day 21
     - Second updater refresh performed on day 18,
       it is successful and timestamp/snaphot final versions are v2"""
    init_data, repo = server.new_test(client.test_name)

    assert client.init_client(init_data) == 0

    # root v2 expires in 7 days
    now = datetime.datetime.now(timezone.utc)
    repo.root.expires = now + datetime.timedelta(days=7)
    repo.publish([Root.type])

    # Refresh
    assert client.refresh(init_data) == 0

    # root v3 expires in 21 days
    repo.root.expires = now + datetime.timedelta(days=21)
    repo.publish([Root.type])

    # Mocking time so that local root (v2) has expired but v3 from repo has not
    assert client.refresh(init_data, days_in_future=18) == 0
    assert client.version(Root.type) == 3


def test_expired_local_timestamp(client: ClientRunner, server: SimulatorServer) -> None:
    """Ensures that the client can update to the latest remote timestamp
    when the local timestamp has expired.

    The updates and verifications are performed with the following timing:
     - Timestamp v1 expiry set to day 7
     - First updater refresh performed on day 0
     - Repository bumps snapshot and targets to v2 on day 0
     - Timestamp v2 expiry set to day 21
     - Second updater refresh performed on day 18,
       it is successful and timestamp/snaphot final versions are v2"""
    init_data, repo = server.new_test(client.test_name)

    assert client.init_client(init_data) == 0

    # Repo timestamp v1 expires in 7 days
    now = datetime.datetime.now(timezone.utc)
    repo.timestamp.expires = now + datetime.timedelta(days=7)
    repo.publish([Timestamp.type])  # v2

    # Refresh
    assert client.refresh(init_data) == 0

    # Bump targets + snapshot version
    # Set next version of repo timestamp to expire in 21 days
    repo.timestamp.expires = now + datetime.timedelta(days=21)
    repo.publish([Targets.type, Snapshot.type, Timestamp.type])  # v2, v2, v3

    # Mocking time so that local timestamp has expired
    # but the new timestamp has not
    assert client.refresh(init_data, days_in_future=18) == 0

    # Assert final versions of timestamp/snapshot
    # which means a successful refresh is performed
    # with expired local metadata.
    assert client.trusted_roles() == [
        (Root.type, 1),
        (Snapshot.type, 2),
        (Targets.type, 2),
        (Timestamp.type, 3),
    ]
