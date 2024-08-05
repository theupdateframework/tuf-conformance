import datetime
import os
from datetime import timezone
from tuf.api.metadata import Timestamp, Snapshot, Root, Targets, Metadata

from tuf_conformance.client_runner import ClientRunner
from tuf_conformance.simulator_server import SimulatorServer
from tuf_conformance import utils


def test_root_expired(client: ClientRunner, server: SimulatorServer) -> None:
    """Tests a case where root is expired. The spec (5.3.10)
    says that the root should update, so at the end, this
    test asserts that root updates but no other metadata does"""
    init_data, repo = server.new_test(client.test_name)

    assert client.init_client(init_data) == 0
    client.refresh(init_data)

    repo.bump_root_by_one()  # v2
    client.refresh(init_data)

    repo.md_root.signed.expires = utils.get_date_n_days_in_past(1)
    repo.bump_root_by_one()  # v3
    repo.targets.version += 1  # v2

    client.refresh(init_data)

    # Clients should check for a freeze attack after persisting (5.3.10),
    # so root should update, but no other MD should update
    assert client.version(Root.type) == 3
    assert client.version(Timestamp.type) == 1
    assert client.version(Snapshot.type) == 1


def test_snapshot_expired(client: ClientRunner, server: SimulatorServer) -> None:
    """Tests a case where the snapshot metadata is expired.
    Checks whether the clients updates the snapshot metadata
    if the repo has a newer version, but it is expired"""
    init_data, repo = server.new_test(client.test_name)

    assert client.init_client(init_data) == 0
    client.refresh(init_data)
    # Sanity check
    assert client._files_exist([Root.type, Timestamp.type, Snapshot.type, Targets.type])

    repo.md_snapshot.signed.expires = utils.get_date_n_days_in_past(5)
    repo.update_snapshot()

    client.refresh(init_data)

    # Check that the client still has the correct metadata files
    # i.e. that it has not updated to the expired metadata
    assert client._files_exist([Root.type, Timestamp.type])
    assert client.version(Snapshot.type) == 1


def test_targets_expired(client: ClientRunner, server: SimulatorServer) -> None:
    """Tests a case where the targets metadata is expired.
    Checks whether the clients updates the targets metadata
    if the repo has a newer version, but it is expired"""
    init_data, repo = server.new_test(client.test_name)

    assert client.init_client(init_data) == 0
    client.refresh(init_data)
    assert client._files_exist([Root.type, Timestamp.type, Snapshot.type, Targets.type])

    repo.md_targets.signed.expires = utils.get_date_n_days_in_past(5)
    repo.update_snapshot()

    assert client.init_client(init_data) == 0

    # Check that the client still has the correct metadata files
    assert client._files_exist([Root.type, Timestamp.type, Snapshot.type, Targets.type])

    # Client should not bump targets version, because it has expired
    assert client.version(Targets.type) == 1


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
    repo.md_timestamp.signed.expires = now + datetime.timedelta(days=7)

    # Refresh and perform sanity check
    client.refresh(init_data)
    for role in ["timestamp", "snapshot", "targets"]:
        md = Metadata.from_file(os.path.join(client.metadata_dir, f"{role}.json"))
        assert md.signed.version == 1

    repo.md_targets.signed.version += 1
    repo.update_snapshot()

    repo.md_timestamp.signed.expires = now + datetime.timedelta(days=21)
    repo.update_timestamp()

    # Mocking time so that local timestamp has expired
    # but the new timestamp has not
    client.refresh(init_data, days_in_future=18)

    # Assert that the final version of timestamp/snapshot is version 2
    # which means a successful refresh is performed
    # with expired local metadata.

    assert client.version(Targets.type) == 2
    assert client.version(Timestamp.type) == 3
    assert client.version(Snapshot.type) == 2


def test_timestamp_expired(client: ClientRunner, server: SimulatorServer) -> None:
    """Tests a case where the timestamp metadata is expired.
    Checks whether the clients updates the timestamp metadata
    if the repo has a newer version, but it is expired"""
    init_data, repo = server.new_test(client.test_name)

    assert client.init_client(init_data) == 0
    client.refresh(init_data)
    assert client.version(Timestamp.type) == 1

    repo.timestamp.expires = utils.get_date_n_days_in_past(5)
    repo.update_timestamp()  # v2

    client.refresh(init_data)

    # Check that client resisted rollback attack
    assert client._files_exist([Root.type])
    assert client.version(Timestamp.type) == 1
