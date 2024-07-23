import datetime
import os

from datetime import timezone
from tuf_conformance.client_runner import ClientRunner
from tuf_conformance.repository_simulator import RepositorySimulator
from tuf_conformance.simulator_server import SimulatorServer
from tuf_conformance import utils

from tuf.api.metadata import (
    Timestamp, Snapshot, Root, Targets, Metadata,
    DelegatedRole
)


def test_new_snapshot_expired(client: ClientRunner,
                              server: SimulatorServer) -> None:
    # Check for a freeze attack
    name = "test_new_snapshot_expired"

    # initialize a simulator with repository content we need
    repo = RepositorySimulator()
    server.repos[name] = repo
    init_data = server.get_client_init_data(name)
    assert client.init_client(init_data) == 0
    client.refresh(init_data)
    # Sanity check
    assert client._files_exist([Root.type,
                                       Timestamp.type,
                                       Snapshot.type,
                                       Targets.type])

    new_snapshot = repo.load_metadata(Snapshot.type)
    new_snapshot.signed.expires = utils.get_date_n_days_in_past(5)
    repo.save_metadata(Snapshot.type, new_snapshot)
    repo.update_snapshot()

    client.refresh(init_data)

    # Check that the client still has the correct metadata files
    # i.e. that it has not updated to the expired metadata
    assert client._files_exist([Root.type, Timestamp.type])
    assert client._version(Snapshot.type) == 1

def test_new_targets_expired(client: ClientRunner,
                             server: SimulatorServer) -> None:
    # Check against snapshot role's targets version
    name = "test_new_targets_expired"

    # initialize a simulator with repository content we need
    repo = RepositorySimulator()
    server.repos[name] = repo
    init_data = server.get_client_init_data(name)
    assert client.init_client(init_data) == 0
    client.refresh(init_data)
    assert client._files_exist([Root.type,
                                       Timestamp.type,
                                       Snapshot.type,
                                       Targets.type])

    repo.targets.expires = utils.get_date_n_days_in_past(5)
    repo.update_snapshot()

    assert client.init_client(init_data) == 0

    # Check that the client still has the correct metadata files
    assert client._files_exist([Root.type,
                                       Timestamp.type,
                                       Snapshot.type,
                                       Targets.type])

    # Client should not bump targets version, because it has expired
    assert client._version(Targets.type) == 1

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
    name = "test_expired_metadata"

    # initialize a simulator with repository content we need
    repo = RepositorySimulator()
    server.repos[name] = repo
    init_data = server.get_client_init_data(name)
    assert client.init_client(init_data) == 0

    now = datetime.datetime.now(timezone.utc)
    new_timestamp = repo.load_metadata(Timestamp.type)
    new_timestamp.signed.expires = now + datetime.timedelta(days=7)
    repo.save_metadata(Timestamp.type, new_timestamp)

    # Refresh and perform sanity check
    client.refresh(init_data)
    for role in ["timestamp", "snapshot", "targets"]:
        print("Current role: ", role)
        md = Metadata.from_file(
            os.path.join(client.metadata_dir, f"{role}.json")
        )
        assert md.signed.version == 1
    

    new_targets = repo.load_metadata(Targets.type)
    new_targets.signed.version += 1
    repo.save_metadata(Targets.type, new_targets)
    repo.update_snapshot()

    new_timestamp = repo.load_metadata(Timestamp.type)
    new_timestamp.signed.expires = now + datetime.timedelta(days=21)
    repo.save_metadata(Timestamp.type, new_timestamp)
    repo.update_timestamp()

    # Mocking time so that local timestamp has expired
    # but the new timestamp has not
    client.refresh(init_data, days_in_future="18")

    # Assert that the final version of timestamp/snapshot is version 2
    # which means a successful refresh is performed
    # with expired local metadata.
    for role in ["timestamp", "snapshot", "targets"]:
        print("Current role: ", role)
        md = Metadata.from_file(
            os.path.join(client.metadata_dir, f"{role}.json")
        )
        if role == "targets":
            assert md.signed.version == 2
        elif role == "snapshot":
            assert md.signed.version == 2
        else:
            assert md.signed.version == 3

def test_new_timestamp_expired(client: ClientRunner,
                               server: SimulatorServer) -> None:
    """This is an example of a test method:
    it should likely be a e.g. a unittest.TestCase"""

    name = "test_new_timestamp_expired"

    # initialize a simulator with repository content we need
    repo = RepositorySimulator()
    server.repos[name] = repo
    init_data = server.get_client_init_data(name)

    assert client.init_client(init_data) == 0
    repo.timestamp.expires = utils.get_date_n_days_in_past(5)
    repo.update_timestamp()

    client.refresh(init_data)

    # Check that client resisted rollback attack
    assert client._files_exist([Root.type])

def test_TestDelegatesRolesUpdateWithConsistentSnapshotDisabled(client: ClientRunner,
                                                                server: SimulatorServer) -> None:
    #https://github.com/theupdateframework/go-tuf/blob/f1d8916f08e4dd25f91e40139137edb8bf0498f3/metadata/updater/updater_consistent_snapshot_test.go#L97C6-L97C60
    name = "test_TestDelegatesRolesUpdateWithConsistentSnapshotDisabled"

    # initialize a simulator with repository content we need
    repo = RepositorySimulator()
    server.repos[name] = repo
    init_data = server.get_client_init_data(name)
    assert client.init_client(init_data) == 0
    client.refresh(init_data)
    # Sanity check
    assert client._files_exist([Root.type,
                                       Timestamp.type,
                                       Snapshot.type,
                                       Targets.type])

    repo.set_root_consistent_snapshot(False)
    repo.bump_root_by_one()

    # Add 3 delegates for new target
    # Target that expires 5 days in the future
    new_target = Targets(expires=datetime.datetime.now(timezone.utc)
                         .replace(microsecond=0)
                         + datetime.timedelta(days=5))

    delegated_role1 = DelegatedRole(name="role1",
                                    keyids=list(),
                                    threshold=1,
                                    terminating=False,
                                    paths=["*"])
    repo.add_delegation(Targets.type,
                        delegated_role1,
                        new_target)

    delegated_role2 = DelegatedRole(name="..",
                                    keyids=list(),
                                    threshold=1,
                                    terminating=False,
                                    paths=["*"])
    repo.add_delegation(Targets.type,
                        delegated_role2,
                        new_target)

    delegated_role3 = DelegatedRole(name=".",
                                    keyids=list(),
                                    threshold=1,
                                    terminating=False,
                                    paths=["*"])
    repo.add_delegation(Targets.type,
                        delegated_role3,
                        new_target)
    repo.update_snapshot()

    assert client.refresh(init_data) == 0

    # TODO: Implement this: https://github.com/theupdateframework/go-tuf/blob/f1d8916f08e4dd25f91e40139137edb8bf0498f3/metadata/updater/updater_consistent_snapshot_test.go#L146-L161
