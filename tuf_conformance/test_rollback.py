from tuf_conformance.client_runner import ClientRunner
from tuf_conformance.repository_simulator import RepositorySimulator
from tuf_conformance.simulator_server import SimulatorServer

from tuf.api.metadata import (
    Timestamp, Snapshot, Root, Targets
)

def test_new_snapshot_version_rollback(client: ClientRunner,
                                       server: SimulatorServer) -> None:
    """This is an example of a test method:
    it should likely be a e.g. a unittest.TestCase"""

    name = "test_new_snapshot_version_rollback"

    # initialize a simulator with repository content we need
    repo = RepositorySimulator()
    server.repos[name] = repo
    init_data = server.get_client_init_data(name)

    assert client.init_client(init_data) == 0

    # Repository performs legitimate update to snapshot
    repo.update_snapshot()
    assert client.refresh(init_data) == 0

    # Sanity check that client saw the snapshot update:
    assert client._version_equals(Snapshot.type, 2)

    # Repository attempts rollback attack:
    repo.downgrade_snapshot()
    assert repo._version_equals(Snapshot.type, 1)
    client.refresh(init_data)

    # Check that client resisted rollback attack
    assert client._version_equals(Snapshot.type, 2)

def test_new_timestamp_version_rollback(client: ClientRunner,
                                        server: SimulatorServer) -> None:
    """This is an example of a test method:
    it should likely be a e.g. a unittest.TestCase"""

    name = "test_new_timestamp_version_rollback"

    # initialize a simulator with repository content we need
    repo = RepositorySimulator()
    server.repos[name] = repo
    init_data = server.get_client_init_data(name)
    assert client.init_client(init_data) == 0

    # Repository performs legitimate update to snapshot
    repo.update_timestamp()
    assert repo._version_equals(Timestamp.type, 2)
    assert client.refresh(init_data) == 0

    # Sanity check that client saw the snapshot update:
    assert client._version_equals(Timestamp.type, 2)

    # Repository attempts rollback attack:
    repo.downgrade_timestamp()

    # Sanitty check that the repository is attempting a
    # rollback attack
    assert repo._version_equals(Timestamp.type, 1)

    client.refresh(init_data)

    # Check that client resisted rollback attack
    assert client._version_equals(Timestamp.type, 2)

def test_new_timestamp_snapshot_rollback(client: ClientRunner, 
                                         server: SimulatorServer) -> None:
    """This is an example of a test method:
    it should likely be a e.g. a unittest.TestCase"""

    name = "test_new_timestamp_snapshot_rollback"

    # initialize a simulator with repository content we need
    repo = RepositorySimulator()
    server.repos[name] = repo
    init_data = server.get_client_init_data(name)

    assert client.init_client(init_data) == 0

    # Start snapshot version at 2
    #repo.snapshot.version = 2
    new_snapshot = repo.load_metadata(Snapshot.type)
    new_snapshot.signed.version = 2
    repo.save_metadata(Snapshot.type, new_snapshot)

    # Repository performs legitimate update to snapshot
    repo.update_timestamp()
    # Sanity check
    assert repo._version_equals(Timestamp.type, 2)
    assert client.refresh(init_data) == 0

    # Repo attempts rollback attack
    new_timestamp = repo.load_metadata(Timestamp.type)
    new_timestamp.signed.snapshot_meta.version = 1
    new_timestamp.signed.version += 1
    repo.save_metadata(Timestamp.type, new_timestamp)
    # Sanity check
    assert repo._version_equals(Timestamp.type, 3)
    assert client._version_equals(Timestamp.type, 2)

    client.refresh(init_data)

    # Check that client resisted rollback attack
    assert client._version_equals(Timestamp.type, 2)

def test_new_targets_fast_forward_recovery(client: ClientRunner,
                                           server: SimulatorServer) -> None:
    """Test targets fast-forward recovery using key rotation.

    The targets recovery is made by issuing new Snapshot keys, by following
    steps:
        - Remove the snapshot key
        - Create and add a new key for snapshot
        - Bump and publish root
        - Rollback the target version
    """

    name = "test_new_targets_fast_forward_recovery"

    # initialize a simulator with repository content we need
    repo = RepositorySimulator()
    server.repos[name] = repo
    init_data = server.get_client_init_data(name)
    assert client.init_client(init_data) == 0

    new_targets = repo.load_metadata(Targets.type)
    new_targets.signed.version = 99999
    repo.save_metadata(Targets.type, new_targets)
    repo.update_snapshot()

    client.refresh(init_data)
    assert client._version_equals(Targets.type, 99999)

    repo.rotate_keys(Snapshot.type)
    repo.bump_root_by_one()
    new_targets = repo.load_metadata(Targets.type)
    new_targets.signed.version = 1
    repo.save_metadata(Targets.type, new_targets)
    repo.update_snapshot()

    client.refresh(init_data)
    # TODO: Is it really true that the targets version is 1?
    assert client._version_equals(Targets.type, 99999)

def test_new_snapshot_fast_forward_recovery(client: ClientRunner,
                                            server: SimulatorServer) -> None:
    """Test snapshot fast-forward recovery using key rotation.

    The snapshot recovery requires the snapshot and timestamp key rotation.
    It is made by the following steps:
    - Remove the snapshot and timestamp keys
    - Create and add a new key for snapshot and timestamp
    - Rollback snapshot version
    - Bump and publish root
    - Bump the timestamp
    """
    name = "test_new_snapshot_fast_forward_recovery"

    # initialize a simulator with repository content we need
    repo = RepositorySimulator()
    server.repos[name] = repo
    init_data = server.get_client_init_data(name)

    assert client.init_client(init_data) == 0
    new_snapshot = repo.load_metadata(Snapshot.type)
    new_snapshot.signed.version = 99999
    repo.save_metadata(Snapshot.type, new_snapshot)

    repo.update_timestamp()
    client.refresh(init_data)
    assert client._version_equals(Snapshot.type, 99999)

    repo.rotate_keys(Snapshot.type)
    repo.rotate_keys(Timestamp.type)
    repo.bump_root_by_one()

    #repo.snapshot.version = 1
    new_snapshot = repo.load_metadata(Snapshot.type)
    new_snapshot.signed.version = 1
    repo.save_metadata(Snapshot.type, new_snapshot)
    repo.update_timestamp()

    client.refresh(init_data)
    # TODO: Can this really be true?
    assert client._version_equals(Snapshot.type, 99999)

def test_new_snapshot_version_mismatch(client: ClientRunner,
                                       server: SimulatorServer) -> None:
    # Check against timestamp role's snapshot version

    name = "test_new_snapshot_version_mismatch"

    # initialize a simulator with repository content we need
    repo = RepositorySimulator()
    server.repos[name] = repo
    init_data = server.get_client_init_data(name)

    assert client.init_client(init_data) == 0

    # Increase snapshot version without updating timestamp
    repo.snapshot.version += 1
    repo.update_snapshot()

    client.refresh(init_data)
    assert client._files_exist([Root.type, Timestamp.type])

def test_new_timestamp_fast_forward_recovery(client: ClientRunner,
                                             server: SimulatorServer) -> None:
    """The timestamp recovery is made by the following steps
     - Remove the timestamp key
     - Create and add a new key for timestamp
     - Bump and publish root
     - Rollback the timestamp version
    """

    name = "test_new_timestamp_fast_forward_recovery"

    # initialize a simulator with repository content we need
    repo = RepositorySimulator()
    server.repos[name] = repo
    init_data = server.get_client_init_data(name)

    assert client.init_client(init_data) == 0

    # attacker updates to a higher version
    new_timestamp = repo.load_metadata(Timestamp.type)
    new_timestamp.signed.version = 99998
    repo.save_metadata(Timestamp.type, new_timestamp)
    repo.update_timestamp()

    # Sanity check
    assert repo._version_equals(Timestamp.type, 99999)

    # client refreshes the metadata and see the new timestamp version
    client.refresh(init_data)
    assert client._version_equals(Timestamp.type, 99999)

    # repository rotates timestamp keys, rolls back timestamp version
    repo.rotate_keys(Timestamp.type)
    repo.bump_root_by_one()
    #repo.timestamp.version = 1

    new_timestamp = repo.load_metadata(Timestamp.type)
    new_timestamp.signed.version = 1
    repo.save_metadata(Timestamp.type, new_timestamp)

    # client refresh the metadata and see the initial timestamp version
    client.refresh(init_data)
    assert client._version_equals(Timestamp.type, 99999)

def test_snapshot_rollback_with_local_snapshot_hash_mismatch(client: ClientRunner,
                                                             server: SimulatorServer) -> None:
    # Test triggering snapshot rollback check on a newly downloaded snapshot
    # when the local snapshot is loaded even when there is a hash mismatch
    # with timestamp.snapshot_meta.
    name = "test_snapshot_rollback_with_local_snapshot_hash_mismatch"

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

    # Initialize all metadata and assign targets version higher than 1.
    new_targets = repo.load_metadata(Targets.type)
    new_targets.signed.version = 2
    repo.save_metadata(Targets.type, new_targets)
    repo.update_snapshot()
    client.refresh(init_data)
    assert client._version_equals(Targets.type, 2)

    # By raising this flag on timestamp update the simulator would:
    # 1) compute the hash of the new modified version of snapshot
    # 2) assign the hash to timestamp.snapshot_meta
    # The purpose is to create a hash mismatch between timestamp.meta and
    # the local snapshot, but to have hash match between timestamp.meta and
    # the next snapshot version.
    repo.compute_metafile_hashes_length = True

    # The new targets must have a lower version than the local trusted one.
    repo.targets.version = 3
    repo.update_snapshot()

    # Client refresh should fail because there is a hash mismatch.
    assert client.refresh(init_data) == 1
    
