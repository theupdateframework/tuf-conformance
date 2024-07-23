# Test runner
import os

from tuf_conformance.repository_simulator import RepositorySimulator
from tuf_conformance.simulator_server import SimulatorServer
from tuf_conformance.client_runner import ClientRunner

from tuf.api.metadata import (
    Timestamp, Snapshot, Root, Targets, Metadata
)


def test_TestTimestampEqVersionsCheck(client: ClientRunner,
                                      server: SimulatorServer) -> None:
    # https://github.com/theupdateframework/go-tuf/blob/f1d8916f08e4dd25f91e40139137edb8bf0498f3/metadata/updater/updater_top_level_update_test.go#L1058
    name = "test_TestTimestampEqVersionsCheck"

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

    initial_timestamp_meta_ver = repo.timestamp.snapshot_meta.version
    # Change timestamp without bumping its version in order to test if a new
    # timestamp with the same version will be persisted.
    new_timestamp = repo.load_metadata(Timestamp.type)
    new_timestamp.signed.snapshot_meta.version = 100
    repo.save_metadata(Timestamp.type, new_timestamp)

    client.refresh(init_data)

    assert client._version(Timestamp.type) == initial_timestamp_meta_ver


def test_max_root_rotations(client: ClientRunner,
                            server: SimulatorServer) -> None:
    # Root must stop looking for new versions after Y number of
    # intermediate files were downloaded.

    name = "test_max_root_rotations"

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

    updater_max_root_rotations = 3
    client.max_root_rotations = updater_max_root_rotations

    # repo bumps the Root version by more than the client allows
    maxIterations = 20
    for i in range(20):
        if i > maxIterations:
            # Sanity check. This should not happen but
            # it prevents a potential infinite loop
            assert False
        root = repo.load_metadata(Root.type)
        if root.signed.version >= updater_max_root_rotations+10:
            break
        repo.bump_root_by_one()

    # The repositorys root version is now 13.
    assert repo._version_equals(Root.type, 13)

    # Check that the client does not upgrade by more than its max
    md_root = Metadata.from_file(
        os.path.join(client.metadata_dir, "root.json")
    )
    initial_root_version = md_root.signed.version
    client.refresh(init_data)

    # Assert that root version was increased with no more
    # than 'max_root_rotations'
    assert client._version(Root.type) == initial_root_version+3

<<<<<<< HEAD

=======
>>>>>>> 69e805f (change _version_equals to _version)

def test_new_targets_hash_mismatch(client: ClientRunner,
                                   server: SimulatorServer) -> None:
    # Check against snapshot role's targets hashes
    name = "test_new_targets_hash_mismatch"

    # initialize a simulator with repository content we need
    repo = RepositorySimulator()
    server.repos[name] = repo
    init_data = server.get_client_init_data(name)
    assert client.init_client(init_data) == 0
    client.refresh(init_data)
    # Sanity check
    assert client._files_exist([Root.type,
                                Timestamp.type,
                                Snapshot.type])

    repo.compute_metafile_hashes_length = True
    repo.update_snapshot()

    client.refresh(init_data)

    # Modify targets contents without updating
    # snapshot's targets hashes
    repo.bump_version_by_one(Targets.type)
    targets_version = repo.load_metadata(Targets.type).signed.version
    snapshot = Metadata.from_bytes(repo.md_snapshot_json)
    snapshot.signed.meta["targets.json"].version = targets_version
    snapshot.signed.version += 1
    repo.md_snapshot_json = snapshot.to_bytes()
    repo.update_timestamp()

    client.refresh(init_data)
    assert client._version(Snapshot.type) ==  1
    assert client._version(Targets.type) == 1
<<<<<<< HEAD

=======
>>>>>>> 69e805f (change _version_equals to _version)

def test_new_targets_version_mismatch(client: ClientRunner,
                                      server: SimulatorServer) -> None:
    # Check against snapshot role's targets version
    name = "test_new_targets_version_mismatch"

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

    repo.bump_version_by_one(Targets.type)
    client.refresh(init_data)
    # Check that the client still has the correct metadata files
    assert client._files_exist([Root.type,
                                Timestamp.type,
                                Snapshot.type,
                                Targets.type])


def test_basic_init_and_refresh(client: ClientRunner,
                                server: SimulatorServer) -> None:
    """This is an example of a test method:
    it should likely be a e.g. a unittest.TestCase"""

    name = "test_init"

    # initialize a simulator with repository content we need
    repo = RepositorySimulator()
    server.repos[name] = repo
    init_data = server.get_client_init_data(name)

    # Run the test: step 1:  initialize client
    # TODO verify success?
    assert client.init_client(init_data) == 0

    # TODO verify that results are correct, see e.g.
    # * repo.metadata_statistics: no requests expected
    # * client metadat cache should contain root v1

    # Run the test: step 1: Refresh
    assert client.refresh(init_data) == 0

    # Verify that expected requests were made
    assert repo.metadata_statistics == [('root', 1),
                                        ('root', 2),
                                        ('timestamp', None),
                                        ('snapshot', 1),
                                        ('targets', 1)]
    # TODO verify that local metadata cache has the files we expect


def test_timestamp_eq_versions_check(client: ClientRunner,
                                     server: SimulatorServer) -> None:
    # Test that a modified timestamp with different content, but the same
    # version doesn't replace the valid locally stored one.
    name = "test_timestamp_eq_versions_check"

    # initialize a simulator with repository content we need
    repo = RepositorySimulator()
    server.repos[name] = repo
    init_data = server.get_client_init_data(name)
    assert client.init_client(init_data) == 0

    # Make a successful update of valid metadata which stores it in cache
    client.refresh(init_data)
    initial_timestamp_meta_ver = repo.timestamp.snapshot_meta.version

    # Change timestamp without bumping its version in order to test if a new
    # timestamp with the same version will be persisted.
    repo.timestamp.snapshot_meta.version = 100
    client.refresh(init_data)

    # If the local timestamp md file has the same snapshot_meta.version as
    # the initial one, then the new modified timestamp has not been stored.
    timestamp_path = os.path.join(client.metadata_dir, "timestamp.json")
    timestamp: Metadata[Timestamp] = Metadata.from_file(timestamp_path)
    assert initial_timestamp_meta_ver == timestamp.signed.snapshot_meta.version
