# Test runner

import datetime
import json
import os
import tempfile

from datetime import timezone
from tuf_conformance.repository_simulator import RepositorySimulator
from tuf_conformance.simulator_server import SimulatorServer
from tuf_conformance.client_runner import ClientRunner
from tuf_conformance import utils
from tuf.api.serialization import DeserializationError

from tuf.api.exceptions import (
    BadVersionNumberError
)

from tuf.api.metadata import (
    Timestamp, Snapshot, Root, Targets, Metadata,
    DelegatedRole
)

from tuf.ngclient import RequestsFetcher

class TestTarget:
    path: str
    content: bytes
    encoded_path: str

def test_invalid_date_format(client: ClientRunner,
                        server: SimulatorServer) -> None:
    # Tests the client rejects metadata with wrong date format

    name = "test_invalid_date_format"

    # initialize a simulator with repository content we need
    repo = RepositorySimulator()
    #repo.compute_metafile_hashes_length = False
    server.repos[name] = repo
    init_data = server.get_client_init_data(name)
    assert client.init_client(init_data) == 0
    client.refresh(init_data)
    # Sanity checks
    assert client._files_exist([Root.type,
                                       Timestamp.type,
                                       Snapshot.type,
                                       Targets.type])
    assert client._version_equals(Snapshot.type, 1)
    five_days_in_future = utils.get_date_n_days_in_future(5)
    date_str = five_days_in_future.strftime("%Y-%m-%dT%H:%M:%SZ")

    new_snapshot = repo.load_metadata(Snapshot.type)
    new_snapshot.signed.expires = five_days_in_future
    repo.save_metadata(Snapshot.type, new_snapshot)
    repo.update_snapshot()
    assert client.refresh(init_data) == 0
    assert client._version_equals(Snapshot.type, 2)
    assert client._version_equals(Timestamp.type, 2)

    # Set a valid expiration
    repo.set_any_expiration_date(date_str)
    repo.update_any_snapshot()
    assert client.refresh(init_data) == 0
    assert client._version_equals(Snapshot.type, 3)
    assert client._version_equals(Timestamp.type, 3)

    # Set another valid expiration
    # mostly a sanity check
    date_str = five_days_in_future.strftime("%Y-%m-%dT%H:%M:%SZ")
    repo.set_any_expiration_date(date_str)
    repo.update_any_snapshot()
    assert client.refresh(init_data) == 0
    assert client._version_equals(Snapshot.type, 4)
    assert client._version_equals(Timestamp.type, 4)

    # Set an invalid expiration
    date_str = five_days_in_future.strftime("%m-%d-%YT%H:%M:%SZ")
    repo.set_any_expiration_date(date_str)
    repo.update_any_snapshot()
    # Client refresh should fail
    assert client.refresh(init_data) == 1
    assert client._version_equals(Snapshot.type, 4)
    # Timestamp gets updated because the Snapshot is invalid.
    # snapshot is updated after timestamp
    assert client._version_equals(Timestamp.type, 5)

    # Set a valid expiration
    date_str = five_days_in_future.strftime("%Y-%m-%dT%H:%M:%SZ")
    repo.set_any_expiration_date(date_str)
    repo.update_any_snapshot()
    assert client.refresh(init_data) == 0
    assert client._version_equals(Snapshot.type, 6)
    assert client._version_equals(Timestamp.type, 6)

    # Set an invalid expiration - seconds are missing
    date_str = five_days_in_future.strftime("%Y-%m-%dT%H:%MZ")
    repo.set_any_expiration_date(date_str)
    repo.update_any_snapshot()
    # Client refresh should fail
    assert client.refresh(init_data) == 1
    assert client._version_equals(Snapshot.type, 6)
    assert client._version_equals(Timestamp.type, 7)

    # Set an invalid expiration - minutes and seconds are missing
    date_str = five_days_in_future.strftime("%Y-%m-%dT%HZ")
    repo.set_any_expiration_date(date_str)
    repo.update_any_snapshot()
    # Client refresh should fail
    assert client.refresh(init_data) == 1
    assert client._version_equals(Snapshot.type, 6)
    assert client._version_equals(Timestamp.type, 8)

    # Set a valid expiration
    date_str = five_days_in_future.strftime("%Y-%m-%dT%H:%M:%SZ")
    repo.set_any_expiration_date(date_str)
    repo.update_any_snapshot()
    assert client.refresh(init_data) == 0
    assert client._version_equals(Snapshot.type, 9)
    assert client._version_equals(Timestamp.type, 9)

def test_simple_signing(client: ClientRunner,
                        server: SimulatorServer) -> None:
    # Tests that add_key_to_role works as intended

    name = "test_simple_signing"

    # initialize a simulator with repository content we need
    repo = RepositorySimulator()
    server.repos[name] = repo
    init_data = server.get_client_init_data(name)
    assert client.init_client(init_data) == 0
    client.refresh(init_data)
    # Sanity checks
    assert client._files_exist([Root.type,
                                       Timestamp.type,
                                       Snapshot.type,
                                       Targets.type])
    assert client._version_equals(Snapshot.type, 1)

    # Add signature to Snapshot
    repo.add_key_to_role(Snapshot.type)
    repo.add_key_to_role(Snapshot.type)
    repo.add_key_to_role(Snapshot.type)

    # Sanity-check. TODO: Make unit test outside
    # of conformance test for this
    repo_root = repo.load_metadata(Root.type)
    assert repo._version_equals(Root.type, 1)

    repo.bump_root_by_one()

    # Sanity-check. TODO: Make unit test outside
    # of conformance test for this
    repo_root = repo.load_metadata(Root.type)
    assert repo._version_equals(Root.type, 2)
    assert len(repo_root.signed.roles["snapshot"].keyids) == 4

    repo.update_timestamp()
    repo.update_snapshot()

    assert client.refresh(init_data) == 0

    # There should be 4 snapshot signatures in the clients metadata
    md_obj = Metadata.from_file(
        os.path.join(client.metadata_dir, "root.json")).signed
    md_obj2 = Metadata.from_file(
        os.path.join(client.metadata_dir, "snapshot.json"))
    assert len(md_obj.roles[Snapshot.type].keyids) == 4
    assert len(md_obj2.signatures) == 4

    # Add another signature
    repo.add_key_to_role(Snapshot.type)
    repo.bump_root_by_one()

    # Sanity check
    repo_root = repo.load_metadata(Root.type)
    assert len(repo_root.signed.roles["snapshot"].keyids) == 5

    repo.update_timestamp()
    repo.update_snapshot()

    assert client.refresh(init_data) == 0

    # There should be 5 snapshot signatures in the clients metadata
    md_obj = Metadata.from_file(
        os.path.join(client.metadata_dir, "root.json")).signed
    md_obj2 = Metadata.from_file(
        os.path.join(client.metadata_dir, "snapshot.json"))
    assert len(md_obj.roles[Snapshot.type].keyids) == 5
    assert len(md_obj2.signatures) == 5

    # Test 1:
    # Set higher threshold than we have keys. Should fail
    new_root = repo.load_metadata(Root.type)
    new_root.signed.roles[Snapshot.type].threshold = 10
    repo.save_metadata(Root.type, new_root)
    initial_root_version = new_root.signed.version

    repo.bump_root_by_one()
    repo.update_timestamp()
    repo.update_snapshot()
    client.refresh(init_data)

    # Ensure that client does not refresh
    assert client.refresh(init_data) == 1
    assert client._version_equals(Snapshot.type, initial_root_version)


# Set/keep a threshold of 10 keys. All the keyids are different,
# but the keys are all identical. As such, the snapshot metadata
# has been signed by 1 key.
def test_duplicate_keys_root(client: ClientRunner,
                             server: SimulatorServer) -> None:
    # Tests that add_key_to_role works as intended

    name = "test_duplicate_keys_root"

    # initialize a simulator with repository content we need
    repo = RepositorySimulator()
    server.repos[name] = repo
    init_data = server.get_client_init_data(name)
    assert client.init_client(init_data) == 0
    client.refresh(init_data)
    # Sanity checks
    assert client._files_exist([Root.type,
                                       Timestamp.type,
                                       Snapshot.type,
                                       Targets.type])
    assert client._version_equals(Snapshot.type, 1)

    # Add the same signature to Snapshot 9 times
    repo.add_one_role_key_n_times_to_root(Snapshot.type, 9)
    repo.bump_root_by_one()
    assert len(repo.root.roles["snapshot"].keyids) == 10
    repo.update_timestamp()
    repo.update_snapshot()

    # This should fail because the metadata should not have
    # the same key in more than 1 keyids. We check failure
    # here, and further down we check that the clients
    # metadata has not been updated.
    client.refresh(init_data)

    # Verify that the client has not updated its metadata
    try:
        md_root = Metadata.from_file(
            os.path.join(client.metadata_dir, "root.json")).signed
    except DeserializationError as e:
        assert False, "The client has updated its local root metadata with corrupted data"

    try:
        md_snapshot = Metadata.from_file(
            os.path.join(client.metadata_dir, "snapshot.json"))
    except DeserializationError as e:
        assert False, "The client has updated its local root metadata with corrupted data"

    md_root = Metadata.from_file(
            os.path.join(client.metadata_dir, "root.json")).signed
    md_snapshot = Metadata.from_file(
        os.path.join(client.metadata_dir, "snapshot.json"))

    # TODO: Double check that "2" is correct here:
    assert len(md_root.roles[Snapshot.type].keyids) == 2
    # TODO: Double check that "2" is correct here:
    assert len(md_snapshot.signatures) == 2

def test_TestTimestampEqVersionsCheck(client: ClientRunner, server: SimulatorServer) -> None:
    #https://github.com/theupdateframework/go-tuf/blob/f1d8916f08e4dd25f91e40139137edb8bf0498f3/metadata/updater/updater_top_level_update_test.go#L1058
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

    assert client._version_equals(Timestamp.type, initial_timestamp_meta_ver)

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
    assert client._version_equals(
        Root.type, initial_root_version+3
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
    assert client._version_equals(Snapshot.type, 1)

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
    new_ss = repo.load_metadata(Snapshot.type)
    targets_version = repo.load_metadata(Targets.type).signed.version
    new_ss.signed.meta["targets.json"].version = targets_version
    new_ss.signed.version += 1
    repo.save_metadata(Snapshot.type, new_ss)
    repo.update_timestamp()

    client.refresh(init_data)
    assert client._version_equals(Snapshot.type, 1)
    assert client._version_equals(Targets.type, 1)

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
    assert client._version_equals(Targets.type, 1)

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

# TODO: Needs work
def test_downloaded_file_is_correct(client: ClientRunner,
                                    server: SimulatorServer) -> None:
    # A test that upgrades the version of one of the files in snapshot.json only
    # but does does not upgrade in the file itself.
    name = "test_downloaded_file_is_correct"

    # initialize a simulator with repository content we need
    repo = RepositorySimulator()
    server.repos[name] = repo
    init_data = server.get_client_init_data(name)

    assert client.init_client(init_data) == 0
    server_process_handler = utils.TestServerProcess(log=utils.logger)

    target_file_gl = ""

    file_contents = b"target file contents"
    file_contents_str = "target file contents"
    file_length = len(file_contents)
    target_base_name = "target_file.txt"

    target_file_path = os.path.join(client._remote_target_dir.name, target_base_name)
    target_file = open(target_file_path, 'w')
    target_file.write(file_contents_str)
    target_file.close()

    url_prefix = (
        f"http://{utils.TEST_HOST_ADDRESS}:"
        f"{server_process_handler.port!s}/{os.path.basename(client._remote_target_dir.name)}"
    )

    target = TestTarget()
    target.path = target_base_name
    target.content = file_contents
    target.encoded_path = target_base_name

    # Add target to repository
    new_targets = repo.load_metadata(Targets.type)
    new_targets.signed.version += 1
    repo.save_metadata(Targets.type, new_targets)
    repo.add_target_with_length("targets",
                                target.content,
                                target.path,
                                len(target.content))
    repo.update_snapshot()
    client.refresh(init_data)

    # Sanity checks
    assert os.path.isfile(target_file_path)
    with open(target_file_path) as f:
        assert f.read() == file_contents_str


    # Sanity check that we have not downloaded any files yet
    assert client.get_last_downloaded_target() == ""

    target_file2 = client.download_target(init_data,
                                          target_base_name,
                                          target_base_url=url_prefix)

    # Sanity check that we downloaded the file
    expected_last_file = os.path.join(client._target_dir.name,
                                                 target_base_name)
    last_downloaded_file = client.get_last_downloaded_target()
    assert last_downloaded_file == expected_last_file

    with open(client.get_last_downloaded_target(), "r") as last_download_file:
        donwloaded_file_contents = last_download_file.read()
        assert donwloaded_file_contents == file_contents_str
        print("last file contents: ", donwloaded_file_contents)

# TODO: Needs work
def test_downloaded_file_is_correct2(client: ClientRunner,
                                     server: SimulatorServer) -> None:
    # A test that upgrades the version of one of the files in
    # snapshot.json only but does does not upgrade in the file itself.
    name = "test_downloaded_file_is_correct2"

    # initialize a simulator with repository content we need
    repo = RepositorySimulator()
    server.repos[name] = repo
    init_data = server.get_client_init_data(name)
    assert client.init_client(init_data) == 0
    server_process_handler = utils.TestServerProcess(log=utils.logger)

    file_contents = b"legitimate data"
    file_contents_str = "legitimate data"
    file_length = len(file_contents)
    target_base_name = "target_file.txt"

    ## Create, upload and update a legitimate target file
    target_file_path = os.path.join(client._remote_target_dir.name,
                                    target_base_name)
    target_file = open(target_file_path, 'w')
    target_file.write(file_contents_str)
    target_file.close()

    target = TestTarget()
    target.path = target_base_name
    target.content = file_contents
    target.encoded_path = target_base_name

    # Add target to repository
    repo.targets.version += 1
    repo.add_target_with_length("targets", target.content,
                                target.path, len(target.content))
    repo.update_snapshot()
    client.refresh(init_data)

    # Sanity checks
    assert os.path.isfile(target_file_path)
    with open(target_file_path) as f:
        assert f.read() == file_contents_str

    url_prefix = (
        f"http://{utils.TEST_HOST_ADDRESS}:"
        f"{server_process_handler.port!s}/{os.path.basename(client._remote_target_dir.name)}"
    )

    # Sanity check that we have not downloaded any files yet
    assert client.get_last_downloaded_target() == ""

    target_file2 = client.download_target(init_data,
                                          target_base_name,
                                          target_base_url=url_prefix)
    # Sanity check that we downloaded the file
    assert client.get_last_downloaded_target() == os.path.join(client._target_dir.name,
                                                               target_base_name)

    with open(client.get_last_downloaded_target(), "r") as last_download_file:
        data_of_last_downloaded_file = last_download_file.read()
        assert data_of_last_downloaded_file == file_contents_str


    ## Now do the following:
    ## 1: Create a file in the repo with the same name but different contents
    ## 2: Update the targets version in the repo
    ## 3: Download the target
    ## 4: Verify that the client has not downloaded the new file.
    ## The repo does not add the file, so this imitates an attacker
    ## that attempts to compromise the repository.
    malicious_file_contents_str = "malicious data - should not download"
    new_target_file = open(target_file_path, 'w')
    new_target_file.write(malicious_file_contents_str)
    new_target_file.close()

    # Update target version target to repository without
    # updating the target in the metadata
    repo.targets.version += 1
    repo.update_snapshot()
    client.refresh(init_data)

    # Sanity checks
    assert os.path.isfile(target_file_path)
    with open(target_file_path) as f:
        assert f.read() == malicious_file_contents_str

    target_file2 = client.download_target(init_data,
                                          target_base_name,
                                          target_base_url=url_prefix)

    with open(client.get_last_downloaded_target(), "r") as last_download_file:
        data_of_last_downloaded_file = last_download_file.read()
        assert data_of_last_downloaded_file == file_contents_str

# TODO: Needs work
def test_downloaded_file_is_correct3(client: ClientRunner,
                                     server: SimulatorServer) -> None:
    # A test that upgrades the version of one of the files in snapshot.json only
    # but does does not upgrade in the file itself.
    name = "test_downloaded_file_is_correct3"

    # initialize a simulator with repository content we need
    repo = RepositorySimulator()
    server.repos[name] = repo
    init_data = server.get_client_init_data(name)
    assert client.init_client(init_data) == 0
    server_process_handler = utils.TestServerProcess(log=utils.logger)

    file_contents = b"legitimate data"
    file_contents_str = "legitimate data"
    file_length = len(file_contents)
    target_base_name = "target_file.txt"

    ## Create, upload and update a legitimate target file
    target_file_path = os.path.join(client._remote_target_dir.name,
                                    target_base_name)
    target_file = open(target_file_path, 'w')
    target_file.write(file_contents_str)
    target_file.close()

    target = TestTarget()
    target.path = target_base_name
    target.content = file_contents
    target.encoded_path = target_base_name

    # Add target to repository
    repo.targets.version += 1
    repo.add_target_with_length("targets", target.content,
                                target.path, len(target.content))
    repo.update_snapshot()
    client.refresh(init_data)

    # Sanity checks
    assert os.path.isfile(target_file_path)
    with open(target_file_path) as f:
        assert f.read() == file_contents_str

    url_prefix = (
        f"http://{utils.TEST_HOST_ADDRESS}:"
        f"{server_process_handler.port!s}/{os.path.basename(client._remote_target_dir.name)}"
    )

    # Sanity check that we have not downloaded any files yet
    assert client.get_last_downloaded_target() == ""

    target_file2 = client.download_target(init_data,
                                          target_base_name,
                                          target_base_url=url_prefix)
    # Sanity check that we downloaded the file
    assert client.get_last_downloaded_target() == os.path.join(client._target_dir.name,
                                                               target_base_name)

    with open(client.get_last_downloaded_target(), "r") as last_download_file:
        data_of_last_downloaded_file = last_download_file.read()
        assert data_of_last_downloaded_file == file_contents_str


    ## Now do the following:
    ## 1: Create a file in the repo with the same name but different contents
    ## 2: Update the targets version in the repo
    ## 3: Download the target
    ## 4: Verify that the client has not downloaded the new file.
    ## The repo does not add the file, so this imitates an attacker
    ## that attempts to compromise the repository.
    malicious_file_contents_str = "malicious data - should not download"
    new_target_file = open(target_file_path, 'w')
    new_target_file.write(malicious_file_contents_str)
    new_target_file.close()

    # Make a lot of changes to the repo and refresh the client
    # and check the target file
    for i in range(10):
        repo.update_timestamp()
        repo.rotate_keys(Snapshot.type)
        repo.bump_root_by_one()
        repo.bump_version_by_one(Targets.type)
        repo.update_snapshot()
        client.refresh(init_data)
        # Sanity checks
        assert os.path.isfile(target_file_path)
        with open(target_file_path) as f:
            assert f.read() == malicious_file_contents_str
        target_file2 = client.download_target(init_data,
                                              target_base_name,
                                              target_base_url=url_prefix)
        with open(client.get_last_downloaded_target(), "r") as last_download_file:
            data_of_last_downloaded_file = last_download_file.read()
            assert data_of_last_downloaded_file == file_contents_str

def test_multiple_changes_to_target(client: ClientRunner,
                                    server: SimulatorServer) -> None:
    name = "test_downloaded_file_is_correct3"

    # initialize a simulator with repository content we need
    repo = RepositorySimulator()
    server.repos[name] = repo
    init_data = server.get_client_init_data(name)
    assert client.init_client(init_data) == 0
    server_process_handler = utils.TestServerProcess(log=utils.logger)

    file_contents = b"legitimate data"
    file_contents_str = "legitimate data"
    file_length = len(file_contents)
    target_base_name = "target_file.txt"

    ## Create, upload and update a legitimate target file
    target_file_path = os.path.join(client._remote_target_dir.name, target_base_name)
    target_file = open(target_file_path, 'w')
    target_file.write(file_contents_str)
    target_file.close()

    target = TestTarget()
    target.path = target_base_name
    target.content = file_contents
    target.encoded_path = target_base_name

    # Add target to repository
    repo.targets.version += 1
    repo.add_target_with_length("targets", target.content,
                                target.path, len(target.content))
    repo.update_snapshot()
    client.refresh(init_data)

    # Sanity checks
    assert os.path.isfile(target_file_path)
    with open(target_file_path) as f:
        assert f.read() == file_contents_str

    url_prefix = (
        f"http://{utils.TEST_HOST_ADDRESS}:"
        f"{server_process_handler.port!s}/{os.path.basename(client._remote_target_dir.name)}"
    )

    # Sanity check that we have not downloaded any files yet
    assert client.get_last_downloaded_target() == ""

    target_file2 = client.download_target(init_data,
                                          target_base_name,
                                          target_base_url=url_prefix)
    # Sanity check that we downloaded the file
    assert client.get_last_downloaded_target() == os.path.join(client._target_dir.name,
                                                               target_base_name)

    with open(client.get_last_downloaded_target(), "r") as last_download_file:
        data_of_last_downloaded_file = last_download_file.read()
        assert data_of_last_downloaded_file == file_contents_str
    

    # Change the target contents 10 times and check it each time
    for i in range(10):
        new_legitimate_file_contents = f"{file_contents_str}-{i}"
        file_length = len(new_legitimate_file_contents)

        target_file = open(target_file_path, 'w+')
        target_file.write(new_legitimate_file_contents)
        target_file.close()

        new_targets = repo.load_metadata(Targets.type)
        new_targets.signed.version += 1
        repo.save_metadata(Targets.type, new_targets)

        repo.add_target_with_length("targets", bytes(new_legitimate_file_contents, 'utf-8'),
                                    target_base_name, len(bytes(new_legitimate_file_contents, 'utf-8')))
        repo.update_snapshot()
        client.refresh(init_data)

        # Check that the file is the one we expect
        assert os.path.isfile(target_file_path)
        with open(target_file_path) as f:
            assert f.read() == new_legitimate_file_contents
        target_file2 = client.download_target(init_data,
                                              target_base_name,
                                              target_base_url=url_prefix)
        with open(client.get_last_downloaded_target(), "r") as last_download_file:
            data_of_last_downloaded_file = last_download_file.read()
            assert data_of_last_downloaded_file == new_legitimate_file_contents

        # Substitute the file and check that the file is still the one we expect
        malicious_file_contents_str = f"malicious-file-contents-{i}"
        new_target_file = open(target_file_path, 'w+')
        new_target_file.write(malicious_file_contents_str)
        new_target_file.close()

        assert os.path.isfile(target_file_path)
        with open(target_file_path) as f:
            assert f.read() == malicious_file_contents_str
        target_file2 = client.download_target(init_data,
                                              target_base_name,
                                              target_base_url=url_prefix)
        with open(client.get_last_downloaded_target(), "r") as last_download_file:
            data_of_last_downloaded_file = last_download_file.read()
            assert data_of_last_downloaded_file == new_legitimate_file_contents

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