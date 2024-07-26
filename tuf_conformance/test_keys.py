import os

from tuf_conformance.repository_simulator import RepositorySimulator
from tuf_conformance.simulator_server import SimulatorServer, ClientInitData
from tuf_conformance.client_runner import ClientRunner
from securesystemslib.signer import CryptoSigner

from tuf.api.metadata import (
    Timestamp, Snapshot, Root, Targets, Metadata
)
from tuf.api.serialization import DeserializationError


def initial_setup_for_key_threshold(client: ClientRunner,
                                    repo: RepositorySimulator,
                                    init_data: ClientInitData) -> None:
    # Explicitly set the threshold
    repo.md_root.signed.roles[Snapshot.type].threshold = 3
    repo.bump_root_by_one()  # v2

    # Add a legitimate key:
    repo.add_key(Snapshot.type)
    repo.update_timestamp()
    repo.update_snapshot()
    repo.bump_root_by_one()  # v3

    assert client.refresh(init_data) == 1

    # Add a legitimate key:
    repo.add_key(Snapshot.type)
    repo.add_key(Snapshot.type)
    repo.update_timestamp()
    repo.update_snapshot()
    repo.bump_root_by_one()  # v4

    assert len(repo.root.roles[Snapshot.type].keyids) == 4

    assert client.refresh(init_data) == 0
    assert client._version(Snapshot.type) == 3
    assert client._version(Root.type) == 4


def test_root_has_keys_but_not_snapshot(client: ClientRunner,
                                        server: SimulatorServer) -> None:
    """This test adds keys to the repo root MD to test for cases
    where are client might calculate the threshold from only the
    roots keys and not check that the snapshot MD has the same
    keys"""
    name = "test_root_has_keys_but_not_snapshot"

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
    assert client._version(Snapshot.type) == 1
    assert len(repo.md_snapshot.signatures) == 1

    initial_setup_for_key_threshold(client, repo, init_data)

    # Increase the threshold
    repo.root.roles[Snapshot.type].threshold = 5
    repo.bump_root_by_one()  # v5

    # Updating should fail. Root should bump, but not snapshot
    assert client.refresh(init_data) == 1
    assert client._version(Root.type) == 5
    assert client._version(Snapshot.type) == 3

    # Add two invalid keys only to root and expect the client
    # to fail updating
    signer = CryptoSigner.generate_ecdsa()

    repo.root.roles[Snapshot.type].keyids.append(signer.public_key.keyid)

    # Sanity check
    assert len(repo.root.roles[Snapshot.type].keyids) == 5

    # Updating should fail. Root should bump, but not snapshot
    assert client.refresh(init_data) == 1
    assert client._version(Root.type) == 5
    assert client._version(Snapshot.type) == 3


def test_wrong_hashing_algorithm(client: ClientRunner,
                                 server: SimulatorServer) -> None:
    """This test sets a wrong but valid hashing algorithm for a key
    in the root MD. The client should not care and still update"""

    name = "test_wrong_hashing_algorithm"

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
    assert client._version(Snapshot.type) == 1
    assert len(repo.md_snapshot.signatures) == 1

    initial_setup_for_key_threshold(client, repo, init_data)

    assert client.refresh(init_data) == 0
    assert client._version(Root.type) == 4
    assert client._version(Snapshot.type) == 3
    assert len(repo.root.roles[Snapshot.type].keyids) == 4

    # Increase the threshold
    repo.md_root.signed.roles[Snapshot.type].threshold = 5
    repo.bump_root_by_one()  # v5

    # Verify that the client cannot update snapshot
    # because it has 4 keys and the threshold is 5.
    # This is mostly a sanity check.
    assert client.refresh(init_data) == 1
    assert client._version(Root.type) == 5
    assert client._version(Snapshot.type) == 3

    # Add a valid key and bump
    repo.add_key(Snapshot.type)
    repo.update_timestamp()
    repo.update_snapshot()  # v4
    repo.bump_root_by_one()  # v6

    # Verify that the client can update before making
    # the metadata faulty
    assert client.refresh(init_data) == 0
    assert client._version(Root.type) == 6
    assert client._version(Snapshot.type) == 4

    # Change hashing algorithm of a valid key
    # Let's bump so that the client sees there are updates.
    # Note that we change the hashing algorithm after bumping
    repo.update_timestamp()
    repo.update_snapshot()  # v5
    repo.bump_root_by_one()  # v7
    valid_key = repo.root.roles[Snapshot.type].keyids[0]
    repo.root.keys[valid_key].unrecognized_fields = dict()
    alg_key = "keyid_hash_algorithms"
    repo.root.keys[valid_key].unrecognized_fields[alg_key] = ["md5"]
    repo.bump_root_by_one()  # v8

    # All metadata should update; even though "keyid_hash_algorithms"
    # is wrong, it is not a part of the TUF spec.
    assert client.refresh(init_data) == 0
    assert client._version(Root.type) == 8
    assert client._version(Snapshot.type) == 5


def test_simple_signing(client: ClientRunner,
                        server: SimulatorServer) -> None:
    # Tests that add_key works as intended

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
    assert client._version(Snapshot.type) == 1

    # Add signature to Snapshot
    repo.add_key(Snapshot.type)
    repo.add_key(Snapshot.type)
    repo.add_key(Snapshot.type)

    repo.bump_root_by_one()

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
    repo.add_key(Snapshot.type)
    repo.bump_root_by_one()

    # Sanity check
    assert len(repo.root.roles["snapshot"].keyids) == 5

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
    repo.md_root.signed.roles[Snapshot.type].threshold = 10
    initial_root_version = repo.root.version

    repo.bump_root_by_one()
    repo.update_timestamp()
    repo.update_snapshot()
    client.refresh(init_data)

    # Ensure that client does not refresh
    assert client.refresh(init_data) == 1
    assert client._version(Snapshot.type) == initial_root_version


# Set/keep a threshold of 10 keys. All the keyids are different,
# but the keys are all identical. As such, the snapshot metadata
# has been signed by 1 key.
def Ttest_duplicate_keys_root(client: ClientRunner,
                             server: SimulatorServer) -> None:
    # Tests that add_key works as intended

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
    assert client._version(Snapshot.type) == 1

    # Add the same key 9 times
    signer = CryptoSigner.generate_ecdsa()

    # Add one key 9 times to root
    for n in range(0, 9):
        repo.root.add_key(signer.public_key, Snapshot.type)

    repo.add_signer(Snapshot.type, signer)

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
    except DeserializationError:
        assert False, "The client has updated with corrupted data"

    try:
        md_snapshot = Metadata.from_file(
            os.path.join(client.metadata_dir, "snapshot.json"))
    except DeserializationError:
        assert False, "The client has updated with corrupted data"

    md_root = Metadata.from_file(
            os.path.join(client.metadata_dir, "root.json")).signed
    md_snapshot = Metadata.from_file(
        os.path.join(client.metadata_dir, "snapshot.json"))

    # TODO: Double check that "1" is correct here:
    assert len(md_root.roles[Snapshot.type].keyids) == 1
    # TODO: Double check that "1" is correct here:
    assert len(md_snapshot.signatures) == 1
