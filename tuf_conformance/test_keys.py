from tuf_conformance.repository_simulator import RepositorySimulator
from tuf_conformance.simulator_server import SimulatorServer, ClientInitData
from tuf_conformance.client_runner import ClientRunner
from securesystemslib.signer import CryptoSigner

from tuf.api.metadata import (
    Timestamp, Snapshot, Root, Targets
)


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


def test_root_two_duplicate_snapshot_public_keys(
    client: ClientRunner, server: SimulatorServer
) -> None:
    """This tests adds two identical public keys for the snapshot
    metadata to the root metadata. It expects the client to fail
    the update because there are two identical keys."""
    name = "test_root_two_duplicate_snapshot_public_keys"

    # initialize a simulator with repository content we need
    repo = RepositorySimulator()
    server.repos[name] = repo
    init_data = server.get_client_init_data(name)
    assert client.init_client(init_data) == 0
    client.refresh(init_data)
    # Add keys
    repo.add_key(Snapshot.type)
    repo.add_key(Snapshot.type)
    repo.add_key(Snapshot.type)
    repo.update_snapshot()  # v2
    repo.bump_root_by_one()  # v2

    assert len(repo.root.roles[Snapshot.type].keyids) == 4
    assert client.refresh(init_data) == 0

    # Set the threshold to 1 to prevent threshold being a blocker.
    repo.md_root.signed.roles[Snapshot.type].threshold = 1 

    # The test will now test that two identical public keys
    # will fail the update. It does this over two steps to
    # be explicit: It first adds the public key so that
    # there are no duplicates. This should succeed. After
    # demonstating that it does succeed, we add the same
    # public key once more and demonstrate that the update
    # fails.
    signer = CryptoSigner.generate_ecdsa()
    repo.root.roles[Snapshot.type].keyids.append(signer.public_key.keyid)
    repo.bump_root_by_one()  # v3
    repo.update_snapshot()  # v3

    # Sanity check
    # The root metadata has 5 public keys for snapshots
    # with no duplicate
    assert len(repo.root.roles[Snapshot.type].keyids) == 5

    # Updating should succeed.
    assert client.refresh(init_data) == 0
    assert client._version(Root.type) == 3
    assert client._version(Snapshot.type) == 3

    # Here we add the public key once more. Add this point,
    # the root metadata has two identical public keys.
    # We then carry the exact same steps as after adding the
    # public key the first time.
    repo.root.roles[Snapshot.type].keyids.append(signer.public_key.keyid)
    repo.bump_root_by_one()  # v4
    repo.update_snapshot()  # v4
    # The root metadata has 6 public keys for snapshots
    # of which 2 are identical.
    assert len(repo.root.roles[Snapshot.type].keyids) == 6
    # Update should now fail
    assert client.refresh(init_data) == 1
    assert client._version(Root.type) == 3
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

    initial_setup_for_key_threshold(client, repo, init_data)
    repo.add_key(Snapshot.type)

    # Increase the threshold but it is met
    assert len(repo.root.roles[Snapshot.type].keyids) == 5
    repo.md_root.signed.roles[Snapshot.type].threshold = 5

    # Set one of the keys' "keyid_hash_algorithms" to an
    # incorrect algorithm.
    valid_key = repo.root.roles[Snapshot.type].keyids[0]
    repo.root.keys[valid_key].unrecognized_fields = dict()
    alg_key = "keyid_hash_algorithms"
    repo.root.keys[valid_key].unrecognized_fields[alg_key] = ["md5"]
    repo.bump_root_by_one()  # v5
    repo.update_snapshot()  # v4
    assert repo._version(Root.type) == 5
    assert repo._version(Snapshot.type) == 4

    # All metadata should update; even though "keyid_hash_algorithms"
    # is wrong, it is not a part of the TUF spec. This is the tests
    # main assertion: That the client updates so that it has the
    # same metadata as the repository.
    assert client.refresh(init_data) == 0
    assert client._version(Root.type) == repo._version(Root.type)
    assert client._version(Snapshot.type) == repo._version(Snapshot.type)


def test_snapshot_threshold(
    client: ClientRunner, server: SimulatorServer
) -> None:
    # Tests that add_key works as intended

    name = "test_snapshot_threshold"

    repo = RepositorySimulator()
    server.repos[name] = repo
    init_data = server.get_client_init_data(name)
    assert client.init_client(init_data) == 0
    client.refresh(init_data)

    # Add 4 Snapshot keys so that there are 5 in total.
    repo.add_key(Snapshot.type)
    repo.add_key(Snapshot.type)
    repo.add_key(Snapshot.type)
    repo.add_key(Snapshot.type)
    assert len(repo.root.roles["snapshot"].keyids) == 5

    # Set higher threshold than we have keys such that the
    # client should not successfully update.
    repo.root.roles[Snapshot.type].threshold = 6

    repo.bump_root_by_one()  # v2
    repo.update_snapshot()  # v2
    assert repo._version(Snapshot.type) == 2
    assert repo._version(Root.type) == 2

    # Ensure that client does not update because it does
    # not have enough keys.
    assert client.refresh(init_data) == 1
    assert client._version(Snapshot.type) == 1


# Set/keep a threshold of 10 keys. All the keyids are different,
# but the keys are all identical. As such, the snapshot metadata
# has been signed by 1 key.
def test_duplicate_keys_root(client: ClientRunner,
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

    # Set a threshold that will be covered but only by
    # the same key multiple times and not separate keys.
    repo.root.roles[Snapshot.type].threshold = 6
    repo.bump_root_by_one()

    repo.update_timestamp()
    repo.update_snapshot()  # v2

    # Sanity check that the clients snapshot
    # metadata is version 1
    assert client._version(Snapshot.type) == 1

    # This should fail because the metadata should not have
    # the same key in more than 1 keyids. We check failure
    # here, and further down we check that the clients
    # metadata has not been updated.
    assert client.refresh(init_data) == 1

    # The clients snapshot metadata should still
    # be version 1
    assert client._version(Snapshot.type) == 1
