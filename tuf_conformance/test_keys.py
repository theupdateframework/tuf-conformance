from securesystemslib.signer import CryptoSigner
from tuf.api.metadata import Root, Snapshot, Targets, Timestamp

from tuf_conformance.client_runner import ClientRunner
from tuf_conformance.repository_simulator import RepositorySimulator
from tuf_conformance.simulator_server import ClientInitData, SimulatorServer


def initial_setup_for_key_threshold(
    client: ClientRunner, repo: RepositorySimulator, init_data: ClientInitData
) -> None:
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
    assert client.version(Snapshot.type) == 3
    assert client.version(Root.type) == 4


def test_root_has_keys_but_not_snapshot(
    client: ClientRunner, server: SimulatorServer
) -> None:
    """This test adds keys to the repo root MD to test for cases
    where are client might calculate the threshold from only the
    roots keys and not check that the snapshot MD has the same
    keys"""
    init_data, repo = server.new_test(client.test_name)

    assert client.init_client(init_data) == 0
    client.refresh(init_data)
    # Sanity checks
    assert client._files_exist([Root.type, Timestamp.type, Snapshot.type, Targets.type])
    assert client.version(Snapshot.type) == 1
    assert len(repo.md_snapshot.signatures) == 1

    initial_setup_for_key_threshold(client, repo, init_data)

    # Increase the threshold
    repo.root.roles[Snapshot.type].threshold = 5
    repo.bump_root_by_one()  # v5

    # Updating should fail. Root should bump, but not snapshot
    assert client.refresh(init_data) == 1
    assert client.version(Root.type) == 5
    assert client.version(Snapshot.type) == 3

    # Add two invalid keys only to root and expect the client
    # to fail updating
    signer = CryptoSigner.generate_ecdsa()

    repo.root.roles[Snapshot.type].keyids.append(signer.public_key.keyid)

    # Sanity check
    assert len(repo.root.roles[Snapshot.type].keyids) == 5

    # Updating should fail. Root should bump, but not snapshot
    assert client.refresh(init_data) == 1
    assert client.version(Root.type) == 5
    assert client.version(Snapshot.type) == 3


def test_wrong_hashing_algorithm(client: ClientRunner, server: SimulatorServer) -> None:
    """This test sets a wrong but valid hashing algorithm for a key
    in the root MD. The client should not care and still update"""
    init_data, repo = server.new_test(client.test_name)

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
    assert client.version(Root.type) == repo._version(Root.type)
    assert client.version(Snapshot.type) == repo._version(Snapshot.type)


def test_snapshot_threshold(client: ClientRunner, server: SimulatorServer) -> None:
    # Test basic failure to reach signature threshold
    init_data, repo = server.new_test(client.test_name)

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
    assert client.version(Snapshot.type) == 1


def test_duplicate_keys_root(client: ClientRunner, server: SimulatorServer) -> None:
    # Set/keep a threshold of 10 keys. All the keyids are different,
    # but the keys are all identical. As such, the snapshot metadata
    # has been signed by 1 key.
    init_data, repo = server.new_test(client.test_name)

    assert client.init_client(init_data) == 0
    client.refresh(init_data)
    # Sanity checks
    assert client._files_exist([Root.type, Timestamp.type, Snapshot.type, Targets.type])
    assert client.version(Snapshot.type) == 1

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
    assert client.version(Snapshot.type) == 1

    # This should fail because the metadata should not have
    # the same key in more than 1 keyids. We check failure
    # here, and further down we check that the clients
    # metadata has not been updated.
    assert client.refresh(init_data) == 1

    # The clients snapshot metadata should still
    # be version 1
    assert client.version(Snapshot.type) == 1
