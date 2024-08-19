from securesystemslib.signer import CryptoSigner
from tuf.api.metadata import Root, Snapshot

from tuf_conformance.client_runner import ClientRunner
from tuf_conformance.repository_simulator import RepositorySimulator
from tuf_conformance.simulator_server import ClientInitData, SimulatorServer


def initial_setup_for_key_threshold(
    client: ClientRunner, repo: RepositorySimulator, init_data: ClientInitData
) -> None:
    # Explicitly set the threshold
    repo.root.roles[Snapshot.type].threshold = 3
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
    assert client.refresh(init_data) == 0

    initial_setup_for_key_threshold(client, repo, init_data)

    # Increase the threshold
    repo.root.roles[Snapshot.type].threshold = 5
    repo.bump_root_by_one()  # v5

    # Refresh should fail: root updates but there's no new snapshot:
    # The existing snapshot does not meet threshold anymore.
    # NOTE: we don't actually expect clients to delete the
    # file from trusted_roles() at this point
    assert client.refresh(init_data) == 1
    assert client.version(Root.type) == 5

    # Add two keyids only to root and expect the client
    # to fail updating
    signer = CryptoSigner.generate_rsa(scheme="rsa-pkcs1v15-sha256")

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
    repo.root.roles[Snapshot.type].threshold = 5

    # Set one of the keys' "keyid_hash_algorithms" to an
    # incorrect algorithm.
    valid_key = repo.root.roles[Snapshot.type].keyids[0]
    repo.root.keys[valid_key].unrecognized_fields = dict()
    alg_key = "keyid_hash_algorithms"
    repo.root.keys[valid_key].unrecognized_fields[alg_key] = ["md5"]
    repo.bump_root_by_one()  # v5
    repo.update_snapshot()  # v4

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

    # Ensure that client does not update because it does
    # not have enough keys.
    assert client.refresh(init_data) == 1
    assert client.version(Snapshot.type) == 1


def test_duplicate_keys_root(client: ClientRunner, server: SimulatorServer) -> None:
    """Test multiple identical keyids, try to fake threshold

    Client should either not accept metadata with duplicate keyids in a role,
    or it should not allow the duplicate keyids to count in threshold calculation
    """
    init_data, repo = server.new_test(client.test_name)

    assert client.init_client(init_data) == 0

    signer = CryptoSigner.generate_rsa(scheme="rsa-pkcs1v15-sha256")

    # Add one key 9 times to root
    for n in range(0, 9):
        repo.root.add_key(signer.public_key, Snapshot.type)

    repo.add_signer(Snapshot.type, signer)

    # Set a threshold that will be covered but only by
    # the same key multiple times and not separate keys.
    repo.root.roles[Snapshot.type].threshold = 6
    repo.bump_root_by_one()

    # This should fail for one of two reasons:
    # 1. client does not accept root v2 metadata that contains duplicate keyids or
    # 2. client did accept root v2 but then snapshot threshold is not reached
    assert client.refresh(init_data) == 1

    # client should not have accepted snapshot
    assert client.version(Snapshot.type) is None
