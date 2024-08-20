from tuf.api.metadata import Root, Snapshot

from tuf_conformance.client_runner import ClientRunner
from tuf_conformance.repository_simulator import RepositorySimulator
from tuf_conformance.simulator_server import ClientInitData, SimulatorServer


def initial_setup_for_key_threshold(
    client: ClientRunner, repo: RepositorySimulator, init_data: ClientInitData
) -> None:
    """This is a helper for tests for key thresholds.
    It sets a threshold of 3 for snapshot metadata,
    adds three keys, bumps the repo metadata and
    refreshes the client"""

    # Set treshold to 3 for snapshot metadata
    repo.root.roles[Snapshot.type].threshold = 3

    # Add three keys for snapshot:
    repo.add_key(Snapshot.type)
    repo.add_key(Snapshot.type)
    repo.add_key(Snapshot.type)
    repo.update_timestamp()
    repo.update_snapshot()  # v2
    repo.bump_root_by_one()  # v2

    assert len(repo.root.roles[Snapshot.type].keyids) == 4

    assert client.refresh(init_data) == 0
    assert client.version(Snapshot.type) == 2
    assert client.version(Root.type) == 2


def test_root_has_keys_but_not_snapshot(
    client: ClientRunner, server: SimulatorServer
) -> None:
    """This test adds keys for snapshot metadata only to the
    repo root MD to test for a case where a client might
    calculate the threshold from only the key in the root MD
    and not check that the snapshot MD also has the same keys.
    For example, the goal is to bring the repository into a state where:

    1. repo.root.roles.snapshot.keyids has the following keyids:
      1.a: ccce1a69b4eea9daf315d8a9c43fffd8ee541bfb41fdcb773657192af51d3cfa
      1.b: 4f7c454c55a81918fa1fc1f513d510f36c3efa796711d9f5883602f91a5b9da7
      1.c: 146e0dc5038d3b8772f5d4bd6626fe1436f656494b501628a2b54d6aa6a6edfe
      1.d: 3c80449ebd33c67ff8d9befce23c534b50d97ed805e52da8c746e6a1daefab8e
    2: repo.root.roles.snapshot.threshold is 4
    3: repo.snapshot.signatures has the following keyids:
      3.a: ccce1a69b4eea9daf315d8a9c43fffd8ee541bfb41fdcb773657192af51d3cfa
      3.b: 4f7c454c55a81918fa1fc1f513d510f36c3efa796711d9f5883602f91a5b9da7
      3.c: 146e0dc5038d3b8772f5d4bd6626fe1436f656494b501628a2b54d6aa6a6edfe

    The test ensures that clients do not update snapshot in this scenario.
    """
    init_data, repo = server.new_test(client.test_name)

    assert client.init_client(init_data) == 0
    assert client.refresh(init_data) == 0

    initial_setup_for_key_threshold(client, repo, init_data)

    # Set the threshold to 4 and remove a signer from snapshot
    # metadata so that root has 4 keys and snapshot has 3
    repo.root.roles[Snapshot.type].threshold = 4
    repo.signers[Snapshot.type].popitem()
    repo.bump_root_by_one()  # v3
    repo.update_snapshot()  # v3

    # The snapshot does not meet the threshold anymore,
    # because there are 3 snapshot signers keys, and the
    # threshold is 4.
    # NOTE: we don't actually expect clients to delete the
    # file from trusted_roles() at this point
    assert client.refresh(init_data) == 1
    assert client.version(Root.type) == 3
    assert client.version(Snapshot.type) == 2


def test_wrong_hashing_algorithm(client: ClientRunner, server: SimulatorServer) -> None:
    """This test sets a wrong but valid hashing algorithm for a key
    in the root MD. The client should not care and still update"""
    init_data, repo = server.new_test(client.test_name)

    assert client.init_client(init_data) == 0
    assert client.refresh(init_data) == 0

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
    repo.bump_root_by_one()  # v4
    repo.update_snapshot()  # v3

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
    assert client.refresh(init_data) == 0

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

    signer = repo.new_signer()

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
