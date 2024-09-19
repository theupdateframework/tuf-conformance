import pytest
from tuf.api.metadata import Root, Snapshot, Targets, Timestamp

from tuf_conformance.client_runner import ClientRunner
from tuf_conformance.simulator_server import SimulatorServer


def test_simple_snapshot_rollback(
    client: ClientRunner, server: SimulatorServer
) -> None:
    """Test a simple snapshot version rollback attack.

    Repository publishes a snapshot with version that is not higher than what client has
    already seen, without updating timestamp.meta.
    Expect client to refuse the update.
    """

    init_data, repo = server.new_test(client.test_name)

    assert client.init_client(init_data) == 0

    # Repository performs legitimate update to snapshot
    repo.publish([Snapshot.type, Timestamp.type])
    assert client.refresh(init_data) == 0

    # Repository attempts rollback attack (note that the snapshot version in
    # timestamp.meta is v2)
    repo.publish([Snapshot.type])
    # Client succeeds in this case since it already has the snapshot version specified
    # in timestamp.meta
    assert client.refresh(init_data) == 0

    # Check that client resisted rollback attack
    assert client.version(Snapshot.type) == 2
    assert repo.metadata_statistics[-1] == (Timestamp.type, None)


def test_new_timestamp_version_rollback(
    client: ClientRunner, server: SimulatorServer
) -> None:
    """Test a timestamp version rollback attack.

    Repository publishes a timestamp with version that is not higher than what client
    has already seen. Expect client to refuse the update
    """
    init_data, repo = server.new_test(client.test_name)

    assert client.init_client(init_data) == 0

    # Repository performs legitimate update to timestamp
    repo.publish([Timestamp.type])
    assert client.refresh(init_data) == 0

    # Sanity check that client saw the timestamp update:
    assert client.version(Timestamp.type) == 2

    # Repository attempts rollback attack:
    del repo.signed_mds[Timestamp.type]
    repo.timestamp.version = 1
    repo.publish([Timestamp.type])
    assert client.refresh(init_data) == 1

    # Check that client resisted rollback attack
    assert client.version(Timestamp.type) == 2
    assert repo.metadata_statistics[-1] == (Timestamp.type, None)


@pytest.mark.parametrize("use_hashes", [False, True], ids=["basic", "with hashes"])
def test_snapshot_rollback(
    client: ClientRunner, server: SimulatorServer, use_hashes: bool
) -> None:
    """Test a complete snapshot version rollback attack.

    Repository publishes a snapshot with version that is not higher than what client has
    already seen, updating timestamp.meta.
    Expect client to refuse the update.
    """
    init_data, repo = server.new_test(client.test_name)
    assert client.init_client(init_data) == 0

    # When hashes are used and timestamp update happens:
    #  1) snapshot hash is is computed
    #  2) hash is stored in timestamp.snapshot_meta
    # The local snapshot must be used in rollback check even when hashes are used

    repo.compute_metafile_hashes_length = use_hashes
    repo.publish([Snapshot.type, Timestamp.type])  # v2, v2

    assert client.refresh(init_data) == 0

    # Repo attempts snapshot version rollback attack
    del repo.signed_mds[Snapshot.type]
    repo.snapshot.version = 1
    repo.publish([Snapshot.type, Timestamp.type])  # v1, v3

    assert client.refresh(init_data) == 1

    # Check that client resisted rollback attack
    assert client.version(Timestamp.type) == 2
    assert client.version(Snapshot.type) == 2
    assert repo.metadata_statistics[-1] == (Timestamp.type, None)


def test_new_targets_fast_forward_recovery(
    client: ClientRunner, server: SimulatorServer
) -> None:
    """Test targets fast-forward recovery using key rotation.

    The targets recovery is made by issuing new Snapshot keys, by following
    steps:
        - Remove the snapshot key
        - Create and add a new key for snapshot
        - Bump and publish root
        - Rollback the target version
    """

    init_data, repo = server.new_test(client.test_name)
    assert client.init_client(init_data) == 0

    for i in range(99):
        repo.publish([Targets.type])
    repo.publish([Snapshot.type, Timestamp.type])

    assert client.refresh(init_data) == 0
    assert client.version(Targets.type) == 100

    repo.rotate_keys(Snapshot.type)
    repo.targets.version = 1
    repo.publish([Root.type, Targets.type, Snapshot.type, Timestamp.type])

    assert client.refresh(init_data) == 0
    assert client.version(Targets.type) == 2


def test_new_snapshot_fast_forward_recovery(
    client: ClientRunner, server: SimulatorServer
) -> None:
    """Test snapshot fast-forward recovery using key rotation.

    The snapshot recovery requires the snapshot and timestamp key rotation.
    It is made by the following steps:
    - Remove the snapshot and timestamp keys
    - Create and add a new key for snapshot and timestamp
    - Rollback snapshot version
    - Bump and publish root
    - Bump the timestamp
    """
    init_data, repo = server.new_test(client.test_name)

    assert client.init_client(init_data) == 0
    for i in range(99):
        repo.publish([Snapshot.type])
    repo.publish([Timestamp.type])

    # client refreshes the metadata and see the new snapshot version
    assert client.refresh(init_data) == 0
    assert client.version(Snapshot.type) == 100

    # rotate keys, rollback snapshot to version 1
    repo.rotate_keys(Snapshot.type)
    repo.rotate_keys(Timestamp.type)
    del repo.signed_mds[Snapshot.type]
    repo.snapshot.version = 1
    repo.publish([Root.type, Targets.type, Snapshot.type, Timestamp.type])

    assert client.refresh(init_data) == 0
    assert client.version(Snapshot.type) == 1


def test_new_snapshot_version_mismatch(
    client: ClientRunner, server: SimulatorServer
) -> None:
    """Tests that the client does not download the snapshot
    metadata if the repo has bumped the snapshot version in
    the snapshot metadata but not in timestamp.meta.
    """

    init_data, repo = server.new_test(client.test_name)

    assert client.init_client(init_data) == 0

    # Increase snapshot version but do not update version in timestamp.snapshot_meta
    repo.publish([Snapshot.type])  # v2
    repo.timestamp.snapshot_meta.version -= 1
    repo.publish([Root.type, Timestamp.type])  # v2

    assert client.refresh(init_data) == 0
    assert client.trusted_roles() == [
        (Root.type, 2),
        (Snapshot.type, 1),
        (Targets.type, 1),
        (Timestamp.type, 2),
    ]


def test_new_timestamp_fast_forward_recovery(
    client: ClientRunner, server: SimulatorServer
) -> None:
    """The timestamp recovery is made by the following steps
    - Remove the timestamp key
    - Create and add a new key for timestamp
    - Bump and publish root
    - Rollback the timestamp version
    """

    init_data, repo = server.new_test(client.test_name)

    assert client.init_client(init_data) == 0

    # attacker updates to a higher version
    for i in range(99):
        repo.publish([Timestamp.type])

    # client refreshes the metadata and see the new timestamp version
    assert client.refresh(init_data) == 0
    assert client.version(Timestamp.type) == 100

    # repository rotates timestamp keys,
    # rolls back timestamp version
    repo.rotate_keys(Timestamp.type)
    repo.publish([Root.type, Targets.type, Snapshot.type, Timestamp.type])
    repo.timestamp.version = 1
    repo.publish([Timestamp.type], bump_version=False)

    # client refresh the metadata and see the initial timestamp version
    assert client.refresh(init_data) == 0
    assert client.version(Timestamp.type) == 1


@pytest.mark.parametrize("use_hashes", [False, True], ids=["basic", "with hashes"])
def test_targets_rollback(
    client: ClientRunner, server: SimulatorServer, use_hashes: bool
) -> None:
    """Test targets rollback

    the targets version info in local snapshot.meta should get used in a rollback check.
    """
    init_data, repo = server.new_test(client.test_name)

    # When hashes are used and timestamp update happens:
    #  1) snapshot hash is is computed
    #  2) hash is stored in timestamp.snapshot_meta
    # The local snapshot must be used in rollback check even when hashes are used
    assert client.init_client(init_data) == 0

    repo.compute_metafile_hashes_length = use_hashes
    repo.publish([Targets.type, Snapshot.type, Timestamp.type])  # v2, v2, v2

    assert client.refresh(init_data) == 0

    # rollback targets version, start again from v1:
    del repo.signed_mds[Targets.type]
    repo.targets.version = 1
    repo.publish([Targets.type, Snapshot.type, Timestamp.type])  # v1, v3, v3

    # Client refresh should fail because of targets rollback
    assert client.refresh(init_data) == 1
    assert client.version(Snapshot.type) == 2
    assert client.version(Targets.type) == 2
