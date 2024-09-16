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
    repo.update_snapshot()  # v2
    assert client.refresh(init_data) == 0

    # Repository attempts rollback attack (note that the snapshot version in
    # timestamp.meta is v2)
    repo.snapshot.version -= 1  # v1
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
    repo.update_timestamp()  # v2
    assert client.refresh(init_data) == 0

    # Sanity check that client saw the timestamp update:
    assert client.version(Timestamp.type) == 2

    # Repository attempts rollback attack:
    repo.timestamp.version -= 1  # v1
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
    # When hashes are used and timestamp update happens:
    #  1) snapshot hash is is computed
    #  2) hash is stored in timestamp.snapshot_meta
    # The local snapshot must be used in rollback check even when hashes are used
    repo.compute_metafile_hashes_length = use_hashes

    assert client.init_client(init_data) == 0

    # Start snapshot version at 2
    repo.update_snapshot()  # v2, timestamp = v2

    assert client.refresh(init_data) == 0

    # Repo attempts rollback attack
    repo.snapshot.version = 1
    repo.update_timestamp()  # v3

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

    repo.targets.version = 99999
    repo.update_snapshot()  # v2

    assert client.refresh(init_data) == 0
    assert client.version(Targets.type) == 99999

    repo.rotate_keys(Snapshot.type)
    repo.publish([Snapshot.type, Timestamp.type])
    repo.publish([Root.type], bump_version=True)

    repo.targets.version = 1
    repo.update_snapshot()  # v3
    repo.publish([Targets.type, Snapshot.type, Timestamp.type])

    assert client.refresh(init_data) == 0
    assert client.version(Targets.type) == 1


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
    repo.snapshot.version = 99999
    repo.update_timestamp()
    repo.publish([Targets.type, Snapshot.type, Timestamp.type])

    # client refreshes the metadata and see the new snapshot version
    assert client.refresh(init_data) == 0
    assert client.version(Snapshot.type) == 99999

    repo.rotate_keys(Snapshot.type)
    repo.rotate_keys(Timestamp.type)
    repo.publish([Targets.type, Snapshot.type, Timestamp.type])
    repo.publish([Root.type], bump_version=True)

    repo.snapshot.version = 1
    repo.update_timestamp()
    repo.publish([Targets.type, Snapshot.type, Timestamp.type])

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

    # Increase snapshot version without updating timestamp
    repo.snapshot.version += 1
    repo.publish([Snapshot.type, Timestamp.type])

    assert client.refresh(init_data) == 1
    assert client.trusted_roles() == [(Root.type, 1), (Timestamp.type, 1)]
    assert repo.metadata_statistics[-1] == (Snapshot.type, 1)


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
    repo.timestamp.version = 99999
    repo.publish([Timestamp.type])

    # client refreshes the metadata and see the new timestamp version
    assert client.refresh(init_data) == 0
    assert client.version(Timestamp.type) == 99999

    # repository rotates timestamp keys,
    # rolls back timestamp version
    repo.rotate_keys(Timestamp.type)
    repo.publish([Targets.type, Snapshot.type, Timestamp.type])
    repo.publish([Root.type], bump_version=True)
    repo.timestamp.version = 1
    repo.publish([Timestamp.type])

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
    repo.compute_metafile_hashes_length = use_hashes

    assert client.init_client(init_data) == 0

    # Initialize all metadata and assign targets
    # version higher than 1.
    repo.targets.version = 2
    repo.timestamp.version += 1
    repo.snapshot.version += 1
    repo.publish([Targets.type, Snapshot.type, Timestamp.type])
    repo.update_snapshot()  # v2
    assert client.refresh(init_data) == 0

    # The new targets must have a lower version than the local trusted one.
    repo.targets.version = 1
    repo.publish([Targets.type, Snapshot.type, Timestamp.type])
    repo.update_snapshot()  # v3

    # Client refresh should fail because of targets rollback
    assert client.refresh(init_data) == 1
    assert client.version(Snapshot.type) == 3
    assert client.version(Targets.type) == 2
