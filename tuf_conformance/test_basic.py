# Test runner
import json
import os

from tuf.api.metadata import Metadata, Root, Snapshot, Targets, Timestamp

from tuf_conformance.client_runner import ClientRunner
from tuf_conformance.simulator_server import SimulatorServer


def test_timestamp_content_changes(
    client: ClientRunner, server: SimulatorServer
) -> None:
    """Repository modifies timestamp content without bumping a version. Expect client
    to keep using the version it already has.
    """
    # https://github.com/theupdateframework/go-tuf/blob/f1d8916f08e4dd25f91e40139137edb8bf0498f3/metadata/updater/updater_top_level_update_test.go#L1058
    init_data, repo = server.new_test(client.test_name)

    assert client.init_client(init_data) == 0
    client.refresh(init_data)
    # Sanity check
    assert client._files_exist([Root.type, Timestamp.type, Snapshot.type, Targets.type])

    initial_timestamp_meta_ver = repo.timestamp.snapshot_meta.version
    # Change timestamp without bumping its version in order to test if a new
    # timestamp with the same version will be persisted.
    repo.timestamp.snapshot_meta.version = 100

    client.refresh(init_data)

    assert client.version(Timestamp.type) == initial_timestamp_meta_ver


def test_new_targets_hash_mismatch(
    client: ClientRunner, server: SimulatorServer
) -> None:
    # Check against snapshot role's targets hashes
    init_data, repo = server.new_test(client.test_name)

    assert client.init_client(init_data) == 0
    client.refresh(init_data)
    # Sanity check
    assert client._files_exist([Root.type, Timestamp.type, Snapshot.type])

    repo.compute_metafile_hashes_length = True
    repo.update_snapshot()

    client.refresh(init_data)

    # Modify targets contents without updating
    # snapshot's targets hashes
    repo.targets.version += 1
    repo.snapshot.meta["targets.json"].version = repo.targets.version
    repo.snapshot.version += 1
    repo.update_timestamp()

    client.refresh(init_data)
    assert client.version(Snapshot.type) == 1
    assert client.version(Targets.type) == 1


def test_new_targets_version_mismatch(
    client: ClientRunner, server: SimulatorServer
) -> None:
    # Check against snapshot role's targets version
    init_data, repo = server.new_test(client.test_name)

    assert client.init_client(init_data) == 0
    client.refresh(init_data)
    assert client._files_exist([Root.type, Timestamp.type, Snapshot.type, Targets.type])

    repo.targets.version += 1
    client.refresh(init_data)
    # Check that the client still has the correct metadata files
    assert client._files_exist([Root.type, Timestamp.type, Snapshot.type, Targets.type])


def test_basic_init_and_refresh(client: ClientRunner, server: SimulatorServer) -> None:
    init_data, repo = server.new_test(client.test_name)

    # Run the test: step 1:  initialize client
    assert client.init_client(init_data) == 0

    # Run the test: step 2: Refresh
    assert client.refresh(init_data) == 0

    # Verify that expected requests were made
    assert repo.metadata_statistics == [
        ("root", 2),
        ("timestamp", None),
        ("snapshot", 1),
        ("targets", 1),
    ]

    # verify client metadata looks as expected
    assert client.version(Root.type) == 1
    assert client.version(Timestamp.type) == 1
    assert client.version(Snapshot.type) == 1
    assert client.version(Targets.type) == 1


def test_implicit_refresh(client: ClientRunner, server: SimulatorServer) -> None:
    """Run download immediately after initialization: Expect download to fail
    (as targetpath does not exist) but expect metadata to get updated
    """

    init_data, repo = server.new_test(client.test_name)
    assert client.init_client(init_data) == 0

    assert client.download_target(init_data, "nonexistent artifact") == 1

    # Verify that expected requests were made
    assert repo.metadata_statistics == [
        ("root", 2),
        ("timestamp", None),
        ("snapshot", 1),
        ("targets", 1),
    ]

    # verify client metadata looks as expected
    assert client.version(Root.type) == 1
    assert client.version(Timestamp.type) == 1
    assert client.version(Snapshot.type) == 1
    assert client.version(Targets.type) == 1


def test_invalid_initial_root(client: ClientRunner, server: SimulatorServer) -> None:
    """Initialize client with invalid root. Expect refresh to fail and
    nothing to get downloaded from repository
    """
    init_data, repo = server.new_test(client.test_name)

    root_json = json.loads(init_data.trusted_root)
    del root_json["signed"]["version"]
    init_data.trusted_root = json.dumps(root_json).encode()

    # init may or may not fail (depending on if client does validation at this point)
    client.init_client(init_data)

    # Verify that refresh fails and no requests were made
    assert client.refresh(init_data) == 1
    assert repo.metadata_statistics == []


def test_unsigned_initial_root(client: ClientRunner, server: SimulatorServer) -> None:
    """Initialize client with root that is not correctly signed. Expect refresh to fail
    and nothing to get downloaded from repository
    """
    init_data, repo = server.new_test(client.test_name)

    # replace root signature with some other signature
    root_json = json.loads(init_data.trusted_root)
    root_json["signatures"][0]["sig"] = (
        "3045022100ee448afe2d25dd1f05afedac83a24e7df90f203615221434979153dc7cea6d4702207710015851e571885a77db8a6e42c4b2983a59b9e1ebec91178dfa2fb0d42ab8"
    )
    init_data.trusted_root = json.dumps(root_json).encode()

    # init may or may not fail (depending on if client does validation at this point)
    client.init_client(init_data)

    # Verify that refresh fails and no requests were made
    assert client.refresh(init_data) == 1
    assert repo.metadata_statistics == []


def test_timestamp_eq_versions_check(
    client: ClientRunner, server: SimulatorServer
) -> None:
    # Test that a modified timestamp with different content, but the same
    # version doesn't replace the valid locally stored one.
    init_data, repo = server.new_test(client.test_name)

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


def test_custom_fields(client: ClientRunner, server: SimulatorServer) -> None:
    """Verify that client copes with unexpected fields in metadata.

    spec section 4: "Implementers who encounter undefined attribute-value pairs
    in the format must include the data when calculating hashes or verifying
    signatures."""

    init_data, repo = server.new_test(client.test_name)

    assert client.init_client(init_data) == 0
    assert client.refresh(init_data) == 0

    # Add some custom fields into root metadata, make a new root version
    repo.root.unrecognized_fields["custom-field"] = "value"
    keyid = repo.root.roles[Root.type].keyids[0]
    repo.root.keys[keyid].unrecognized_fields["extra-field"] = {"a": 1, "b": 2}
    repo.root.roles[Root.type].unrecognized_fields["another-field"] = "value"
    repo.bump_root_by_one()

    # client should accept new root: The signed content contains the unknown fields
    assert client.refresh(init_data) == 0
    assert client.version(Root.type) == 2
