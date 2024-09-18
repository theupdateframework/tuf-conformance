# Test runner
import json
import os

import pytest
from tuf.api.metadata import Metadata, Root, Snapshot, Targets, Timestamp

from tuf_conformance.client_runner import ClientRunner
from tuf_conformance.simulator_server import SimulatorServer


def test_basic_init_and_refresh(client: ClientRunner, server: SimulatorServer) -> None:
    """Test basic client functionality.

    Run a refresh, verify client trusted metadata and requests made by the client
    """
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
    """Test that client refreshes metadata before downloading artifacts.

    Run download immediately after initialization: Expect download to fail
    (as targetpath does not exist) but expect metadata to get updated.
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
    """Test client when initial trusted root is invalid

    Initialize client with invalid root. Expect refresh to fail and
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
    """Test client when initial trusted root is not signed correctly

    Initialize client with root that is not correctly signed. Expect refresh to fail
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


# tuples of
#  * rolename that will be improperly signed
#  * expected trusted metadata versions after refresh fails
unsigned_cases = [
    ("root", [("root", 1)]),
    ("timestamp", [("root", 1)]),
    ("snapshot", [("root", 1), ("timestamp", 1)]),
    ("targets", [("root", 1), ("snapshot", 1), ("timestamp", 1)]),
]
unsigned_ids = [case[0] for case in unsigned_cases]


@pytest.mark.parametrize("role, trusted", unsigned_cases, ids=unsigned_ids)
def test_unsigned_metadata(
    client: ClientRunner, server: SimulatorServer, role: str, trusted: tuple[str, int]
) -> None:
    """Test refresh when a top-level role is incorrectly signed.

    Serve client metadata that is not properly signed.
    Expect the refresh to succeed until that point, but not continue from that point.
    """

    init_data, repo = server.new_test(client.test_name)
    # Removed published roles:
    del repo.signed_mds[Targets.type]
    del repo.signed_mds[Snapshot.type]
    del repo.signed_mds[Timestamp.type]

    # remove signing key for role, increase version
    repo.signers[role].popitem()
    repo.mds[role].signed.version += 1
    if role == "root":
        repo.publish([Root.type])
    else:
        repo.publish([Targets.type, Snapshot.type, Timestamp.type])

    assert client.init_client(init_data) == 0

    # Verify that refresh fails and that current trusted metadata is as expected
    assert client.refresh(init_data) == 1
    assert client.trusted_roles() == trusted


def test_timestamp_content_changes(
    client: ClientRunner, server: SimulatorServer
) -> None:
    """Repository modifies timestamp content without bumping a version. Expect client
    to keep using the version it already has.
    """
    # https://github.com/theupdateframework/go-tuf/blob/f1d8916f08e4dd25f91e40139137edb8bf0498f3/metadata/updater/updater_top_level_update_test.go#L1058
    init_data, repo = server.new_test(client.test_name)

    assert client.init_client(init_data) == 0
    assert client.refresh(init_data) == 0

    # Change timestamp v1: client should not download a new one if it has v1 already
    repo.timestamp.snapshot_meta.version = 100
    del repo.signed_mds[Timestamp.type]
    repo.publish([Timestamp.type])  # v1

    # client should not persist new timestamp and should not download snapshot v100
    assert client.refresh(init_data) == 0
    assert repo.metadata_statistics[-1] == (Timestamp.type, None)

    timestamp_path = os.path.join(client.metadata_dir, "timestamp.json")
    timestamp: Metadata[Timestamp] = Metadata.from_file(timestamp_path)
    assert timestamp.signed.snapshot_meta.version == 1


def test_basic_metadata_hash_support(
    client: ClientRunner, server: SimulatorServer
) -> None:
    """Verify that clients supports hashes for metadata"""
    init_data, repo = server.new_test(client.test_name)

    # Construct repository with hashes in timestamp/snapshot
    repo.compute_metafile_hashes_length = True
    repo.publish([Targets.type, Snapshot.type, Timestamp.type])  # v2, v2, v2

    assert client.init_client(init_data) == 0
    # Verify client accepts correct hashes
    assert client.refresh(init_data) == 0

    # Modify targets metadata, set hash in snapshot to wrong value
    repo.publish([Targets.type])  # v3
    assert repo.snapshot.meta["targets.json"].hashes
    repo.snapshot.meta["targets.json"].hashes["sha256"] = (
        "46419349341cfb2d95f6ae3d4cd5c3d3dd7f4673985dad42a45130be5e0531a0"
    )
    repo.publish([Snapshot.type, Timestamp.type])  # v3

    # Verify client refuses targets v3 that does not match hashes
    assert client.refresh(init_data) == 1
    assert client.version(Snapshot.type) == 3
    assert client.version(Targets.type) == 2


def test_new_targets_version_mismatch(
    client: ClientRunner, server: SimulatorServer
) -> None:
    """Create new targets version. Check that client does not
    download it as the version is not in snapshot.meta
    """
    init_data, repo = server.new_test(client.test_name)

    assert client.init_client(init_data) == 0
    assert client.refresh(init_data) == 0

    repo.publish([Targets.type])

    assert client.refresh(init_data) == 0
    # Check that the client still has the correct targets version
    assert client.version(Targets.type) == 1
    assert repo.metadata_statistics[-1] == (Timestamp.type, None)


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
    repo.publish([Root.type])

    # client should accept new root: The signed content contains the unknown fields
    assert client.refresh(init_data) == 0
    assert client.version(Root.type) == 2
