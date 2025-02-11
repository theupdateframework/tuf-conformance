import json
import os
from datetime import UTC, datetime, timedelta

import pytest
from securesystemslib.formats import encode_canonical
from securesystemslib.hash import digest
from tuf.api.metadata import Key, Metadata, MetaFile, Root, Snapshot, Targets, Timestamp

from tuf_conformance._internal.client_runner import ClientRunner
from tuf_conformance._internal.simulator_server import SimulatorServer


def recalculate_keyid(key: Key) -> None:
    """method to recalculate keyid: needed if key content is modified"""
    data: bytes = encode_canonical(key.to_dict()).encode()
    hasher = digest("sha256")
    hasher.update(data)
    key.keyid = hasher.hexdigest()


def test_basic_refresh_requests(client: ClientRunner, server: SimulatorServer) -> None:
    """Test basic client functionality.

    Run a refresh, verify requests made by the client
    """
    init_data, repo = server.new_test(client.test_name)
    assert client.init_client(init_data) == 0

    # Run client refresh, verify that expected requests were made
    assert client.refresh(init_data) == 0
    assert repo.metadata_statistics == [
        ("root", 2),
        ("timestamp", None),
        ("snapshot", 1),
        ("targets", 1),
    ]


def test_basic_refresh_trusted_data(
    client: ClientRunner, server: SimulatorServer
) -> None:
    """Test basic client functionality.

    Run a refresh, verify clients trusted metadata
    """
    init_data, repo = server.new_test(client.test_name)
    assert client.init_client(init_data) == 0

    # Run client refresh, verify that trusted metadata is as expected
    assert client.refresh(init_data) == 0

    for role in [Root.type, Timestamp.type, Snapshot.type, Targets.type]:
        client.assert_metadata(role, repo.fetch_metadata(role))


def test_implicit_refresh(client: ClientRunner, server: SimulatorServer) -> None:
    """Test that client refreshes metadata before downloading artifacts.

    Run download immediately after initialization: Expect download to fail
    (as targetpath does not exist) but expect metadata to get updated.
    """

    init_data, repo = server.new_test(client.test_name)
    assert client.init_client(init_data) == 0

    # Run download, verify that requests and trusted metadata are as expected
    assert client.download_target(init_data, "nonexistent artifact") == 1

    assert repo.metadata_statistics == [
        ("root", 2),
        ("timestamp", None),
        ("snapshot", 1),
        ("targets", 1),
    ]
    for role in [Root.type, Timestamp.type, Snapshot.type, Targets.type]:
        client.assert_metadata(role, repo.fetch_metadata(role))


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
    ("timestamp", [("root", 2)]),
    ("snapshot", [("root", 2), ("timestamp", 2)]),
    ("targets", [("root", 2), ("snapshot", 2), ("timestamp", 2)]),
]
unsigned_ids = [case[0] for case in unsigned_cases]


@pytest.mark.parametrize("role, trusted", unsigned_cases, ids=unsigned_ids)
def test_unsigned_metadata(
    client: ClientRunner,
    server: SimulatorServer,
    role: str,
    trusted: list[tuple[str, int]],
) -> None:
    """Test refresh when a top-level role is incorrectly signed.

    Serve client metadata that is not properly signed.
    Expect the client to refuse that roles metadata but accept the roles
    updated before that in the client workflow.
    """

    init_data, repo = server.new_test(client.test_name)

    # remove signing key for role, increase version
    repo.signers[role].popitem()
    repo.publish([Root.type, Targets.type, Snapshot.type, Timestamp.type])

    assert client.init_client(init_data) == 0

    # Verify that refresh fails and that improperly signed role is not updated
    assert client.refresh(init_data) == 1
    assert client.trusted_roles() == trusted


# tuples of
#  * rolename that should have a version mismatch
#  * expected trusted metadata versions after refresh fails
mismatch_cases = [
    ("root", [("root", 1)]),
    ("snapshot", [("root", 2), ("timestamp", 2)]),
    ("targets", [("root", 2), ("snapshot", 2), ("timestamp", 2)]),
]
mismatch_ids = [case[0] for case in mismatch_cases]


@pytest.mark.parametrize("role, trusted", mismatch_cases, ids=mismatch_ids)
def test_url_and_metadata_version_mismatch(
    client: ClientRunner,
    server: SimulatorServer,
    role: str,
    trusted: list[tuple[str, int]],
) -> None:
    """Publish metadata with a mismatch between the version in the metadata and the
    published URL. Expect client to refuse the mismatching metadata update
    """

    init_data, repo = server.new_test(client.test_name)

    # After publish roles metadata contains "version: 3" but the URL is going to be
    # /2.<ROLE>.json. Use `verify_version=False` to silence warning about this
    repo.mds[role].signed.version += 1
    repo.publish(
        [Root.type, Targets.type, Snapshot.type, Timestamp.type], verify_version=False
    )

    assert client.init_client(init_data) == 0

    # Expect client to not accept version mismatch
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

    # Change timestamp v1: client should not use the new one if it already has a v1
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


def test_metadata_bytes_match(client: ClientRunner, server: SimulatorServer) -> None:
    """Test that client stores the specific serialization from repository.

    This is not strictly stated in the spec buy clients should not store their own
    serialization of metadata on disk (as this break hash comparisons of local
    metadata), they should store the bytes they receive from repository
    """
    init_data, repo = server.new_test(client.test_name)
    assert client.init_client(init_data) == 0

    # Make sure the serialization is very unique
    data = repo.signed_mds[Timestamp.type][-1] + b" "
    repo.signed_mds[Timestamp.type][-1] = data

    assert client.refresh(init_data) == 0

    # Assert that client stored the timestamp metadata as is
    client_timestamp = os.path.join(client.metadata_dir, "timestamp.json")
    with open(client_timestamp, "rb") as f:
        assert f.read() == data


def test_custom_fields(client: ClientRunner, server: SimulatorServer) -> None:
    """Verify that client copes with unexpected fields in metadata.

    spec section 4: "Implementers who encounter undefined attribute-value pairs
    in the format must include the data when calculating hashes or verifying
    signatures."""

    init_data, repo = server.new_test(client.test_name)

    assert client.init_client(init_data) == 0
    assert client.refresh(init_data) == 0

    signer = repo.new_signer()
    signer.public_key.unrecognized_fields["extra-field"] = {"a": 1, "b": 2}
    recalculate_keyid(signer.public_key)

    # Add some custom fields into root metadata, make a new root version
    repo.root.unrecognized_fields["custom-field"] = "value"
    repo.add_key(Root.type, signer=signer)
    repo.root.roles[Root.type].unrecognized_fields["another-field"] = "value"
    repo.publish([Root.type])

    # client should accept new root: The signed content contains the unknown fields
    assert client.refresh(init_data) == 0
    assert client.version(Root.type) == 2


def test_deprecated_keyid_hash_algorithms(
    client: ClientRunner, server: SimulatorServer
) -> None:
    """This test sets a misleading "keyid_hash_algorithms" value: this field is not
    a part of the TUF spec and should not affect clients.
    """
    init_data, repo = server.new_test(client.test_name)
    assert client.init_client(init_data) == 0

    # remove current snapshot key
    old_keyid = repo.root.roles[Snapshot.type].keyids[0]
    repo.root.revoke_key(old_keyid, Snapshot.type)
    del repo.signers[Snapshot.type][old_keyid]

    # Use a key with the custom field
    signer = repo.new_signer()
    signer.public_key.unrecognized_fields = {"keyid_hash_algorithms": "md5"}
    recalculate_keyid(signer.public_key)
    repo.add_key(Snapshot.type, signer=signer)

    repo.publish([Root.type, Snapshot.type, Timestamp.type])  # v2

    # All metadata should update; even though "keyid_hash_algorithms"
    # value is "wrong", it is not a part of the TUF spec.
    assert client.refresh(init_data) == 0
    assert client.version(Root.type) == 2
    assert client.version(Snapshot.type) == 2


def test_snapshot_404(client: ClientRunner, server: SimulatorServer) -> None:
    """Verify that missing snapshot version is handled correctly"""
    init_data, repo = server.new_test(client.test_name)

    assert client.init_client(init_data) == 0
    assert client.refresh(init_data) == 0

    # Bump snapshot version in timestamp.snapshot_meta without publishing new snapshot
    repo.timestamp.snapshot_meta.version += 1
    repo.publish([Timestamp.type])

    # Client should not consider the repository valid because snapshot v2 was not found,
    # but should update timestamp
    assert client.refresh(init_data) == 1
    assert repo.metadata_statistics[-1] == (Snapshot.type, 2)
    assert client.trusted_roles() == [
        (Root.type, 1),
        (Snapshot.type, 1),
        (Targets.type, 1),
        (Timestamp.type, 2),
    ]


def test_targets_404(client: ClientRunner, server: SimulatorServer) -> None:
    """Verify that missing targets version is handled correctly"""
    init_data, repo = server.new_test(client.test_name)

    assert client.init_client(init_data) == 0
    assert client.refresh(init_data) == 0

    # Bump targets version in snapshot.meta without publishing new targets
    repo.snapshot.meta["targets.json"].version += 1
    repo.publish([Snapshot.type, Timestamp.type])

    # Client should not consider the repository valid because targets v2 was not found,
    # but should update timestamp and snapshot
    assert client.refresh(init_data) == 1
    assert repo.metadata_statistics[-1] == (Targets.type, 2)
    assert client.trusted_roles() == [
        (Root.type, 1),
        (Snapshot.type, 2),
        (Targets.type, 1),
        (Timestamp.type, 2),
    ]


def test_timestamp_404(client: ClientRunner, server: SimulatorServer) -> None:
    """Verify that missing timestamp is handled correctly"""
    init_data, repo = server.new_test(client.test_name)

    assert client.init_client(init_data) == 0
    assert client.refresh(init_data) == 0

    # Remove all timestamp versions so client gets a 404
    del repo.signed_mds[Timestamp.type]

    # Client should not consider the repository valid because timestamp was not found
    assert client.refresh(init_data) == 1
    assert repo.metadata_statistics[-1] == (Timestamp.type, None)


def test_incorrect_metadata_type(client: ClientRunner, server: SimulatorServer) -> None:
    """Verify that client checks metadata type

    Test is a bit complicated since it ensures that that the metadata is otherwise
    completely valid and correctly signed, only the type is incorrect
    """
    init_data, repo = server.new_test(client.test_name)
    assert client.init_client(init_data) == 0

    # Create a version of snapshot that looks a lot like a timestamp:
    # 1. Make sure snapshot gets signed by timestamp key as well
    signer = next(iter(repo.signers[Timestamp.type].values()))
    repo.add_key(Snapshot.type, signer=signer)

    # 2. Make sure snapshot content is valid as timestamp
    repo.snapshot.meta = {"snapshot.json": MetaFile(1)}

    # Publish snapshot v2 (to get it signed), but then make sure it's
    # actually published as a timestamp v2
    repo.publish([Root.type, Snapshot.type])
    repo.signed_mds[Timestamp.type].append(repo.signed_mds[Snapshot.type].pop())

    # Client should refuse timestamp that has incorrect type field
    assert client.refresh(init_data) == 1
    assert client.trusted_roles() == [(Root.type, 2)]


def test_faketime(client: ClientRunner, server: SimulatorServer) -> None:
    """Ensures that client supports the faketime setup in this test suite"""
    init_data, repo = server.new_test(client.test_name)

    assert client.init_client(init_data) == 0

    # root v2 expires in 7 days
    now = datetime.now(UTC)
    repo.root.expires = now + timedelta(days=7)
    repo.publish([Root.type])

    # Refresh
    assert client.refresh(init_data) == 0

    # Mock time so that root has expired. If client unexpectedly succeeds here,
    # it likely does not work with faketime
    assert client.refresh(init_data, now + timedelta(days=8)) == 1
