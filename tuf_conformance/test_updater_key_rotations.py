from dataclasses import dataclass

import pytest
from tuf.api.metadata import Root, Snapshot, Targets, Timestamp

from tuf_conformance.client_runner import ClientRunner
from tuf_conformance.simulator_server import SimulatorServer


@dataclass
class MdVersion:
    keys: list[int]
    threshold: int
    sigs: list[int]
    res: bool = True  # expected client success/failure


root_rotation_cases = {
    "1-of-1-key-rotation": [
        MdVersion(keys=[1], threshold=1, sigs=[1]),
        MdVersion(keys=[2], threshold=1, sigs=[2, 1]),
        MdVersion(keys=[2], threshold=1, sigs=[2]),
    ],
    "1-of-1-key-rotation-unused-signatures": [
        MdVersion(keys=[1], threshold=1, sigs=[3, 1, 4]),
        MdVersion(keys=[2], threshold=1, sigs=[3, 2, 1, 4]),
        MdVersion(keys=[2], threshold=1, sigs=[3, 2, 4]),
    ],
    "3-of-5-sign-with-different-keycombos": [
        MdVersion(keys=[0, 1, 2, 3, 4], threshold=3, sigs=[0, 2, 4]),
        MdVersion(keys=[0, 1, 2, 3, 4], threshold=3, sigs=[0, 4, 1]),
        MdVersion(keys=[0, 1, 2, 3, 4], threshold=3, sigs=[0, 1, 3]),
        MdVersion(keys=[0, 1, 2, 3, 4], threshold=3, sigs=[0, 1, 3]),
    ],
    "3-of-5-one-key-rotated": [
        MdVersion(keys=[0, 1, 2, 3, 4], threshold=3, sigs=[0, 2, 4]),
        MdVersion(keys=[0, 1, 3, 4, 5], threshold=3, sigs=[0, 4, 1]),
    ],
    "3-of-5-one-key-rotated-with-intermediate-step": [
        MdVersion(keys=[0, 1, 2, 3, 4], threshold=3, sigs=[0, 2, 4]),
        MdVersion(keys=[0, 1, 3, 4, 5], threshold=3, sigs=[0, 2, 4, 5]),
        MdVersion(keys=[0, 1, 3, 4, 5], threshold=3, sigs=[0, 4, 5]),
    ],
    "3-of-5-all-keys-rotated-with-intermediate-step": [
        MdVersion(keys=[0, 1, 2, 3, 4], threshold=3, sigs=[0, 2, 4]),
        MdVersion(keys=[5, 6, 7, 8, 9], threshold=3, sigs=[0, 2, 4, 5, 6, 7]),
        MdVersion(keys=[5, 6, 7, 8, 9], threshold=3, sigs=[5, 6, 7]),
    ],
    "1-of-3-threshold-increase-to-2-of-3": [
        MdVersion(keys=[1, 2, 3], threshold=1, sigs=[1]),
        MdVersion(keys=[1, 2, 3], threshold=2, sigs=[1, 2]),
    ],
    "2-of-3-threshold-decrease-to-1-of-3": [
        MdVersion(keys=[1, 2, 3], threshold=2, sigs=[1, 2]),
        MdVersion(keys=[1, 2, 3], threshold=1, sigs=[1, 2]),
        MdVersion(keys=[1, 2, 3], threshold=1, sigs=[1]),
    ],
    "1-of-2-threshold-increase-to-2-of-2": [
        MdVersion(keys=[1], threshold=1, sigs=[1]),
        MdVersion(keys=[1, 2], threshold=2, sigs=[1, 2]),
    ],
    "1-of-1-key-rotation-fail-not-signed-with-old-key": [
        MdVersion(keys=[1], threshold=1, sigs=[1]),
        MdVersion(keys=[2], threshold=1, sigs=[2, 3, 4], res=False),
    ],
    "1-of-1-key-rotation-fail-not-signed-with-new-key": [
        MdVersion(keys=[1], threshold=1, sigs=[1]),
        MdVersion(keys=[2], threshold=1, sigs=[1, 3, 4], res=False),
    ],
    "3-of-5-one-key-rotate-fails-not-signed-with-3-new-keys": [
        MdVersion(keys=[0, 1, 2, 3, 4], threshold=3, sigs=[0, 2, 4]),
        MdVersion(keys=[0, 1, 3, 4, 5], threshold=3, sigs=[0, 2, 4], res=False),
    ],
    "3-of-5-one-key-rotate-fails-not-signed-with-3-old-keys": [
        MdVersion(keys=[0, 1, 2, 3, 4], threshold=3, sigs=[0, 2, 4]),
        MdVersion(keys=[0, 1, 3, 4, 5], threshold=3, sigs=[0, 4, 5], res=False),
    ],
    "1-of-3-threshold-bump-to-2-of-3-fails-new-threshold-not-reached": [
        MdVersion(keys=[1, 2, 3], threshold=1, sigs=[1]),
        MdVersion(keys=[1, 2, 3], threshold=2, sigs=[2], res=False),
    ],
    "2-of-3-threshold-decr-to-1-of-3-fails-old-threshold-not-eached": [
        MdVersion(keys=[1, 2, 3], threshold=2, sigs=[1, 2]),
        MdVersion(keys=[1, 2, 3], threshold=1, sigs=[1], res=False),
    ],
}

non_root_rotation_cases: dict[str, MdVersion] = {
    "1-of-1-key-rotation": MdVersion(keys=[2], threshold=1, sigs=[2]),
    "1-of-1-key-rotation-unused-signatures": MdVersion(
        keys=[1], threshold=1, sigs=[3, 1, 4]
    ),
    "1-of-1-key-rotation-fail-not-signed-with-new-key": MdVersion(
        keys=[2], threshold=1, sigs=[1, 3, 4], res=False
    ),
    "3-of-5-one-key-signature-wrong-not-signed-with-3-expected-keys": MdVersion(
        keys=[0, 1, 3, 4, 5], threshold=3, sigs=[0, 2, 4], res=False
    ),
    "2-of-5-one-key-signature-mising-threshold-not-reached": MdVersion(
        keys=[0, 1, 3, 4, 5], threshold=3, sigs=[0, 4], res=False
    ),
    "3-of-5-sign-first-combo": MdVersion(
        keys=[0, 1, 2, 3, 4], threshold=3, sigs=[0, 2, 4]
    ),
    "3-of-5-sign-second-combo": MdVersion(
        keys=[0, 1, 2, 3, 4], threshold=3, sigs=[0, 4, 1]
    ),
    "3-of-5-sign-third-combo": MdVersion(
        keys=[0, 1, 2, 3, 4], threshold=3, sigs=[0, 1, 3]
    ),
    "3-of-5-sign-fourth-combo": MdVersion(
        keys=[0, 1, 2, 3, 4], threshold=3, sigs=[1, 2, 3]
    ),
    "3-of-5-sign-fifth-combo": MdVersion(
        keys=[0, 1, 2, 3, 4], threshold=3, sigs=[2, 3, 4]
    ),
}

rotation_ids = root_rotation_cases.keys()
rotation_cases = root_rotation_cases.values()

non_rotation_ids = non_root_rotation_cases.keys()
non_rotation_cases = non_root_rotation_cases.values()


@pytest.mark.parametrize("root_versions", rotation_cases, ids=rotation_ids)
def test_root_rotation(
    client: ClientRunner, server: SimulatorServer, root_versions: list[MdVersion]
) -> None:
    """Test client refresh with various sequences of root updates

    Each MdVersion in root_versions describes root keys and signatures of a
    remote root metadata version. As an example:
        MdVersion([1,2,3], 2, [1,2])
    defines a root that contains keys 1, 2 and 3 with threshold 2. The
    metadata is signed with keys 1 and 2.

    Assert that refresh result is expected and that local root on disk is
    the expected one after all roots have been loaded from remote using the
    standard client update workflow.
    """

    # initialize a simulator with repository content we need
    init_data, repo = server.new_test(client.test_name)
    del repo.signed_mds[Root.type]
    signers = [repo.new_signer() for _ in range(10)]

    for rootver in root_versions:
        # clear root keys, signers
        repo.root.roles[Root.type].keyids.clear()
        repo.signers[Root.type].clear()

        repo.root.roles[Root.type].threshold = rootver.threshold
        for i in rootver.keys:
            repo.root.add_key(signers[i].public_key, Root.type)
        for i in rootver.sigs:
            repo.add_signer(Root.type, signers[i])
        repo.publish([Root.type])
    repo.publish([Targets.type, Snapshot.type, Timestamp.type])

    # Make sure our initial root is the v1 we just created
    init_data.trusted_root = repo.fetch_metadata("root", 1)

    # Run client against the repository, assert expected result
    assert client.init_client(init_data) == 0
    expected_result = root_versions[-1].res
    if expected_result:
        expected_local_root = repo.signed_mds[Root.type][-1]
        assert client.refresh(init_data) == 0
    else:
        expected_local_root = repo.signed_mds[Root.type][-2]
        assert client.refresh(init_data) == 1

    # make sure trusted metadata matches the repository metadata
    client.assert_metadata(Root.type, expected_local_root)


@pytest.mark.parametrize("md_version", non_rotation_cases, ids=non_rotation_ids)
def test_non_root_rotations(
    client: ClientRunner, server: SimulatorServer, md_version: MdVersion
) -> None:
    """Test Updater.refresh() with various sequences of metadata updates

    Each MdVersion in the list describes metadata keys and signatures
    of a remote metadata version. As an example:
        MdVersion([1,2,3], 2, [1,2])
    defines a metadata that contains keys 1, 2 and 3 with threshold 2. The
    metadata is signed with keys 1 and 2.

    Assert that refresh() result is expected and that local metadata on disk
    is the expected one after all roots have been loaded from remote using
    the standard client update workflow.
    """

    # initialize a simulator with repository content we need
    init_data, repo = server.new_test(client.test_name)
    assert client.init_client(init_data) == 0
    signers = [repo.new_signer() for _ in range(10)]

    for role in ["timestamp", "snapshot", "targets"]:
        # clear role keys, signers
        repo.root.roles[role].keyids.clear()
        repo.signers[role].clear()

        repo.root.roles[role].threshold = md_version.threshold
        for i in md_version.keys:
            repo.root.add_key(signers[i].public_key, role)

        for i in md_version.sigs:
            repo.add_signer(role, signers[i])

        repo.publish([Root.type, Targets.type, Snapshot.type, Timestamp.type])

        # run client workflow, assert success/failure
        expected_result = md_version.res
        if expected_result:
            assert client.refresh(init_data) == 0
            # make sure trusted metadata matches the repository metadata
            client.assert_metadata(role, repo.fetch_metadata(role))
        else:
            # failure expected
            assert client.refresh(init_data) == 1
