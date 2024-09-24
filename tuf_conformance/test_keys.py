import pytest
from tuf.api.metadata import Metadata, Root, Snapshot, Targets, Timestamp

from tuf_conformance.client_runner import ClientRunner
from tuf_conformance.simulator_server import SimulatorServer


def test_snapshot_does_not_meet_threshold(
    client: ClientRunner, server: SimulatorServer
) -> None:
    """In this test snapshot v3 is not signed by threshold of signatures. The client
    should therefore not refresh the snapshot metadata from the repo.

    Specifically, the goal is to bring the repository into a state where:

    1. repo.root.roles.snapshot.keyids has 3 keyids
    2: repo.root.roles.snapshot.threshold is 3
    3: repo.snapshot.signatures contains signatures from two of the keys

    The test ensures that clients do not update snapshot in this scenario.
    """
    init_data, repo = server.new_test(client.test_name)

    # Set snapshot threshold to 3, add keys to snapshot role (snapshot now has 3 keys)
    repo.root.roles[Snapshot.type].threshold = 3
    for _ in range(2):
        repo.add_key(Snapshot.type)
    repo.publish([Root.type, Targets.type, Snapshot.type, Timestamp.type])  # v2

    assert client.init_client(init_data) == 0
    assert client.refresh(init_data) == 0

    # Remove a signer from snapshot: amount of signatures will be 2, below threshold
    repo.signers[Snapshot.type].popitem()
    repo.publish([Targets.type, Snapshot.type, Timestamp.type])  # v3

    # snapshot v3 does not meet the threshold anymore:
    assert client.refresh(init_data) == 1
    assert client.version(Snapshot.type) != 3


def test_deprecated_keyid_hash_algorithms(
    client: ClientRunner, server: SimulatorServer
) -> None:
    """This test sets a misleading "keyid_hash_algorithms" value: this field is not
    a part of the TUF spec and should not affect clients.
    """
    init_data, repo = server.new_test(client.test_name)
    assert client.init_client(init_data) == 0

    # Set snapshot keys "keyid_hash_algorithms" to an incorrect algorithm.
    valid_key = repo.root.roles[Snapshot.type].keyids[0]
    repo.root.keys[valid_key].unrecognized_fields = {"keyid_hash_algorithms": "md5"}
    repo.publish([Root.type])  # v2

    # All metadata should update; even though "keyid_hash_algorithms"
    # is wrong, it is not a part of the TUF spec.
    assert client.refresh(init_data) == 0
    assert client.version(Root.type) == 2
    assert client.version(Snapshot.type) == 1


def test_snapshot_has_too_few_keys(
    client: ClientRunner, server: SimulatorServer
) -> None:
    """In this test snapshot does not have enough keys: it is impossible
    to have a threshold of signatures."""
    # Test basic failure to reach signature threshold
    init_data, repo = server.new_test(client.test_name)
    assert client.init_client(init_data) == 0

    # Add 4 Snapshot keys so that there are 5 in total.
    for _ in range(4):
        repo.add_key(Snapshot.type)
    assert len(repo.root.roles["snapshot"].keyids) == 5

    # Set higher threshold than we have keys such that the
    # client should not successfully update.
    repo.root.roles[Snapshot.type].threshold = 6
    repo.publish([Root.type, Snapshot.type, Timestamp.type])

    # Ensure that client does not update because it does
    # not have enough keys.
    assert client.refresh(init_data) == 1
    assert client.version(Root.type) == 2
    assert client.version(Snapshot.type) != 2


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
    repo.publish([Root.type, Snapshot.type, Timestamp.type])

    # This should fail for one of two reasons:
    # 1. client does not accept root v2 metadata that contains duplicate keyids or
    # 2. client did accept root v2 but then snapshot threshold is not reached
    assert client.refresh(init_data) == 1

    # client should not have accepted snapshot
    assert client.version(Snapshot.type) is None


# keytype, scheme and an example signature from this type of key
standard_keytypes = [
    (
        "rsa",
        "rsassa-pss-sha256",
        "b123346abdead7069ab07eb3cae8ba6323222fb448b4903061f481066b0393dde6268eba7696b73b20586fc2cb3e3f68317863a8a9ee85824cfffdc70762821fa8afbcb7a5fd5c520b77f95b8cc6df4a52b3b7896c388b5b7fbed972337a15089e70f2313bbd511ea0d694356d8837e4b1515bb79a16a31e22e9ab15be5b26ad39abcf45311e025d76d372d44f9e51474d27b71c23f63e24c60544a9f9dbf073f52812d68b5d26b230ec711ce03d9ae765c62eb1f33269437650132318a356224bbdc7de27c88d7552db1d14f4f4c52165feaebd5735e9928cd9703ced5271abb29415eeabf03067dbae3d71bc24bd5b9d2a24af3f92eafa85e933ed76284c8cf1a466c1314583d15ec12b00b06836305dca3c84f00468bbc8e4de8f19c2184200f46458a24d94c4abfb090df3d09b79ecfc384d4041e3b5687d5b5bc97d0888ea27641b3862b64d3c892ef352e68edfe952c89e9c4e957185647133e6aa58141ff80c03de5c3aa4cf9b5da6444bceec43c08a433abe11b25d3ef6aab8d83485",
    ),
    (
        "ecdsa",
        "ecdsa-sha2-nistp256",
        "3046022100fa1f62d38e0f5c565fa23e5d230086258427d87f024c146071966deefde55468022100b3347b4bd9ba6701ca6cef949d04b5742394b9f8c4417933e5d4fa76c3ca3a98",
    ),
    (
        "ed25519",
        "ed25519",
        "b61589620c287e23a00abf0e653421010a0ad33869e5a096d604e08d7b4f8eb9c58ebb8a02124576be776f86ab5a3b05dbb6f27cc47f4b144f32ba4012d4b302",
    ),
]

ids = [f"{keytype}/{scheme}" for keytype, scheme, _ in standard_keytypes]


@pytest.mark.parametrize("keytype, scheme, bad_sig", standard_keytypes, ids=ids)
def test_keytype_and_scheme(
    client: ClientRunner,
    server: SimulatorServer,
    keytype: str,
    scheme: str,
    bad_sig: str,
) -> None:
    """Test that client supports keytypes referenced in the TUF specification"""
    init_data, repo = server.new_test(client.test_name)
    assert client.init_client(init_data) == 0
    # Add a new root signer with given keytype.
    # Increase root threshold so the new key is required
    signer = repo.new_signer(keytype, scheme)
    repo.add_key(Root.type, signer=signer)
    repo.root.roles[Root.type].threshold += 1
    repo.publish([Root.type])

    assert client.refresh(init_data) == 0
    assert client.version(Root.type) == 2

    # Create new root version. Replace the correct signature with one that looks
    # reasonable for the keytype but is incorrect. Expect client to refuse the new root.
    repo.publish([Root.type])
    root_md = Metadata.from_bytes(repo.signed_mds[Root.type].pop())
    root_md.signatures[signer.public_key.keyid].signature = bad_sig
    repo.signed_mds[Root.type].append(root_md.to_bytes())

    assert client.refresh(init_data) == 1
    assert client.version(Root.type) == 2
