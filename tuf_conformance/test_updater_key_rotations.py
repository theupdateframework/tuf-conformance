import os

from dataclasses import dataclass
from tuf_conformance.client_runner import ClientRunner
from tuf_conformance.repository_simulator import RepositorySimulator
from tuf_conformance.simulator_server import SimulatorServer
from typing import List, Optional, Type
from tuf.api.exceptions import UnsignedMetadataError
from securesystemslib.signer import CryptoSigner

from tuf.api.metadata import Root


@dataclass
class MdVersion:
    keys: List[int]
    threshold: int
    sigs: List[int]
    res: Optional[Type[Exception]] = None


def test_root_rotation(client: ClientRunner,
                       server: SimulatorServer) -> None:
    """Test client.refresh() with various sequences of root updates

        Each MdVersion in the list describes root keys and signatures of a
        remote root metadata version. As an example:
            MdVersion([1,2,3], 2, [1,2])
        defines a root that contains keys 1, 2 and 3 with threshold 2. The
        metadata is signed with keys 1 and 2.

        Assert that refresh() result is expected and that local root on disk is
        the expected one after all roots have been loaded from remote using the
        standard client update workflow.
        """

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
            MdVersion(keys=[2], threshold=1, sigs=[2, 3, 4], res=UnsignedMetadataError),
        ],
        "1-of-1-key-rotation-fail-not-signed-with-new-key": [
            MdVersion(keys=[1], threshold=1, sigs=[1]),
            MdVersion(keys=[2], threshold=1, sigs=[1, 3, 4], res=UnsignedMetadataError),
        ],
        "3-of-5-one-key-rotate-fails-not-signed-with-3-new-keys": [
            MdVersion(keys=[0, 1, 2, 3, 4], threshold=3, sigs=[0, 2, 4]),
            MdVersion(keys=[0, 1, 3, 4, 5], threshold=3, sigs=[0, 2, 4], res=UnsignedMetadataError),
        ],
        "3-of-5-one-key-rotate-fails-not-signed-with-3-old-keys": [
            MdVersion(keys=[0, 1, 2, 3, 4], threshold=3, sigs=[0, 2, 4]),
            MdVersion(keys=[0, 1, 3, 4, 5], threshold=3, sigs=[0, 4, 5], res=UnsignedMetadataError),
        ],
        "1-of-3-threshold-bump-to-2-of-3-fails-new-threshold-not-reached": [
            MdVersion(keys=[1, 2, 3], threshold=1, sigs=[1]),
            MdVersion(keys=[1, 2, 3], threshold=2, sigs=[2], res=UnsignedMetadataError),
        ],
        "2-of-3-threshold-decr-to-1-of-3-fails-old-threshold-not-eached": [
            MdVersion(keys=[1, 2, 3], threshold=2, sigs=[1, 2]),
            MdVersion(keys=[1, 2, 3], threshold=1, sigs=[1], res=UnsignedMetadataError),
        ],
    }

    signers = []
    for _ in range(10):
        signer = CryptoSigner.generate_ed25519()
        signers.append(signer)

    for tname, root_versions in root_rotation_cases.items():
        # initialize a simulator with repository content we need
        repo = RepositorySimulator()
        repo.signed_roots.clear()
        repo.root.version = 0
        server.repos[tname] = repo

        repo.signed_roots.clear()
        for rootver in root_versions:
            # clear root keys, signers
            repo.root.roles[Root.type].keyids.clear()
            repo.signers[Root.type].clear()

            repo.root.roles[Root.type].threshold = rootver.threshold
            for i in rootver.keys:
                repo.root.add_key(signers[i].public_key, Root.type)
            for i in rootver.sigs:
                repo.add_signer(Root.type, signers[i])
            repo.root.version += 1
            repo.publish_root()

        init_data = server.get_client_init_data(tname)
        assert client.init_client(init_data) == 0
        expected_error = root_versions[-1].res
        if expected_error is None:
            expected_local_root = repo.signed_roots[-1]
            assert client.refresh(init_data) == 0
        else:
            expected_local_root = repo.signed_roots[-2]
            assert client.refresh(init_data) == 1

        with open(os.path.join(client.metadata_dir, "root.json"), "rb") as f:
            assert f.read() == expected_local_root
