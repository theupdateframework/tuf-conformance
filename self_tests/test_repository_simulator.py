import unittest
from tuf_conformance.repository_simulator import RepositorySimulator
from tuf.api.metadata import (
    Timestamp, Snapshot, Root, Targets
)
from securesystemslib.signer import CryptoSigner

from tuf_conformance.metadata import (
    MetadataTest,
    RootTest,
    JSONDeserializerTest
)


class TestRepositorySimulator(unittest.TestCase):
    """Tests that ensure the repository behaves as intended"""

    def test_metadata_files_exist_after_creating_repository(self):
        repo = RepositorySimulator()
        self.assertTrue(repo._version_equals(Root.type, 1))
        self.assertTrue(repo._version_equals(Snapshot.type, 1))
        self.assertTrue(repo._version_equals(Targets.type, 1))
        self.assertTrue(repo._version_equals(Timestamp.type, 1))

    def test_add_key_to_role(self):
        repo = RepositorySimulator()
        signer = CryptoSigner.generate_ecdsa()
        root_md = MetadataTest.from_bytes(repo.md_root_json,
                                          JSONDeserializerTest())
        new_signed_root = RootTest.from_dict(root_md.signed.to_dict())
        new_signed_root.add_key(signer.public_key, Snapshot.type)
        new_signed_root.add_key(signer.public_key, Snapshot.type)
        new_signed_root.add_key(signer.public_key, Snapshot.type)
        root_md.signed = new_signed_root
        repo.md_root_json = root_md.to_bytes()

        repo_root = MetadataTest.from_bytes(repo.md_root_json,
                                            JSONDeserializerTest())
        self.assertEqual(repo_root.signed.version, 1)

        repo.bump_root_by_one()

        repo_root = MetadataTest.from_bytes(repo.md_root_json,
                                            JSONDeserializerTest())
        self.assertEqual(repo_root.signed.version, 2)
        self.assertEqual(len(repo_root.signed.roles["snapshot"].keyids), 4)

    def test_root_version_after_adding_same_keys(self):
        repo = RepositorySimulator()
        signer = CryptoSigner.generate_ecdsa()

        root_md = MetadataTest.from_bytes(repo.md_root_json,
                                          JSONDeserializerTest())
        new_signed_root = RootTest.from_dict(root_md.signed.to_dict())
        new_signed_root.add_key(signer.public_key, Snapshot.type)
        new_signed_root.add_key(signer.public_key, Snapshot.type)
        new_signed_root.add_key(signer.public_key, Snapshot.type)
        root_md.signed = new_signed_root
        repo.md_root_json = root_md.to_bytes()

        repo_root = MetadataTest.from_bytes(repo.md_root_json,
                                            JSONDeserializerTest())
        self.assertEqual(repo_root.signed.version, 1)
        repo.bump_root_by_one()
        repo_root = MetadataTest.from_bytes(repo.md_root_json,
                                            JSONDeserializerTest())
        self.assertEqual(repo_root.signed.version, 2)
        repo.bump_root_by_one()
        repo_root = MetadataTest.from_bytes(repo.md_root_json,
                                            JSONDeserializerTest())
        self.assertEqual(repo_root.signed.version, 3)

    def test_downgrade_snapshot(self):
        repo = RepositorySimulator()
        repo.update_snapshot()  # v2
        self.assertTrue(repo._version_equals(Snapshot.type, 2))
        repo.downgrade_snapshot()  # v1
        self.assertTrue(repo._version_equals(Snapshot.type, 1))

    def test_downgrade_timestamp(self):
        repo = RepositorySimulator()
        repo.update_timestamp()  # v2
        self.assertTrue(repo._version_equals(Timestamp.type, 2))
        repo.downgrade_timestamp()  # v1
        self.assertTrue(repo._version_equals(Timestamp.type, 1))


if __name__ == '__main__':
    unittest.main()
