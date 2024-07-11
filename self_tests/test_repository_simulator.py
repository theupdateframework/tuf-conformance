import json
import unittest
from tuf_conformance.repository_simulator import RepositorySimulator
from tuf.api.metadata import (
    Timestamp, Snapshot, Root, Targets, Metadata
)
from tuf_conformance.utils import meta_dict_to_bytes
from securesystemslib.signer import CryptoSigner, Signer

from tuf.api.metadata import (
    TOP_LEVEL_ROLE_NAMES
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
        # Add signature to Snapshot
        repo.add_key_to_role(Snapshot.type)
        repo.add_key_to_role(Snapshot.type)
        repo.add_key_to_role(Snapshot.type)

        self.assertTrue(repo._version_equals(Root.type, 1))

        repo.bump_root_by_one()

        repo_root = repo.load_metadata(Root.type)
        self.assertTrue(repo._version_equals(Root.type, 2))
        self.assertEqual(len(repo_root.signed.roles["snapshot"].keyids), 4)

    def test_add_one_role_key_n_times_to_root(self):
        repo = RepositorySimulator()
        # Add signature to Snapshot
        repo.add_one_role_key_n_times_to_root(Snapshot.type, 9)

        repo.bump_root_by_one()

        repo_root = json.loads(repo.load_metadata_bytes(Root.type))
        root_key_ids = repo_root["signed"]["roles"]["snapshot"]["keyids"]
        self.assertEqual(len(root_key_ids), 10)

        # the last 9 ids should be identical
        self.assertEqual(root_key_ids[1], root_key_ids[2])
        self.assertEqual(root_key_ids[1], root_key_ids[3])
        self.assertEqual(root_key_ids[1], root_key_ids[4])
        self.assertEqual(root_key_ids[1], root_key_ids[5])
        self.assertEqual(root_key_ids[1], root_key_ids[6])
        self.assertEqual(root_key_ids[1], root_key_ids[7])
        self.assertEqual(root_key_ids[1], root_key_ids[8])
        self.assertEqual(root_key_ids[1], root_key_ids[9])

    def test_serialize_after_signing(self):
        repo = RepositorySimulator()
        repo.add_one_role_key_n_times_to_root(Snapshot.type, 1)
        repo_root = json.loads(repo.load_metadata_bytes(Root.type))
        root_key_ids = repo_root["signed"]["roles"]["snapshot"]["keyids"]
        self.assertEqual(len(root_key_ids), 2)

        repo.bump_root_by_one()

        root_md = Metadata.from_bytes(repo.md_root_json)
        serialized_root_md = meta_dict_to_bytes(root_md.to_dict())
        self.assertEqual(repo.md_root_json, serialized_root_md)

        snapshot_md = Metadata.from_bytes(repo.md_snapshot_json)
        serialized_snapshot_md = meta_dict_to_bytes(snapshot_md.to_dict())
        self.assertEqual(repo.md_snapshot_json, serialized_snapshot_md)

        # Test that we can add more keys
        repo.add_one_role_key_n_times_to_root(Snapshot.type, 2)
        repo.bump_root_by_one()
        repo_root = json.loads(repo.load_metadata_bytes(Root.type))
        root_key_ids = repo_root["signed"]["roles"]["snapshot"]["keyids"]
        self.assertEqual(len(root_key_ids), 4)

    def test_root_version_after_adding_same_keys(self):
        repo = RepositorySimulator()
        repo.add_one_role_key_n_times_to_root(Snapshot.type, 3)
        repo_root = json.loads(repo.load_metadata_bytes(Root.type))
        self.assertEqual(repo_root["signed"]["version"], 1)
        repo.bump_root_by_one()
        repo_root = json.loads(repo.load_metadata_bytes(Root.type))
        self.assertEqual(repo_root["signed"]["version"], 2)
        repo.bump_root_by_one()

    def test_add_key_implementation(self):
        """Tests the repositorys add_key implementation.
        Specifically that the 'signed' bytes are equal between
        our own implementation of add_key and the 'correct' one.
        The test imitates the repositorys initialization method
        with fresh but also signs the metadata using the Metadata
        class."""
        repo = RepositorySimulator()

        repo.md_targets = Metadata(Targets(expires=repo.safe_expiry))
        repo.md_snapshot = Metadata(Snapshot(expires=repo.safe_expiry))
        repo.md_timestamp = Metadata(Timestamp(expires=repo.safe_expiry))
        repo.md_root = Metadata(Root(expires=repo.safe_expiry))

        repo.md_targets_json = meta_dict_to_bytes(repo.md_targets.to_dict()) 
        repo.md_snapshot_json = meta_dict_to_bytes(repo.md_snapshot.to_dict()) 
        repo.md_timestamp_json = meta_dict_to_bytes(repo.md_timestamp.to_dict()) 
        repo.md_root_json = meta_dict_to_bytes(repo.md_root.to_dict()) 

        for role in TOP_LEVEL_ROLE_NAMES:
            signer = CryptoSigner.generate_ecdsa()

            # Add key for role
            # This is the test suites way to add a key.
            repo.add_key(Root.type, role, signer)

            # This is the correct way to add a key. The conf test suite
            # does not use this method, so we use this as the correct value
            # that we should match.
            repo.md_root.signed.add_key(signer.public_key, role)

            # Add signer for role
            repo.add_signer(role, signer)

        repo.publish_root()

        our_own_bytes = meta_dict_to_bytes(json.loads(repo.load_metadata_bytes(Root.type))["signed"])
        expected_bytes = meta_dict_to_bytes(json.loads(repo.md_root.to_bytes())["signed"])
        self.assertEqual(our_own_bytes, expected_bytes)

    def test_downgrade_snapshot(self):
        repo = RepositorySimulator()
        repo.update_snapshot() # v2
        self.assertTrue(repo._version_equals(Snapshot.type, 2))
        repo.downgrade_snapshot() # v1
        self.assertTrue(repo._version_equals(Snapshot.type, 1))

    def test_downgrade_timestamp(self):
        repo = RepositorySimulator()
        repo.update_timestamp() # v2
        self.assertTrue(repo._version_equals(Timestamp.type, 2))
        repo.downgrade_timestamp() # v1
        self.assertTrue(repo._version_equals(Timestamp.type, 1))

if __name__ == '__main__':
    unittest.main()