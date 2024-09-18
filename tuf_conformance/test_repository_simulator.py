import unittest
from tempfile import TemporaryDirectory

from tuf.api.metadata import (
    Metadata,
    Root,
    Snapshot,
    Targets,
    Timestamp,
)

from tuf_conformance import utils
from tuf_conformance.simulator_server import SimulatorServer


class TestRepositorySimulator(unittest.TestCase):
    def test_repo_initialzation_unittest(self) -> None:
        tmp_dir = TemporaryDirectory()
        server = SimulatorServer(dump_dir=tmp_dir.name)
        init_data, repo = server.new_test("test_repo_initialzation")
        self.assertEqual(repo.root.version, 1)
        self.assertEqual(repo.timestamp.version, 1)
        self.assertEqual(repo.snapshot.version, 1)
        self.assertEqual(repo.targets.version, 1)
        self.assertEqual(len(repo.signed_mds), 4)
        self.assertEqual(
            Metadata.from_bytes(repo.signed_mds[Root.type][-1]).signed.version, 1
        )
        self.assertEqual(
            Metadata.from_bytes(repo.signed_mds[Timestamp.type][-1]).signed.version, 1
        )
        self.assertEqual(
            Metadata.from_bytes(repo.signed_mds[Snapshot.type][-1]).signed.version, 1
        )
        self.assertEqual(
            Metadata.from_bytes(repo.signed_mds[Targets.type][-1]).signed.version, 1
        )

    def test_basic_metadata_hash_support_unittest(self) -> None:
        tmp_dir = TemporaryDirectory()
        server = SimulatorServer(dump_dir=tmp_dir.name)
        init_data, repo = server.new_test("unittest_basic_metadata_hash_support")
        repo.compute_metafile_hashes_length = True
        repo.publish([Targets.type, Snapshot.type, Timestamp.type])  # v2
        self.assertEqual(
            Metadata.from_bytes(repo.signed_mds[Snapshot.type][-1]).signed.version, 2
        )

        expected_hashes, expected_length = repo._compute_hashes_and_length(
            Snapshot.type
        )

        self.assertEqual(
            Metadata[Timestamp]
            .from_bytes(repo.signed_mds[Timestamp.type][-1])
            .signed.snapshot_meta.length,
            expected_length,
        )
        self.assertEqual(
            Metadata[Timestamp]
            .from_bytes(repo.signed_mds[Timestamp.type][-1])
            .signed.snapshot_meta.hashes,
            expected_hashes,
        )

    def test_update_timestamp(self) -> None:
        tmp_dir = TemporaryDirectory()
        server = SimulatorServer(dump_dir=tmp_dir.name)
        init_data, repo = server.new_test("test_timestamp_expired")

        five_days_in_path = utils.get_date_n_days_in_past(5)
        repo.timestamp.expires = five_days_in_path
        repo.publish([Timestamp.type])
        self.assertEqual(
            Metadata.from_bytes(repo.signed_mds[Timestamp.type][-1]).signed.expires,
            five_days_in_path,
        )


if __name__ == "__main__":
    unittest.main()
