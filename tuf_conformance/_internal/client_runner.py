import glob
import os
import subprocess
from datetime import datetime
from tempfile import TemporaryDirectory

from tuf.api.exceptions import StorageError
from tuf.api.metadata import Metadata
from tuf.api.serialization.json import JSONSerializer

from tuf_conformance._internal.metadata import MetadataTest
from tuf_conformance._internal.simulator_server import (
    ClientInitData,
    SimulatorServer,
    StaticServer,
)


class ClientRunner:
    """Wrapper that executes the client under test

    The constructor arg 'client_cmd' is a path to an executable that
    conforms to the test script definition.

    ClientRunner manages client resources (like the cache paths etc)"""

    def __init__(
        self, client_cmd: str, server: SimulatorServer | StaticServer, test_name: str
    ) -> None:
        self._server = server
        self._cmd = client_cmd.split(" ")
        self._tempdir = TemporaryDirectory()
        # TODO: cleanup tempdir
        self.metadata_dir = os.path.join(self._tempdir.name, "metadata")
        self.artifact_dir = os.path.join(self._tempdir.name, "targets")
        os.mkdir(self.metadata_dir)
        os.mkdir(self.artifact_dir)
        self.test_name = test_name

    def get_downloaded_target_bytes(self) -> list[bytes]:
        """Returns list of downloaded artifact contents in order of modification time"""
        artifacts = glob.glob(f"{self.artifact_dir}/**", recursive=True)
        artifact_bytes = []
        for artifact in sorted(artifacts, key=os.path.getmtime):
            if not os.path.isfile(artifact):
                continue
            with open(artifact, "rb") as f:
                artifact_bytes.append(f.read())

        return artifact_bytes

    def _run(self, cmd: list[str]) -> int:
        popen = subprocess.Popen(cmd)  # noqa: S603
        while popen.poll() is None:
            self._server.handle_request()
        return popen.returncode

    def init_client(self, data: ClientInitData) -> int:
        trusted = os.path.join(self._tempdir.name, "initial_root.json")
        with open(trusted, "bw") as f:
            f.write(data.trusted_root)

        cmd = [*self._cmd, "--metadata-dir", self.metadata_dir, "init", trusted]
        return self._run(cmd)

    def refresh(self, data: ClientInitData, fake_time: datetime | None = None) -> int:
        # dump a repository version for each client refresh (if configured to)
        self._server.debug_dump(self.test_name)

        cmd = self._cmd
        if fake_time:
            cmd = ["faketime", f"{fake_time}", *cmd]

        cmd = [
            *cmd,
            "--metadata-url",
            data.metadata_url,
            "--metadata-dir",
            self.metadata_dir,
            "refresh",
        ]
        return self._run(cmd)

    def download_target(self, data: ClientInitData, target_name: str) -> int:
        self._server.debug_dump(self.test_name)
        cmd = [
            *self._cmd,
            "--metadata-url",
            data.metadata_url,
            "--metadata-dir",
            self.metadata_dir,
            "--target-name",
            target_name,
            "--target-dir",
            self.artifact_dir,
            "--target-base-url",
            data.targets_url,
            "download",
        ]
        return self._run(cmd)

    def version(self, role: str) -> int | None:
        """Returns current trusted version of role. Returns None if there is no trusted
        version
        """
        try:
            md = MetadataTest.from_file(os.path.join(self.metadata_dir, f"{role}.json"))
        except StorageError:
            return None
        return md.signed.version

    def trusted_roles(self) -> list[tuple[str, int]]:
        """Return list of current trusted role names and versions

        Note that delegated role names may be encoded in a application specific way"""
        roles = []
        for filename in sorted(os.listdir(self.metadata_dir)):
            if not filename.endswith(".json"):
                continue
            rolename = filename.removesuffix(".json")
            md = Metadata.from_file(os.path.join(self.metadata_dir, filename))
            roles.append((rolename, md.signed.version))

        return roles

    def assert_metadata(self, role: str, expected_bytes: bytes | None) -> None:
        """Assert that trusted roles metadata matches the expected bytes

        This assert uses deserialized comparison: See test_metadata_bytes_match
        for the test that requires byte-for-byte equality.
        """
        try:
            trusted = MetadataTest.from_file(
                os.path.join(self.metadata_dir, f"{role}.json")
            ).to_bytes(JSONSerializer())
        except StorageError:
            trusted = None

        assert trusted == expected_bytes, f"Unexpected trusted role {role} content"
