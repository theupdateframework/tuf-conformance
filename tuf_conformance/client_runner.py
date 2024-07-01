import subprocess
import os
from os import listdir
from os.path import isfile, join
import glob
from tempfile import TemporaryDirectory
from typing import Iterable

from tuf_conformance.simulator_server import ClientInitData, SimulatorServer
from tuf.api.metadata import Metadata, Snapshot


class ClientRunner:
    """Wrapper that executes the client under test
    
    The constructor arg 'client_cmd' is a path to an executable that
    conforms to the test script definition.
    
    ClientRunner manages client resources (like the cache paths etc)"""
    def __init__(self, client_cmd: str, server: SimulatorServer) -> None:
        self._server = server
        self._cmd = client_cmd
        self._tempdir = TemporaryDirectory()
        self._target_dir = TemporaryDirectory()
        self._remote_target_dir = TemporaryDirectory(dir=os.getcwd())
        # TODO: cleanup tempdir
        self.metadata_dir = os.path.join(self._tempdir.name, "metadata")
        os.mkdir(self.metadata_dir)
        self.max_root_rotations = 32

    def get_last_downloaded_target(self) -> str:
        onlyfiles = [f for f in listdir(self._tempdir.name) if isfile(join(self._tempdir.name, f))]
        print("OF: ", onlyfiles)
        onlyfiles = [f for f in listdir(self._target_dir.name) if isfile(join(self._target_dir.name, f))]
        print("OF: ", onlyfiles)
        list_of_files = glob.glob(self._target_dir.name+"/*")
        if len(list_of_files) == 0:
            return ""
        latest_file = max(list_of_files, key=os.path.getctime)
        print("latest_file: ", latest_file)
        return latest_file

    def _run(self, cmd: list[str]) -> int:
        popen = subprocess.Popen(cmd)
        while popen.poll() is None:
            self._server.handle_request()
        return popen.returncode

    def init_client(self, data: ClientInitData) -> int:
        trusted = os.path.join(self._tempdir.name, "initial_root.json")
        with open(trusted, "bw") as f:
            f.write(data.trusted_root)
        
        cmd = self._cmd.split(" ") + ["--metadata-url", data.metadata_url, "--metadata-dir", self.metadata_dir, "init", trusted]
        return self._run(cmd)

    def refresh(self, data: ClientInitData, days_in_future="0") -> int:
        cmd = self._cmd.split(" ") + ["--metadata-url", data.metadata_url,
                                      "--metadata-dir", self.metadata_dir,
                                      "--days-in-future", days_in_future,
                                      "--max-root-rotations", str(self.max_root_rotations),
                                      "refresh"]
        return self._run(cmd)

    def download_target(self, data: ClientInitData, target_url: str, target_base_url: str) -> int:
        cmd = self._cmd.split(" ") + ["--metadata-url", data.metadata_url,
                                      "--metadata-dir", self.metadata_dir,
                                      "--target-url",target_url,
                                      "--target-dir", self._target_dir.name, 
                                      "--target-base-url", target_base_url,
                                      "download"]
        return self._run(cmd)

    def _version_equals(self, role: str, expected_version: int) -> None:
        """Check that local metadata version is the expected"""
        md = Metadata.from_file(os.path.join(self.metadata_dir, f"{role}.json"))
        print("md:::::::::::::::::::", md.signed.version, "role:::::::::", role, "expected: ", expected_version)
        return md.signed.version == expected_version

    def _files_exist(self, roles: Iterable[str]) -> None:
        """Check that local metadata files exist for 'roles'.
           There may be additional files in the local 
           metadata_dir than the expted files"""
        expected_files = sorted([f"{role}.json" for role in roles])
        local_metadata_files = sorted(os.listdir(self.metadata_dir))
        print("expected_files: ", expected_files, "local_metadata_files: ", local_metadata_files)
        return all(x in local_metadata_files for x in expected_files)
