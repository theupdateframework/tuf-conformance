import subprocess
import os
from tempfile import TemporaryDirectory

from tuf_conformance.simulator_server import ClientInitData, SimulatorServer


class ClientRunner:
    """Wrapper that executes the client under test
    
    The constructor arg 'client_cmd' is a path to an executable that
    conforms to the test script definition.
    
    ClientRunner manages client resources (like the cache paths etc)"""
    def __init__(self, client_cmd: str, server: SimulatorServer) -> None:
        self._server = server
        self._cmd = client_cmd
        self._tempdir = TemporaryDirectory()
        # TODO: cleanup tempdir
        self.metadata_dir = os.path.join(self._tempdir.name, "metadata")
        os.mkdir(self.metadata_dir)

    def _run(self, cmd: list[str]):
        popen = subprocess.Popen(cmd)
        while popen.poll() is None:
            self._server.handle_request()

    def init_client(self, data: ClientInitData):
        trusted = os.path.join(self._tempdir.name, "initial_root.json")
        with open(trusted, "bw") as f:
            f.write(data.trusted_root)
        
        cmd = self._cmd.split(" ") + ["--metadata-url", data.metadata_url, "--metadata-dir", self.metadata_dir, "init", trusted]
        self._run(cmd)

    def refresh(self, data: ClientInitData):
        cmd = self._cmd.split(" ") + ["--metadata-url", data.metadata_url, "--metadata-dir", self.metadata_dir, "refresh"]
        self._run(cmd)
