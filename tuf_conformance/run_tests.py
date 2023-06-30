# Test runner

# This is just a very quick hack: we may want to use an actual unit test
# system to build this eventually 

import argparse
import logging
import os
import subprocess
import sys
from typing import Dict, List
from tempfile import TemporaryDirectory

from tuf_conformance.repository_simulator import RepositorySimulator
from tuf_conformance.simulator_server import SimulatorServer, ClientInitData

class ClientRunner:
    """Wrapper that executes the client under test
    
    The constructor arg 'client_cmd' is a path to an executable that
    conforms to the test script definition.
    
    ClientRunner manages client resources (like the cache paths etc)"""
    def __init__(self, client_cmd: str) -> None:
        self._cmd = client_cmd
        self._tempdir = TemporaryDirectory()
        # TODO: cleanup tempdir
        self.metadata_dir = os.path.join(self._tempdir.name, "metadata")
        os.mkdir(self.metadata_dir)

    def init_client(self, data: ClientInitData):
        trusted = os.path.join(self._tempdir.name, "initial_root.json")
        with open(trusted, "bw") as f:
            f.write(data.trusted_root)
        
        cmd = self._cmd.split(" ") + ["init", "--metadata-url", data.metadata_url, "--metadata-dir", self.metadata_dir, "--trusted", trusted]
        subprocess.run(cmd)


def test_init(client: ClientRunner, server: SimulatorServer) -> None:
    """This is an example of a test method: it should likely be a e.g. a unittest.TestCase"""

    name = "test_init"

    # initialize a simulator with repository content we need
    repo = RepositorySimulator()
    server.repos[name] = repo

    # Run the test: initialize client
    client.init_client(server.get_client_init_data(name))

    # TODO verify that results are correct, see e.g. 
    # * repo.metadata_statistics to verify requests (in this case no requests expected)
    # * contents of clients metadata cache (in this case root v1 only)


def main(argv: List[str]) -> None:
    """Conformance test runner"""

    parser = argparse.ArgumentParser()
    parser.add_argument("client")
    args = parser.parse_args()

    server = SimulatorServer(9001)

    client = ClientRunner(args.client)
    print(f"Running tests using client wrapper '{args.client}'")


    # loop through tests here, maybe by using unittest or something?
    test_init(client, server)


if __name__ == "__main__":
    sys.exit(main(sys.argv))

