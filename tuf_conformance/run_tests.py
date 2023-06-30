# Test runner

# This is just a very quick hack: we may want to use an actual unit test
# system to build this eventually 

import argparse
from typing import Dict, List

from tuf_conformance.repository_simulator import RepositorySimulator
from tuf_conformance.simulator_server import SimulatorServer
from tuf_conformance.client_runner import ClientRunner

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


def main() -> None:
    """Conformance test runner"""

    parser = argparse.ArgumentParser()
    parser.add_argument("client")
    args = parser.parse_args()

    server = SimulatorServer(9001)

    client = ClientRunner(args.client)
    print(f"Running tests using client wrapper '{args.client}'")


    # loop through tests here, maybe by using unittest or something?
    test_init(client, server)
