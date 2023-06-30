# Test runner

# This is just a very quick hack: we may want to use an actual unit test
# system to build this eventually 

import argparse
from typing import Dict, List

from tuf_conformance.repository_simulator import RepositorySimulator
from tuf_conformance.simulator_server import SimulatorServer
from tuf_conformance.client_runner import ClientRunner

def test_basic_init_and_refresh(client: ClientRunner, server: SimulatorServer) -> None:
    """This is an example of a test method: it should likely be a e.g. a unittest.TestCase"""

    name = "test_init"

    # initialize a simulator with repository content we need
    repo = RepositorySimulator()
    server.repos[name] = repo
    init_data = server.get_client_init_data(name)

    # Run the test: step 1:  initialize client
    # TODO verify success?
    client.init_client(init_data)

    # TODO verify that results are correct, see e.g. 
    # * repo.metadata_statistics: no requests expected
    # * client metadat cache should contain root v1

    # Run the test: step 1: Refresh
    client.refresh(init_data)

    # Verify that expected requests were made
    assert repo.metadata_statistics == [('root', 1), ('root', 2), ('timestamp', None), ('snapshot', 1), ('targets', 1)]
    # TODO verify that local metadata cache has the files we expect


def main() -> None:
    """Conformance test runner"""

    parser = argparse.ArgumentParser()
    parser.add_argument("client")
    args = parser.parse_args()

    server = SimulatorServer(9001)

    client = ClientRunner(args.client, server)
    print(f"Running tests using client wrapper '{args.client}'")


    # loop through tests here, maybe by using unittest or something?
    test_basic_init_and_refresh(client, server)
