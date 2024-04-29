# Test runner

import json
import os

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
    assert client.init_client(init_data) == 0

    # TODO verify that results are correct, see e.g. 
    # * repo.metadata_statistics: no requests expected
    # * client metadat cache should contain root v1

    # Run the test: step 1: Refresh
    assert client.refresh(init_data) == 0

    # Verify that expected requests were made
    assert repo.metadata_statistics == [('root', 1), ('root', 2), ('timestamp', None), ('snapshot', 1), ('targets', 1)]
    # TODO verify that local metadata cache has the files we expect

    tmpdir = [ [os.path.relpath( os.path.join(parent, file) , client._tempdir.name) for file in files] for (parent, _, files) in os.walk(client._tempdir.name)]
    for list in tmpdir: list.sort()
    assert tmpdir == [
        ['initial_root.json'], 
        ['metadata/root.json', 'metadata/snapshot.json', 'metadata/targets.json', 'metadata/timestamp.json']
    ]
    for file in tmpdir[1]:
        with open(os.path.join(client._tempdir.name, file), 'rb') as f:
            assert strip_signature(f.read()) == strip_signature(repo.fetch_metadata(os.path.basename(file).split('.')[0], 1).decode()), f"{file} does not match"

def strip_signature(b: bytes) -> bytes:
    value = json.loads(b)  # check if it is valid json
    for sig in value.get("signatures"):
        sig.pop("sig")
    return value