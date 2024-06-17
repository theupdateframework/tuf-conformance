# Test runner

import datetime
import json
import os
import tempfile

from datetime import timezone
from tuf_conformance.repository_simulator import RepositorySimulator
from tuf_conformance.simulator_server import SimulatorServer
from tuf_conformance.client_runner import ClientRunner
from tuf_conformance import utils

from tuf.api.exceptions import (
    BadVersionNumberError
)

from tuf.api.metadata import (
    Timestamp, Snapshot, Root, Targets, Metadata
)

from tuf.ngclient import RequestsFetcher


class TestTarget:
    path: str
    content: bytes
    encoded_path: str

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

def test_new_snapshot_version_rollback(client: ClientRunner, server: SimulatorServer) -> None:
    """This is an example of a test method: it should likely be a e.g. a unittest.TestCase"""

    name = "test_new_snapshot_version_rollback"

    # initialize a simulator with repository content we need
    repo = RepositorySimulator()
    server.repos[name] = repo
    init_data = server.get_client_init_data(name)

    assert client.init_client(init_data) == 0

    # Repository performs legitimate update to snapshot
    repo.update_snapshot()
    assert client.refresh(init_data) == 0

    # Sanity check that client saw the snapshot update:
    assert client._assert_version_equals(Snapshot.type, 2)

    # Repository attempts rollback attack:
    repo.downgrade_snapshot()
    assert repo.snapshot.version == 1
    client.refresh(init_data)

    # Check that client resisted rollback attack
    assert client._assert_version_equals(Snapshot.type, 2)

def test_new_timestamp_version_rollback(client: ClientRunner, server: SimulatorServer) -> None:
    """This is an example of a test method: it should likely be a e.g. a unittest.TestCase"""

    name = "test_new_timestamp_version_rollback"

    # initialize a simulator with repository content we need
    repo = RepositorySimulator()
    server.repos[name] = repo
    init_data = server.get_client_init_data(name)

    assert client.init_client(init_data) == 0

    # Repository performs legitimate update to snapshot
    repo.update_timestamp()
    assert repo.timestamp.version == 2
    assert client.refresh(init_data) == 0

    # Sanity check that client saw the snapshot update:
    assert client._assert_version_equals(Timestamp.type, 2)

    # Repository attempts rollback attack:
    repo.downgrade_timestamp()

    # Sanitty check that the repository is attempting a rollback attack
    assert repo.timestamp.version == 1

    client.refresh(init_data)

    # Check that client resisted rollback attack
    assert client._assert_version_equals(Timestamp.type, 2)

def test_new_timestamp_snapshot_rollback(client: ClientRunner, server: SimulatorServer) -> None:
    """This is an example of a test method: it should likely be a e.g. a unittest.TestCase"""

    name = "test_new_timestamp_snapshot_rollback"

    # initialize a simulator with repository content we need
    repo = RepositorySimulator()
    server.repos[name] = repo
    init_data = server.get_client_init_data(name)

    assert client.init_client(init_data) == 0

    # Start snapshot version at 2
    repo.snapshot.version = 2

    # Repository performs legitimate update to snapshot
    repo.update_timestamp()
    assert repo.timestamp.version == 2
    assert client.refresh(init_data) == 0

    # Repo attempts rollback attack
    repo.timestamp.snapshot_meta.version = 1
    repo.timestamp.version += 1
    assert repo.timestamp.version == 3

    client.refresh(init_data)

    # Check that client resisted rollback attack
    assert client._assert_version_equals(Timestamp.type, 2)

def test_new_timestamp_expired(client: ClientRunner, server: SimulatorServer) -> None:
    """This is an example of a test method: it should likely be a e.g. a unittest.TestCase"""

    name = "test_new_timestamp_expired"

    # initialize a simulator with repository content we need
    repo = RepositorySimulator()
    server.repos[name] = repo
    init_data = server.get_client_init_data(name)

    assert client.init_client(init_data) == 0
    repo.timestamp.expires = datetime.datetime.now(timezone.utc).replace(
        microsecond=0
    ) - datetime.timedelta(days=5)
    client.refresh(init_data)

    repo.update_timestamp()

    client.refresh(init_data)

    # Check that client resisted rollback attack
    assert client._assert_files_exist([Root.type])

def test_new_targets_fast_forward_recovery(client: ClientRunner, server: SimulatorServer) -> None:
    """Test targets fast-forward recovery using key rotation.

    The targets recovery is made by issuing new Snapshot keys, by following
    steps:
        - Remove the snapshot key
        - Create and add a new key for snapshot
        - Bump and publish root
        - Rollback the target version
    """

    name = "test_new_targets_fast_forward_recovery"

    # initialize a simulator with repository content we need
    repo = RepositorySimulator()
    server.repos[name] = repo
    init_data = server.get_client_init_data(name)

    assert client.init_client(init_data) == 0
    repo.targets.version = 99999

    repo.update_snapshot()
    client.refresh(init_data)
    client._assert_version_equals(Targets.type, 99999)

    repo.rotate_keys(Snapshot.type)
    repo.root.version += 1
    repo.publish_root()

    repo.targets.version = 1
    repo.update_snapshot()

    client.refresh(init_data)
    assert client._assert_version_equals(Targets.type, 1)

def test_new_snapshot_fast_forward_recovery(client: ClientRunner, server: SimulatorServer) -> None:
    """Test snapshot fast-forward recovery using key rotation.

    The snapshot recovery requires the snapshot and timestamp key rotation.
    It is made by the following steps:
    - Remove the snapshot and timestamp keys
    - Create and add a new key for snapshot and timestamp
    - Rollback snapshot version
    - Bump and publish root
    - Bump the timestamp
    """
    name = "test_new_snapshot_fast_forward_recovery"

    # initialize a simulator with repository content we need
    repo = RepositorySimulator()
    server.repos[name] = repo
    init_data = server.get_client_init_data(name)

    assert client.init_client(init_data) == 0
    repo.snapshot.version = 99999

    repo.update_timestamp()
    client.refresh(init_data)
    client._assert_version_equals(Snapshot.type, 99999)

    repo.rotate_keys(Snapshot.type)
    repo.rotate_keys(Timestamp.type)
    repo.root.version += 1
    repo.publish_root()

    repo.snapshot.version = 1
    repo.update_timestamp()

    client.refresh(init_data)
    assert client._assert_version_equals(Snapshot.type, 1)

def test_new_snapshot_version_mismatch(client: ClientRunner, server: SimulatorServer) -> None:
    # Check against timestamp role's snapshot version

    name = "test_new_snapshot_version_mismatch"

    # initialize a simulator with repository content we need
    repo = RepositorySimulator()
    server.repos[name] = repo
    init_data = server.get_client_init_data(name)

    assert client.init_client(init_data) == 0

    # Increase snapshot version without updating timestamp
    repo.snapshot.version += 1
    repo.update_snapshot()

    client.refresh(init_data)
    assert client._assert_files_exist([Root.type, Timestamp.type])

def test_new_timestamp_fast_forward_recovery(client: ClientRunner, server: SimulatorServer) -> None:
    """The timestamp recovery is made by the following steps
     - Remove the timestamp key
     - Create and add a new key for timestamp
     - Bump and publish root
     - Rollback the timestamp version
    """

    name = "test_new_timestamp_fast_forward_recovery"

    # initialize a simulator with repository content we need
    repo = RepositorySimulator()
    server.repos[name] = repo
    init_data = server.get_client_init_data(name)

    assert client.init_client(init_data) == 0

    # attacker updates to a higher version
    repo.timestamp.version = 99998
    repo.update_timestamp()

    assert repo.timestamp.version == 99999

    # client refreshes the metadata and see the new timestamp version
    client.refresh(init_data)
    assert client._assert_version_equals(Timestamp.type, 99999)

    # repository rotates timestamp keys, rolls back timestamp version
    repo.rotate_keys(Timestamp.type)
    repo.root.version += 1
    repo.publish_root()
    repo.timestamp.version = 1

    # client refresh the metadata and see the initial timestamp version
    client.refresh(init_data)
    assert client._assert_version_equals(Timestamp.type, 1)

def test_downloaded_file_is_correct(client: ClientRunner, server: SimulatorServer) -> None:
    # A test that upgrades the version of one of the files in snapshot.json only
    # but does does not upgrade in the file itself.
    name = "test_downloaded_file_is_correct"

    # initialize a simulator with repository content we need
    repo = RepositorySimulator()
    server.repos[name] = repo
    init_data = server.get_client_init_data(name)

    assert client.init_client(init_data) == 0
    server_process_handler = utils.TestServerProcess(log=utils.logger)

    target_file_gl = ""

    file_contents = b"target file contents"
    file_contents_str = "target file contents"
    file_length = len(file_contents)
    target_base_name = "target_file.txt"

    target_file_path = os.path.join(client._remote_target_dir.name, target_base_name)
    target_file = open(target_file_path, 'w')
    target_file.write(file_contents_str)
    target_file.close()

    url_prefix = (
        f"http://{utils.TEST_HOST_ADDRESS}:"
        f"{server_process_handler.port!s}/{os.path.basename(client._remote_target_dir.name)}"
    )

    target = TestTarget()
    target.path = target_base_name
    target.content = file_contents
    target.encoded_path = target_base_name

    # Add target to repository
    repo.targets.version += 1
    repo.add_target_with_length("targets", target.content, target.path, len(target.content))
    repo.update_snapshot()

    # Sanity checks
    assert os.path.isfile(target_file_path)
    with open(target_file_path) as f:
        assert f.read() == file_contents_str

    # Sanity check that we have not downloaded any files yet
    assert client.get_last_downloaded_target() == ""

    target_file2 = client.download_target(init_data,
                                          target_base_name,
                                          target_base_url=url_prefix)

    # Sanity check that we downloaded the file
    assert client.get_last_downloaded_target() == os.path.join(client._target_dir.name,
                                                               target_base_name)

    with open(client.get_last_downloaded_target(), "r") as last_download_file:
        donwloaded_file_contents = last_download_file.read()
        assert donwloaded_file_contents == file_contents_str
        print("last file contents: ", donwloaded_file_contents)

def test_downloaded_file_is_correct2(client: ClientRunner, server: SimulatorServer) -> None:
    # A test that upgrades the version of one of the files in snapshot.json only
    # but does does not upgrade in the file itself.
    name = "test_downloaded_file_is_correct2"

    # initialize a simulator with repository content we need
    repo = RepositorySimulator()
    server.repos[name] = repo
    init_data = server.get_client_init_data(name)
    assert client.init_client(init_data) == 0
    server_process_handler = utils.TestServerProcess(log=utils.logger)

    file_contents = b"legitimate data"
    file_contents_str = "legitimate data"
    file_length = len(file_contents)
    target_base_name = "target_file.txt"

    ## Create, upload and update a legitimate target file
    target_file_path = os.path.join(client._remote_target_dir.name, target_base_name)
    target_file = open(target_file_path, 'w')
    target_file.write(file_contents_str)
    target_file.close()

    target = TestTarget()
    target.path = target_base_name
    target.content = file_contents
    target.encoded_path = target_base_name

    # Add target to repository
    repo.targets.version += 1
    repo.add_target_with_length("targets", target.content,
                                target.path, len(target.content))
    repo.update_snapshot()

    # Sanity checks
    assert os.path.isfile(target_file_path)
    with open(target_file_path) as f:
        assert f.read() == file_contents_str

    url_prefix = (
        f"http://{utils.TEST_HOST_ADDRESS}:"
        f"{server_process_handler.port!s}/{os.path.basename(client._remote_target_dir.name)}"
    )

    # Sanity check that we have not downloaded any files yet
    assert client.get_last_downloaded_target() == ""

    target_file2 = client.download_target(init_data,
                                          target_base_name,
                                          target_base_url=url_prefix)
    # Sanity check that we downloaded the file
    assert client.get_last_downloaded_target() == os.path.join(client._target_dir.name,
                                                               target_base_name)

    with open(client.get_last_downloaded_target(), "r") as last_download_file:
        data_of_last_downloaded_file = last_download_file.read()
        assert data_of_last_downloaded_file == file_contents_str


    ## Now do the following:
    ## 1: Create a file in the repo with the same name but different contents
    ## 2: Update the targets version in the repo
    ## 3: Download the target
    ## 4: Verify that the client has not downloaded the new file.
    ## The repo does not add the file, so this imitates an attacker
    ## that attempts to compromise the repository.
    malicious_file_contents_str = "malicious data - should not download"
    new_target_file = open(target_file_path, 'w')
    new_target_file.write(malicious_file_contents_str)
    new_target_file.close()

    # Update target version target to repository without
    # updating the target in the metadata
    repo.targets.version += 1
    repo.update_snapshot()

    # Sanity checks
    assert os.path.isfile(target_file_path)
    with open(target_file_path) as f:
        assert f.read() == malicious_file_contents_str

    target_file2 = client.download_target(init_data,
                                          target_base_name,
                                          target_base_url=url_prefix)

    with open(client.get_last_downloaded_target(), "r") as last_download_file:
        data_of_last_downloaded_file = last_download_file.read()
        assert data_of_last_downloaded_file == file_contents_str
