import os

from tuf_conformance.repository_simulator import RepositorySimulator
from tuf_conformance.simulator_server import SimulatorServer
from tuf_conformance.client_runner import ClientRunner
from tuf_conformance import utils
from tuf_conformance.utils import TestTarget

from tuf.api.metadata import (
    Snapshot
)


def get_url_prefix(server_process_handler: utils.TestServerProcess,
                   client: ClientRunner) -> str:
    url_prefix = (
        f"http://{utils.TEST_HOST_ADDRESS}:"
        f"{server_process_handler.port!s}/{os.path.basename(client._remote_target_dir.name)}"
    )
    return url_prefix


# TODO: Needs work
def test_downloaded_file_is_correct(
    client: ClientRunner, server: SimulatorServer
) -> None:
    """ A test that upgrades the version of one of the
    files in snapshot.json only but does does not upgrade
    in the file itself."""
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

    target_file_path = os.path.join(client._remote_target_dir.name,
                                    target_base_name)
    target_file = open(target_file_path, 'w')
    target_file.write(file_contents_str)
    target_file.close()

    url_prefix = get_url_prefix(server_process_handler, client)

    target = TestTarget()
    target.path = target_base_name
    target.content = file_contents

    # Add target to repository
    repo.add_target_with_length("targets", target)
    repo.targets.version += 1
    repo.update_snapshot()
    client.refresh(init_data)

    # Sanity checks
    assert os.path.isfile(target_file_path)
    with open(target_file_path) as f:
        assert f.read() == file_contents_str


    # Sanity check that we have not downloaded any files yet
    assert client.get_last_downloaded_target() == ""

    assert client.download_target(init_data,
                                  target_base_name,
                                  target_base_url=url_prefix) == 0

    # Sanity check that we downloaded the file
    expected_last_file = os.path.join(client._target_dir.name,
                                      target_base_name)
    last_downloaded_file = client.get_last_downloaded_target()
    assert last_downloaded_file == expected_last_file

    with open(client.get_last_downloaded_target(), "r") as last_download_file:
        donwloaded_file_contents = last_download_file.read()
        assert donwloaded_file_contents == file_contents_str

# TODO: Needs work
def test_downloaded_file_is_correct2(client: ClientRunner,
                                     server: SimulatorServer) -> None:
    # A test that upgrades the version of one of the files in
    # snapshot.json only but does does not upgrade in the file itself.
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
    target_file_path = os.path.join(client._remote_target_dir.name,
                                    target_base_name)
    target_file = open(target_file_path, 'w')
    target_file.write(file_contents_str)
    target_file.close()

    target = TestTarget()
    target.path = target_base_name
    target.content = file_contents

    # Add target to repository
    repo.add_target_with_length("targets", target)
    repo.targets.version += 1
    repo.update_snapshot()
    client.refresh(init_data)

    # Sanity checks
    assert os.path.isfile(target_file_path)
    with open(target_file_path) as f:
        assert f.read() == file_contents_str

    url_prefix = get_url_prefix(server_process_handler, client)


    # Sanity check that we have not downloaded any files yet
    assert client.get_last_downloaded_target() == ""

    target_file2 = client.download_target(init_data,
                                          target_base_name,
                                          target_base_url=url_prefix)
    # Sanity check that we downloaded the file
    assert client.get_last_downloaded_target() == os.path.join(client._target_dir.name,
                                                               target_base_name)

    with open(client.get_last_downloaded_target(), "r") as last_download_file:
        assert last_download_file.read() == file_contents_str


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
    client.refresh(init_data)

    # Sanity checks
    assert os.path.isfile(target_file_path)
    with open(target_file_path) as f:
        assert f.read() == malicious_file_contents_str

    target_file2 = client.download_target(init_data,
                                          target_base_name,
                                          target_base_url=url_prefix)

    with open(client.get_last_downloaded_target(), "r") as last_download_file:
        assert last_download_file.read() == file_contents_str

# TODO: Needs work
def test_downloaded_file_is_correct3(client: ClientRunner,
                                     server: SimulatorServer) -> None:
    """A test that upgrades the version of one of the files in 
    snapshot.json only but does does not upgrade in the file itself."""
    name = "test_downloaded_file_is_correct3"

    # initialize a simulator with repository content we need
    repo = RepositorySimulator()
    server.repos[name] = repo
    init_data = server.get_client_init_data(name)
    assert client.init_client(init_data) == 0
    server_process_handler = utils.TestServerProcess(log=utils.logger)

    file_contents = b"legitimate data"
    target_base_name = "target_file.txt"

    ## Create, upload and update a legitimate target file
    target_file_path = os.path.join(client._remote_target_dir.name,
                                    target_base_name)
    target_file = open(target_file_path, 'w')
    target_file.write(file_contents.decode())
    target_file.close()

    target = TestTarget()
    target.path = target_base_name
    target.content = file_contents

    # Add target to repository
    repo.add_target_with_length("targets", target)
    repo.targets.version += 1
    repo.update_snapshot()
    client.refresh(init_data)

    # Sanity checks
    assert os.path.isfile(target_file_path)
    with open(target_file_path) as f:
        assert f.read() == file_contents.decode()

    url_prefix = get_url_prefix(server_process_handler, client)

    # Sanity check that we have not downloaded any files yet
    assert client.get_last_downloaded_target() == ""

    target_file2 = client.download_target(init_data,
                                          target_base_name,
                                          target_base_url=url_prefix)
    # Sanity check that we downloaded the file
    assert client.get_last_downloaded_target() == os.path.join(client._target_dir.name,
                                                         target_base_name)

    with open(client.get_last_downloaded_target(), "r") as last_download_file:
        assert last_download_file.read() == file_contents.decode()


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

    # Make a lot of changes to the repo and refresh the client
    # and check the target file
    for i in range(10):
        repo.update_timestamp()
        repo.rotate_keys(Snapshot.type)
        repo.bump_root_by_one()
        repo.targets.version += 1
        repo.update_snapshot()
        client.refresh(init_data)
        # Sanity checks
        assert os.path.isfile(target_file_path)
        with open(target_file_path) as f:
            assert f.read() == malicious_file_contents_str
        target_file2 = client.download_target(init_data,
                                              target_base_name,
                                              target_base_url=url_prefix)
        with open(client.get_last_downloaded_target(), "r") as last_download_file:
            assert last_download_file.read() == file_contents.decode()

def test_multiple_changes_to_target(client: ClientRunner,
                                    server: SimulatorServer) -> None:
    name = "test_multiple_changes_to_target"

    # initialize a simulator with repository content we need
    repo = RepositorySimulator()
    server.repos[name] = repo
    init_data = server.get_client_init_data(name)
    assert client.init_client(init_data) == 0
    server_process_handler = utils.TestServerProcess(log=utils.logger)

    file_contents = b"legitimate data"
    target_base_name = "target_file.txt"

    ## Create, upload and update a legitimate target file
    target_file_path = os.path.join(client._remote_target_dir.name,
                                    target_base_name)
    target_file = open(target_file_path, 'w')
    target_file.write(file_contents.decode())
    target_file.close()

    target = TestTarget()
    target.path = target_base_name
    target.content = file_contents

    # Add target to repository
    repo.targets.version += 1
    repo.add_target_with_length("targets", target)
    repo.update_snapshot()
    client.refresh(init_data)

    # Sanity checks
    assert os.path.isfile(target_file_path)
    with open(target_file_path) as f:
        assert f.read() == file_contents.decode()

    url_prefix = get_url_prefix(server_process_handler, client)

    # Sanity check that we have not downloaded any files yet
    assert client.get_last_downloaded_target() == ""

    target_file2 = client.download_target(init_data,
                                          target_base_name,
                                          target_base_url=url_prefix)
    # Sanity check that we downloaded the file
    assert client.get_last_downloaded_target() == os.path.join(client._target_dir.name,
                                                               target_base_name)

    with open(client.get_last_downloaded_target(), "r") as last_download_file:
        assert file_contents.decode() == last_download_file.read()
    

    # Change the target contents 10 times and check it each time
    for i in range(10):
        new_file_contents = f"{file_contents.decode()}-{i}"
        file_length = len(new_file_contents)

        target_file = open(target_file_path, 'w+')
        target_file.write(new_file_contents)
        target_file.close()

        repo.targets.version += 1

        target = TestTarget()
        target.path = target_base_name
        target.content = bytes(new_file_contents, 'utf-8')

        repo.add_target_with_length("targets", target)
        repo.update_snapshot()
        client.refresh(init_data)

        # Check that the file is the one we expect
        assert os.path.isfile(target_file_path)
        with open(target_file_path) as f:
            assert f.read() == new_file_contents
        target_file2 = client.download_target(init_data,
                                              target_base_name,
                                              target_base_url=url_prefix)
        with open(client.get_last_downloaded_target(), "r") as last_download_file:
            assert last_download_file.read() == new_file_contents

        # Substitute the file and check that the file is still the one we expect
        # The client should not download this malicious one even though it exists
        # at the same path as the legitimate one.
        malicious_file_contents_str = f"malicious-file-contents-{i}"
        new_target_file = open(target_file_path, 'w+')
        new_target_file.write(malicious_file_contents_str)
        new_target_file.close()

        assert os.path.isfile(target_file_path)
        with open(target_file_path) as f:
            assert f.read() == malicious_file_contents_str
        target_file2 = client.download_target(init_data,
                                              target_base_name,
                                              target_base_url=url_prefix)
        with open(client.get_last_downloaded_target(), "r") as last_download_file:
            assert new_file_contents == last_download_file.read()
