import os
from tuf.api.metadata import Snapshot

from tuf_conformance.simulator_server import SimulatorServer
from tuf_conformance.client_runner import ClientRunner
from tuf_conformance import utils
from tuf_conformance.utils import TestTarget


def get_url_prefix(server_process_handler: utils.TestServerProcess,
                   client: ClientRunner) -> str:
    url_prefix = (
        f"http://{utils.TEST_HOST_ADDRESS}:"
        f"{server_process_handler.port!s}/{os.path.basename(client._remote_target_dir.name)}"
    )
    return url_prefix


def test_client_downloads_expected_file(
    client: ClientRunner, server: SimulatorServer
) -> None:
    """This test adds a file to the repository targets
    metadata. The client then refreshes, and downloads
    the target file. Finally, the test asserts that the
    client downloaded the file and that the filename and
    the contents of the file are correct"""
    init_data, repo = server.new_test(client.test_name)

    assert client.init_client(init_data) == 0
    server_process_handler = utils.TestServerProcess(log=utils.logger)

    # Create a test target file
    file_contents = b"target file contents"
    file_contents_str = "target file contents"
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

    # Add target to repository metadata
    repo.add_target_with_length("targets", target)

    # Bump targets and snapshot. The client should now update to
    # the metadata that has the file in the targets metadata.
    repo.targets.version += 1
    repo.update_snapshot()
    client.refresh(init_data)

    # Sanity check to ensure that the remote target file exists
    # and has the content we expect.
    assert os.path.isfile(target_file_path)
    with open(target_file_path) as f:
        assert f.read() == file_contents_str

    # Sanity check that we have not downloaded any files yet
    assert client.get_last_downloaded_target() == ""

    assert client.download_target(init_data,
                                  target_base_name,
                                  target_base_url=url_prefix) == 0

    # Check that the file we downloaded is the one we expected
    # Check the filename is correct
    expected_last_file = os.path.join(client._target_dir.name,
                                      target_base_name)
    last_downloaded_file = client.get_last_downloaded_target()
    assert last_downloaded_file == expected_last_file

    # Check the file contents are correct
    with open(client.get_last_downloaded_target(), "r") as last_download_file:
        donwloaded_file_contents = last_download_file.read()
        assert donwloaded_file_contents == file_contents_str


def test_repository_substitutes_target_file(
    client: ClientRunner, server: SimulatorServer
) -> None:
    """In this test, the repository has a file in its
    targets metadata and the corresponding file stored.
    The client then downloads the file and checks that
    it is correct. The repository then replaces the remote
    file that the repo targets metadata refers to. The
    repo then bumps the metadata so the client gets the
    latest metadata when it updates. The repositorys goal
    is to attempt to make the client download a file
    with the correct name but different contents than
    what the metadata specifies. Specifically, the test
    is to ensure that clients check the hashes and the
    lengths of the file before updating."""
    init_data, repo = server.new_test(client.test_name)

    assert client.init_client(init_data) == 0
    server_process_handler = utils.TestServerProcess(log=utils.logger)

    # Create legitimate target file that the client should receive
    # when the client downloads.
    file_contents = b"legitimate data"
    file_contents_str = "legitimate data"
    target_base_name = "target_file.txt"

    target_file_path = os.path.join(client._remote_target_dir.name,
                                    target_base_name)
    target_file = open(target_file_path, 'w')
    target_file.write(file_contents_str)
    target_file.close()

    target = TestTarget()
    target.path = target_base_name
    target.content = file_contents

    # Add target to repository targets metadata
    repo.add_target_with_length("targets", target)
    repo.targets.version += 1
    repo.update_snapshot()

    # The repository now has the file in the targets metadata
    # and the file is ready for download. The client updates.
    client.refresh(init_data)

    # Check that the remote file is the one we expect before
    # the client downloads.
    assert os.path.isfile(target_file_path)
    with open(target_file_path) as f:
        assert f.read() == file_contents_str

    # Check that the client has not downloaded any files yet
    assert client.get_last_downloaded_target() == ""

    # Client downloads the file by referencing the name specified
    # in the targets metadata.
    url_prefix = get_url_prefix(server_process_handler, client)
    target_file2 = client.download_target(init_data,
                                          target_base_name,
                                          target_base_url=url_prefix)
    # Sanity check that the client has downloaded the file
    assert client.get_last_downloaded_target() == os.path.join(client._target_dir.name,
                                                               target_base_name)

    # Check that the file the client download is the expected.
    with open(client.get_last_downloaded_target(), "r") as last_download_file:
        assert last_download_file.read() == file_contents_str

    # Now we replace the remote file with an incorrect one.
    # Here we test that even though the repos targets
    # metadata is bumped, the client still checks the hashes
    # and length of files before downloading files.

    # Create a file in the repo with the same name but different contents
    # The client should not download this.
    malicious_file_contents_str = "malicious data - should not download"
    new_target_file = open(target_file_path, 'w')
    new_target_file.write(malicious_file_contents_str)
    new_target_file.close()

    # Update target version target to repository without
    # updating the file hashes and length
    repo.targets.version += 1
    repo.update_snapshot()

    # Client updates
    client.refresh(init_data)

    # Client downloads the same file as it did earlier.
    client.download_target(init_data,
                           target_base_name,
                           target_base_url=url_prefix)

    # Now we check that the client has not downloaded the
    # malicious file which is expected. We check the
    with open(client.get_last_downloaded_target(), "r") as last_download_file:
        assert last_download_file.read() == file_contents_str


def test_repository_substitutes_target_file_and_bumps_10_times(
    client: ClientRunner, server: SimulatorServer
) -> None:
    """This test is similar to test_repository_substitutes_target_file
    but after the repository has added the malicious file, it does
    many changes such as rotates the root and bumps the metadata,
    and it makes these changes 10 times. After each round of changes,
    the client downloads the target file and asserts that it is has
    not downloaded the tampered file."""
    init_data, repo = server.new_test(client.test_name)

    assert client.init_client(init_data) == 0
    server_process_handler = utils.TestServerProcess(log=utils.logger)

    # Create legitimate target file that the client should receive
    # when the client downloads. The client should never download
    # any other file than this one.
    file_contents = b"legitimate data"
    target_base_name = "target_file.txt"
    target_file_path = os.path.join(client._remote_target_dir.name,
                                    target_base_name)
    target_file = open(target_file_path, 'w')
    target_file.write(file_contents.decode())
    target_file.close()

    # Add the file to the targets metadata.
    target = TestTarget()
    target.path = target_base_name
    target.content = file_contents

    # Add target to repository
    repo.add_target_with_length("targets", target)

    # Bump repo targets and snapshot metadata
    repo.targets.version += 1
    repo.update_snapshot()

    # Client updates.
    client.refresh(init_data)

    # Sanity check that we have not downloaded any files yet
    assert client.get_last_downloaded_target() == ""

    # Download the file created and added above.
    url_prefix = get_url_prefix(server_process_handler, client)

    target_file2 = client.download_target(init_data,
                                          target_base_name,
                                          target_base_url=url_prefix)
    # Sanity check that we downloaded the file
    assert client.get_last_downloaded_target() == os.path.join(client._target_dir.name,
                                                               target_base_name)

    # Check that the client downloaded the correct file.
    with open(client.get_last_downloaded_target(), "r") as last_download_file:
        assert last_download_file.read() == file_contents.decode()

    # Now we consider the repository to be corrupted, and it now attempts
    # to make the client download a malicious file that is not the one
    # that the targets metadata defines. As such, the repository attempts
    # this by making several changes to the metadata, but it does not
    # change the hashes and the length of the file.

    # Replace the legitimate file by the malicious in the remote file store
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

        # The client refreshes
        client.refresh(init_data)

        # Sanity check that the remote malicious file exists
        # in the location that the client would download from
        assert os.path.isfile(target_file_path)
        with open(target_file_path) as f:
            assert f.read() == malicious_file_contents_str
        client.download_target(init_data,
                               target_base_name,
                               target_base_url=url_prefix)
        # Verify that the client did not download a new file
        with open(client.get_last_downloaded_target(), "r") as last_download_file:
            assert last_download_file.read() == file_contents.decode()


def test_multiple_changes_to_target(
    client: ClientRunner, server: SimulatorServer
) -> None:
    """This test first creates a legitimate target file and adds
    it to both the repo file store and metadata. The client then
    updates and downloads the file. The test then invokes a process
    10 times where:
    1. the repo updates the file in a legitimate manner
    2. the client updates the metadata and downloads the new
       legitimate target file.
    3. the repository creates a new target file with the same
       name as the legitimate one and updates the metadata but
       without updating file hashes and length.
    4. the client updates and downloads the file again.
    5. the test checks that the client has not downloaded
       the malicious file created in step 3."""
    init_data, repo = server.new_test(client.test_name)

    assert client.init_client(init_data) == 0
    server_process_handler = utils.TestServerProcess(log=utils.logger)

    file_contents = b"legitimate data"
    target_base_name = "target_file.txt"

    # Create, upload and update a legitimate target file
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

    # Repo bumps targets version and snapshot
    repo.targets.version += 1
    repo.update_snapshot()

    # Client updates
    client.refresh(init_data)

    # Sanity check that we have not downloaded any files yet
    assert client.get_last_downloaded_target() == ""

    # Client downloads the file
    url_prefix = get_url_prefix(server_process_handler, client)
    target_file2 = client.download_target(init_data,
                                          target_base_name,
                                          target_base_url=url_prefix)
    # Sanity checks that we downloaded the file and that it is the correct one
    # check filename
    assert client.get_last_downloaded_target() == os.path.join(client._target_dir.name,
                                                               target_base_name)
    # check file contents
    with open(client.get_last_downloaded_target(), "r") as last_download_file:
        assert file_contents.decode() == last_download_file.read()

    # Now the repository makes 10 changes to the targets metadata.
    # It modifies the targets file in the targets metadata including
    # the hashes and length, and it also makes the corresponding
    # content changes in the file itself. As such, the client
    # should download the file
    for i in range(10):
        # Create the file with the contents the repo will update to.
        new_file_contents = f"{file_contents.decode()}-{i}"

        # Save the new file
        target_file = open(target_file_path, 'w+')
        target_file.write(new_file_contents)
        target_file.close()

        # Bump targets in the repo
        repo.targets.version += 1

        # Add a new target in the target repo
        target = TestTarget()
        target.path = target_base_name
        target.content = bytes(new_file_contents, 'utf-8')
        repo.add_target_with_length("targets", target)

        # Bump repo snapshot
        repo.update_snapshot()

        # Client updates
        client.refresh(init_data)

        # Before the client downloads, check
        # that the fileis the one we expect
        assert os.path.isfile(target_file_path)
        with open(target_file_path) as f:
            assert f.read() == new_file_contents

        # The client now correctly downloads the new target file
        client.download_target(init_data,
                               target_base_name,
                               target_base_url=url_prefix)

        # Check that the client downloaded the file
        with open(client.get_last_downloaded_target(), "r") as last_download_file:
            assert last_download_file.read() == new_file_contents

        # The repository now creates a malicious file on with the
        # same name a the legitimate file and bumps the targets
        # and root metadata.
        malicious_file_contents_str = f"malicious-file-contents-{i}"
        new_target_file = open(target_file_path, 'w+')
        new_target_file.write(malicious_file_contents_str)
        new_target_file.close()
        repo.targets.version += 1
        repo.bump_root_by_one()

        assert os.path.isfile(target_file_path)
        with open(target_file_path) as f:
            assert f.read() == malicious_file_contents_str

        # Client downloads
        client.download_target(init_data,
                               target_base_name,
                               target_base_url=url_prefix)
        # Check that the client did not download the malicious file
        with open(client.get_last_downloaded_target(), "r") as last_download_file:
            assert new_file_contents == last_download_file.read()
