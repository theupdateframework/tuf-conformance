import pytest

from tuf.api.metadata import Targets

from tuf_conformance.simulator_server import SimulatorServer
from tuf_conformance.client_runner import ClientRunner


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

    # Create a test artifact, add it to the repository
    target_path = "target_file.txt"
    target_content = b"target file contents"
    repo.add_target(Targets.type, target_content, target_path)

    # Client updates, sanity check that nothing was downloaded
    assert client.refresh(init_data) == 0
    with pytest.raises(FileNotFoundError):
        client.get_last_downloaded_target()

    assert client.download_target(init_data, target_path) == 0

    # assert that the downloaded file contents are correct
    with open(client.get_last_downloaded_target(), "rb") as last_download_file:
        assert last_download_file.read() == target_content


def test_client_downloads_expected_file_in_sub_dir(
    client: ClientRunner, server: SimulatorServer
) -> None:
    """This test adds a file to the repository targets metadata with a targetpath that
    contains a directory. Client then refreshes, and downloads the target. Finally,
    the test asserts that the client downloaded the file and that the contents of the
    file are correct
    """
    init_data, repo = server.new_test(client.test_name)
    assert client.init_client(init_data) == 0

    # Create a test artifact, add it to the repository
    target_path = "path/to/a/target_file.txt"
    target_content = b"target file contents"
    repo.add_target(Targets.type, target_content, target_path)

    # Client updates, sanity check that nothing was downloaded
    assert client.refresh(init_data) == 0
    with pytest.raises(FileNotFoundError):
        client.get_last_downloaded_target()

    assert client.download_target(init_data, target_path) == 0

    # assert that the downloaded file contents are correct
    with open(client.get_last_downloaded_target(), "rb") as last_download_file:
        assert last_download_file.read() == target_content


def test_repository_substitutes_target_file(
    client: ClientRunner, server: SimulatorServer
) -> None:
    """Repository contains two valid artifacts. Client downloads one of them.
    Repository then replaces both artifacts with malicous data. Client
    tries to download both, test asserts that malicious data was not accepted
    """
    init_data, repo = server.new_test(client.test_name)
    assert client.init_client(init_data) == 0

    # Create legitimate test artifacts
    target_path_1 = "target_file.txt"
    target_content_1 = b"target file contents"
    target_path_2 = "another_target_file.txt"
    target_content_2 = b"content"
    repo.add_target(Targets.type, target_content_1, target_path_1)
    repo.add_target(Targets.type, target_content_2, target_path_2)

    # Client updates
    assert client.refresh(init_data) == 0

    # Download one of the artifacts
    assert client.download_target(init_data, target_path_1) == 0
    with open(client.get_last_downloaded_target(), "rb") as last_download_file:
        assert last_download_file.read() == target_content_1

    # Change both artifact contents that repository serves
    malicious_content = b"malicious data - should not download"
    repo.artifacts[target_path_1].data = malicious_content
    repo.artifacts[target_path_2].data = malicious_content

    # ask client to download again
    # NOTE: this may either succeed (if client cached the artifact and never tries to re-download)
    # or it might fail (if client downloads the new artifact and realizes it is invalid)
    client.download_target(init_data, target_path_1)

    # assert the client did not accept the malicious artifact
    with open(client.get_last_downloaded_target(), "rb") as last_download_file:
        assert last_download_file.read() == target_content_1

    # ask client to download the other artifact and expect failure
    assert client.download_target(init_data, target_path_2) == 1

    # assert the client did not store the malicious artifact
    with open(client.get_last_downloaded_target(), "rb") as last_download_file:
        assert last_download_file.read() == target_content_1


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

    # Create a legitimate test artifacts
    target_path = "target_file.txt"
    target_content = b"target file contents"
    repo.add_target(Targets.type, target_content, target_path)

    # Client updates
    assert client.refresh(init_data) == 0

    # Client downloads the file
    client.download_target(init_data, target_path)
    # check file contents
    with open(client.get_last_downloaded_target(), "rb") as last_download_file:
        assert last_download_file.read() == target_content

    # Now the repository makes 10 changes to the targets metadata.
    # It modifies the targets file in the targets metadata including
    # the hashes and length, and it also makes the corresponding
    # content changes in the file itself. As such, the client
    # should download the file
    for i in range(10):
        # Modify the artifact legitimately:
        new_file_contents = f"target file contents {i}".encode()
        repo.add_target(Targets.type, new_file_contents, target_path)
        repo.targets.version += 1

        # Bump repo snapshot
        repo.update_snapshot()

        # Client updates
        assert client.refresh(init_data) == 0

        # Client downloads the new file
        assert client.download_target(init_data, target_path) == 0
        # check file contents
        with open(client.get_last_downloaded_target(), "rb") as last_download_file:
            assert last_download_file.read() == new_file_contents

        # Modify the artifact content without updating the hashes/length in metadata.
        malicious_file_contents = f"malicious contents {i}".encode()
        repo.artifacts[target_path].data = malicious_file_contents
        repo.targets.version += 1

        # Bump repo snapshot
        repo.update_snapshot()

        # ask client to download (this may fail or succeed, see test_repository_substitutes_target_file)
        client.download_target(init_data, target_path)

        # Check that the client did not download the malicious file
        with open(client.get_last_downloaded_target(), "rb") as last_download_file:
            assert new_file_contents == last_download_file.read()
