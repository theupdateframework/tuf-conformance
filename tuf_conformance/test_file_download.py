import pytest
from tuf.api.metadata import Root, Snapshot, TargetFile, Targets, Timestamp

from tuf_conformance.client_runner import ClientRunner
from tuf_conformance.repository_simulator import Artifact
from tuf_conformance.simulator_server import SimulatorServer


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
    repo.add_artifact(Targets.type, target_content, target_path)
    repo.publish([Targets.type, Snapshot.type, Timestamp.type])

    # Client updates, sanity check that nothing was downloaded
    assert client.refresh(init_data) == 0
    assert client.get_downloaded_target_bytes() == []

    assert client.download_target(init_data, target_path) == 0
    assert client.get_downloaded_target_bytes() == [target_content]


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
    repo.add_artifact(Targets.type, target_content, target_path)
    repo.publish([Targets.type, Snapshot.type, Timestamp.type])

    assert client.download_target(init_data, target_path) == 0
    assert client.get_downloaded_target_bytes() == [target_content]


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
    repo.add_artifact(Targets.type, target_content_1, target_path_1)
    repo.add_artifact(Targets.type, target_content_2, target_path_2)
    repo.publish([Targets.type, Snapshot.type, Timestamp.type])

    # Download one of the artifacts
    assert client.download_target(init_data, target_path_1) == 0
    assert client.get_downloaded_target_bytes() == [target_content_1]

    # Change both artifact contents that repository serves
    malicious_content = b"malicious data - should not download"
    repo.artifacts[target_path_1].data = malicious_content
    repo.artifacts[target_path_2].data = malicious_content

    # ask client to download again
    # NOTE: this may succeed (if client cached the artifact and never re-downloads)
    # or it might fail (if client downloads the new artifact and realizes it is invalid)
    client.download_target(init_data, target_path_1)

    # assert the client did not accept the malicious artifact
    assert client.get_downloaded_target_bytes() == [target_content_1]

    # ask client to download the other artifact and expect failure
    assert client.download_target(init_data, target_path_2) == 1

    # assert the client did not store the malicious artifact
    assert client.get_downloaded_target_bytes() == [target_content_1]


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
    repo.add_artifact(Targets.type, target_content, target_path)
    repo.publish([Targets.type, Snapshot.type, Timestamp.type])

    # Client downloads the file
    assert client.download_target(init_data, target_path) == 0
    # check file contents
    expected_downloads = [target_content]
    previous_content = target_content
    assert client.get_downloaded_target_bytes() == expected_downloads

    # Now the repository makes 10 changes to the targets metadata.
    # It modifies the targets file in the targets metadata including
    # the hashes and length, and it also makes the corresponding
    # content changes in the file itself.
    for i in range(11):
        # Modify the existing artifact legitimately:
        modified_contents = f"modified file contents {i}".encode()
        repo.add_artifact(Targets.type, modified_contents, target_path)
        # Add a completely new artifact
        new_file_contents = f"new file contents {i}".encode()
        new_target_path = f"new-target-{i}"
        repo.add_artifact(Targets.type, new_file_contents, new_target_path)
        repo.targets.version += 1

        # Bump repo snapshot
        repo.update_snapshot()
        repo.publish([Targets.type, Snapshot.type, Timestamp.type])
        # Client only sees every fifth targets version
        if i % 5 == 0:
            # Client downloads the modified artifact
            assert client.download_target(init_data, target_path) == 0
            # the previous content is no longer there, modified content is there
            expected_downloads.remove(previous_content)
            expected_downloads.append(modified_contents)
            previous_content = modified_contents
            assert client.get_downloaded_target_bytes() == expected_downloads

            # Client downloads the new artifact
            assert client.download_target(init_data, new_target_path) == 0
            expected_downloads.append(new_file_contents)

            # check downloaded contents
            assert client.get_downloaded_target_bytes() == expected_downloads

            # Modify artifact content without updating the hashes/length in metadata.
            malicious_file_contents = f"malicious contents {i}".encode()
            repo.artifacts[target_path].data = malicious_file_contents
            repo.targets.version += 1

            # Bump repo snapshot
            repo.update_snapshot()
            repo.publish([Targets.type, Snapshot.type, Timestamp.type])

            # ask client to download (this call may fail or succeed, see
            # test_repository_substitutes_target_file)
            client.download_target(init_data, target_path)

            # Check that the client did not download the malicious file
            assert client.get_downloaded_target_bytes() == expected_downloads


hash_algos = [
    ["sha256"],
    ["sha512"],
    ["sha256", "sha512"],
]


@pytest.mark.parametrize("hashes", hash_algos)
def test_download_with_hash_algorithms(
    client: ClientRunner, server: SimulatorServer, hashes: list[str]
) -> None:
    """Test support of hash algorithms. The specification does not require any
    specific algorithms, and only mentions sha256.

    Clients can use the .xfail file to mark tests as "expected to fail".
    """
    init_data, repo = server.new_test(client.test_name)

    # Create a legitimate test artifact
    target_path = "target_file.txt"
    target_content = b"target file contents"

    # Add target manually and not with repo.add_artifact() so we can choose hashes
    target = TargetFile.from_data(target_path, target_content, hashes)
    repo.targets.targets[target_path] = target
    repo.artifacts[target_path] = Artifact(target_content, target)
    repo.publish([Targets.type, Snapshot.type, Timestamp.type])
    repo.publish([Root.type], bump_version=True)

    assert client.init_client(init_data) == 0
    assert client.download_target(init_data, target_path) == 0

    # downloading using any of the hashes repository advertized is accepted:
    possible_dls = [(target_path, h) for h in target.hashes.values()]
    assert len(repo.artifact_statistics) == 1
    assert repo.artifact_statistics[0] in possible_dls
    assert client.get_downloaded_target_bytes() == [target_content]


def test_download_with_unknown_hash_algorithm(
    client: ClientRunner, server: SimulatorServer
) -> None:
    """Use an unknown hash algorithm: client should not accept the artifact"""
    init_data, repo = server.new_test(client.test_name)

    # Create a legitimate test artifact
    target_path = "target_file.txt"
    target_content = b"target file contents"

    # Add target manually, use a hash algorithm that does not exist
    # Use repo.add_artifact() so we can modify hashes
    target = TargetFile.from_data(target_path, target_content, ["sha512"])
    target.hashes["unknown-hash"] = target.hashes["sha512"]
    del target.hashes["sha512"]
    repo.targets.targets[target_path] = target
    repo.artifacts[target_path] = Artifact(target_content, target)
    repo.publish([Targets.type, Snapshot.type, Timestamp.type])

    assert client.init_client(init_data) == 0
    # Note that we allow the client to actually download the artifact from repo
    # and only then realize hash cannot be verified
    assert client.download_target(init_data, target_path) == 1
    assert client.get_downloaded_target_bytes() == []
