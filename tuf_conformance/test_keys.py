import json
import os

from tuf_conformance.repository_simulator import RepositorySimulator
from tuf_conformance.simulator_server import SimulatorServer, ClientInitData
from tuf_conformance.client_runner import ClientRunner
from securesystemslib.signer import CryptoSigner

from tuf.api.metadata import (
    Timestamp, Snapshot, Root, Targets, Metadata
)

from tuf_conformance.utils import meta_dict_to_bytes

def initial_setup_for_key_threshold_edge_cases(client: ClientRunner,
                                               repo: RepositorySimulator,
                                               init_data: ClientInitData) -> None:
    # Explicitly set the threshold
    new_root = repo.load_metadata(Root.type)
    new_root.signed.roles[Snapshot.type].threshold = 3
    repo.save_metadata(Root.type, new_root)
    repo.bump_root_by_one()

    # Add a legitimate key:
    repo.add_key_to_role(Snapshot.type)
    repo.update_timestamp()
    repo.update_snapshot()
    repo.bump_root_by_one()

    assert client.refresh(init_data) == 1

    # Add a legitimate key:
    repo.add_key_to_role(Snapshot.type)
    repo.add_key_to_role(Snapshot.type)
    repo.update_timestamp()
    repo.update_snapshot()
    repo.bump_root_by_one()

    assert len(json.loads(repo.md_root_json)["signed"]["roles"][Snapshot.type]["keyids"]) == 4
    assert len(json.loads(repo.md_snapshot_json)["signatures"]) == 3

    assert client.refresh(init_data) == 0
    assert client._version_equals(Snapshot.type, 3)
    assert client._version_equals(Root.type, 4)

def test_root_has_keys_but_not_snapshot(client: ClientRunner,
                        server: SimulatorServer) -> None:
    """This test adds keys to the repo root MD to test for cases
    where are client might calculate the threshold from only the
    roots keys and not check that the snapshot MD has the same
    keys"""
    name = "test_root_has_keys_but_not_snapshot"

    # initialize a simulator with repository content we need
    repo = RepositorySimulator()
    server.repos[name] = repo
    init_data = server.get_client_init_data(name)
    assert client.init_client(init_data) == 0
    client.refresh(init_data)
    # Sanity checks
    assert client._files_exist([Root.type,
                                       Timestamp.type,
                                       Snapshot.type,
                                       Targets.type])
    assert client._version_equals(Snapshot.type, 1)
    assert len(json.loads(repo.md_snapshot_json)["signatures"]) == 0

    initial_setup_for_key_threshold_edge_cases(client, repo, init_data)

    # Increase the threshold
    new_root = repo.load_metadata(Root.type)
    new_root.signed.roles[Snapshot.type].threshold = 5
    repo.save_metadata(Root.type, new_root)
    repo.bump_root_by_one()

    # Updating should fail. Root should bump, but not snapshot
    assert client.refresh(init_data) == 1
    assert client._version_equals(Root.type, 5)
    assert client._version_equals(Snapshot.type, 3)

    # Add two invalid keys only to root and expect the client
    # to fail updating
    signer = CryptoSigner.generate_ecdsa()

    root = json.loads(repo.md_root_json)
    root["signed"]["roles"]["snapshot"]["keyids"].append(signer.public_key.keyid)
    repo.md_root_json = meta_dict_to_bytes(root)
    # Number of keys == threshold, but it is faulty, so it should not update
    assert len(json.loads(repo.md_root_json)["signed"]["roles"][Snapshot.type]["keyids"]) == 5

    # Updating should fail. Root should bump, but not snapshot
    assert client.refresh(init_data) == 1
    assert client._version_equals(Root.type, 5)
    assert client._version_equals(Snapshot.type, 3)
    assert len(json.loads(repo.md_snapshot_json)["signatures"]) == 3

# prefixed with "T" to not run in CI.
def Ttest_wrong_keytype_and_scheme(client: ClientRunner,
                        server: SimulatorServer) -> None:
    """Does the following:
    1. Create 5 valid keys
    2. Verify that the client can update
    3. Change the scheme of one key
    4. Verify that the client cannot update
    5. Change the keytype of one key to match the wrong scheme
    6. Verify that the client cannot update
    7. Lower the threshold so the root metadata has enough
       valid keys. 
    8. Verify that the client can update

    This tests a case where root version N is invalid but
    root version N+1 is valid. We expect that the client
    should update to root version N+1, but some clients
    may fail because of root version N"""

    name = "test_wrong_keytype_and_scheme"

    # initialize a simulator with repository content we need
    repo = RepositorySimulator()
    server.repos[name] = repo
    init_data = server.get_client_init_data(name)
    assert client.init_client(init_data) == 0
    client.refresh(init_data)
    # Sanity checks
    assert client._files_exist([Root.type,
                                       Timestamp.type,
                                       Snapshot.type,
                                       Targets.type])
    assert client._version_equals(Snapshot.type, 1)
    assert len(json.loads(repo.md_snapshot_json)["signatures"]) == 0

    initial_setup_for_key_threshold_edge_cases(client, repo, init_data)

    # Increase the threshold
    new_root = repo.load_metadata(Root.type)
    new_root.signed.roles[Snapshot.type].threshold = 5
    repo.save_metadata(Root.type, new_root)
    repo.bump_root_by_one()

    repo.add_key_to_role(Snapshot.type)
    repo.update_timestamp()
    repo.update_snapshot()
    repo.bump_root_by_one()

    # Sanity check that we have 5 keys. They are all
    # valid at this point
    assert len(json.loads(repo.md_root_json)["signed"]
                                            ["roles"]
                                            [Snapshot.type]
                                            ["keyids"]) == 5

    # Updating should succeed because there are now
    # 5 valid keys
    assert client.refresh(init_data) == 0
    assert client._version_equals(Root.type, 6)
    assert client._version_equals(Snapshot.type, 4)

    # Copy the correct keytype/scheme, so we can restore later
    valid_key = json.loads(repo.md_root_json)["signed"]["roles"][Snapshot.type]["keyids"][0]
    copy_root_md = json.loads(repo.md_root_json)
    correct_scheme = copy.deepcopy(copy_root_md["signed"]
                                               ["keys"]
                                               [valid_key]
                                               ["scheme"])
    correct_keytype = copy.deepcopy(copy_root_md["signed"]
                                                ["keys"]
                                                [valid_key]
                                                ["keytype"])

    # Change scheme to a valid but wrong one
    # Sanity check that the current scheme is not "rsa"
    assert correct_scheme != "rsa"
    new_root_md = json.loads(repo.md_root_json)
    new_root_md["signed"]["keys"][valid_key]["scheme"] = "rsa"
    repo.save_metadata_bytes(Root.type, meta_dict_to_bytes(new_root_md))
    assert (json.loads(repo.md_root_json)["signed"]
                                         ["keys"]
                                         [valid_key]
                                         ["scheme"]) == "rsa"

    # Update and fail
    assert client.refresh(init_data) == 1
    assert client._version_equals(Root.type, 6) # TODO verify: Should root update here?
    assert client._version_equals(Snapshot.type, 4)

    # Set the threshold so low that we have enough valid keys
    # At this point the repo root MD has 5 keys of which 1 is
    # invalid.
    new_root_md = json.loads(repo.md_root_json)
    new_root_md["signed"]["roles"][Snapshot.type]["threshold"] = 1
    repo.md_root_json = meta_dict_to_bytes(new_root_md)
    repo.update_timestamp()
    repo.update_snapshot()
    repo.bump_root_by_one()    

    # We should fail because the scheme is wrong
    assert client.refresh(init_data) == 1
    assert client._version_equals(Root.type, 6)
    assert client._version_equals(Snapshot.type, 4)

    # Also change the keytype to rsa    
    # Sanity check that the current keytype is not "rsa"
    assert correct_keytype != "rsa"
    new_root_md = json.loads(repo.md_root_json)
    new_root_md["signed"]["keys"][valid_key]["keytype"] = "rsa"
    repo.save_metadata_bytes(Root.type, meta_dict_to_bytes(new_root_md))
    assert (json.loads(repo.md_root_json)["signed"]
                                         ["keys"]
                                         [valid_key]
                                         ["keytype"]) == "rsa"
    repo.bump_root_by_one()

    # We should fail because the scheme and keytype are wrong
    assert client.refresh(init_data) == 1
    assert client._version_equals(Root.type, 6) # TODO verify: Should root update here?
    assert client._version_equals(Snapshot.type, 4)
    
    # Set the keytype and scheme back to the correct format. The root MD
    # is now identical to the last root MD that the client updated
    new_root_md = json.loads(repo.md_root_json)
    new_root_md["signed"]["keys"][valid_key]["keytype"] = correct_keytype
    new_root_md["signed"]["keys"][valid_key]["scheme"] = correct_scheme
    repo.save_metadata_bytes(Root.type, meta_dict_to_bytes(new_root_md))
    assert (json.loads(repo.md_root_json)["signed"]
                                         ["keys"]
                                         [valid_key]
                                         ["keytype"]) == correct_keytype
    assert (json.loads(repo.md_root_json)["signed"]
                                         ["keys"]
                                         [valid_key]
                                         ["scheme"]) == correct_scheme
    repo.bump_root_by_one()

    # Here we expect that the client updates because the repo
    # has a valid version of the root MD that the client has
    # not downloaded. A reason a client might fail here is 
    # because the repo has an invalid root MD version
    # before the valid one. The tricky part here is that
    # there are enough valid keys but a single invalid that
    # will fail key validation. 
    assert client.refresh(init_data) == 0
    assert client._version_equals(Root.type, 8)
    assert client._version_equals(Snapshot.type, 4)

# prefixed with "T" to not run in CI.
def Ttest_key_with_invalid_scheme(client: ClientRunner,
                        server: SimulatorServer) -> None:
    """Sets the scheme for a key for snapshot MD in root
    to an invalid one and expects the client to update
    root but not snapshot"""
    name = "test_key_with_invalid_scheme"

    # initialize a simulator with repository content we need
    repo = RepositorySimulator()
    server.repos[name] = repo
    init_data = server.get_client_init_data(name)
    assert client.init_client(init_data) == 0
    client.refresh(init_data)
    # Sanity checks
    assert client._files_exist([Root.type,
                                       Timestamp.type,
                                       Snapshot.type,
                                       Targets.type])
    assert client._version_equals(Snapshot.type, 1)
    assert len(json.loads(repo.md_snapshot_json)["signatures"]) == 0

    initial_setup_for_key_threshold_edge_cases(client, repo, init_data)

    # Increase the threshold
    new_root = repo.load_metadata(Root.type)
    new_root.signed.roles[Snapshot.type].threshold = 5
    repo.save_metadata(Root.type, new_root)
    repo.bump_root_by_one()

    # Updating should fail. Root should bump, but not snapshot
    assert client.refresh(init_data) == 1
    assert client._version_equals(Root.type, 5)
    assert client._version_equals(Snapshot.type, 3)
    # Change scheme
    valid_key = json.loads(repo.md_root_json)["signed"]["roles"][Snapshot.type]["keyids"][0]
    new_root_md = json.loads(repo.md_root_json)
    new_root_md["signed"]["keys"][valid_key]["scheme"] = "invalidScheme"
    repo.save_metadata_bytes(Root.type, meta_dict_to_bytes(new_root_md))
    assert json.loads(repo.md_root_json)["signed"]["keys"][valid_key]["scheme"] == "invalidScheme"

    # Root should bump, but not snapshot
    assert client.refresh(init_data) == 1
    assert client._version_equals(Root.type, 5) # TODO: DOUBLE CHECK
    assert client._version_equals(Snapshot.type, 3)

    repo.bump_root_by_one()

    # Updating should fail.
    assert client.refresh(init_data) == 1
    assert client._version_equals(Root.type, 6) # TODO: Double check this
    assert client._version_equals(Snapshot.type, 3)

def test_wrong_hashing_algorithm(client: ClientRunner,
                        server: SimulatorServer) -> None:
    """This test sets a wrong but valid hashing algorithm for a key
    in the root MD. The client should not care and still update"""

    name = "test_wrong_hashing_algorithm"

    # initialize a simulator with repository content we need
    repo = RepositorySimulator()
    server.repos[name] = repo
    init_data = server.get_client_init_data(name)
    assert client.init_client(init_data) == 0
    client.refresh(init_data)
    # Sanity checks
    assert client._files_exist([Root.type,
                                Timestamp.type,
                                Snapshot.type,
                                Targets.type])
    assert client._version_equals(Snapshot.type, 1)
    assert len(json.loads(repo.md_snapshot_json)["signatures"]) == 0

    initial_setup_for_key_threshold_edge_cases(client, repo, init_data)

    assert client.refresh(init_data) == 0
    assert client._version_equals(Root.type, 4)
    assert client._version_equals(Snapshot.type, 3)

    assert len(json.loads(repo.md_root_json)["signed"]
                                            ["roles"]
                                            [Snapshot.type]
                                            ["keyids"]) == 4

    # Increase the threshold
    new_root = repo.load_metadata(Root.type)
    new_root.signed.roles[Snapshot.type].threshold = 5
    repo.save_metadata(Root.type, new_root)
    repo.bump_root_by_one() # v5

    # Verify that the client cannot update snapshot 
    # because it has 4 keys and the threshold is 5.
    # This is mostly a sanity check.
    assert client.refresh(init_data) == 1
    assert client._version_equals(Root.type, 5)
    assert client._version_equals(Snapshot.type, 3)

    # Add a valid key and bump
    repo.add_key_to_role(Snapshot.type)
    repo.update_timestamp()
    repo.update_snapshot() # v4
    repo.bump_root_by_one() # v6

    # Verify that the client can update before making
    # the metadata faulty
    assert client.refresh(init_data) == 0
    assert client._version_equals(Root.type, 6)
    assert client._version_equals(Snapshot.type, 4)

    # Change hashing algorithm of a valid key
    # Let's bump so that the client sees there are updates.
    # Note that we change the hashing algorithm after bumping
    repo.update_timestamp()
    repo.update_snapshot() # v5
    repo.bump_root_by_one() # v7
    valid_key = json.loads(repo.md_root_json)["signed"]["roles"][Snapshot.type]["keyids"][0]
    new_root_md = json.loads(repo.md_root_json)
    new_root_md["signed"]["keys"][valid_key]["keyid_hash_algorithms"] = []
    new_root_md["signed"]["keys"][valid_key]["keyid_hash_algorithms"].append("md5")
    repo.save_metadata_bytes(Root.type, 
                             meta_dict_to_bytes(new_root_md))

    # Make sure the repo has the wrong algorithm:
    assert (json.loads(repo.md_root_json)["signed"]
                                         ["keys"]
                                         [valid_key]
                                         ["keyid_hash_algorithms"]) == ["md5"]
    repo.bump_root_by_one() # v8

    # Make sure again that the repo has the wrong algorithm:
    assert (json.loads(repo.md_root_json)["signed"]
                                         ["keys"]
                                         [valid_key]
                                         ["keyid_hash_algorithms"]) == ["md5"]

    # Root should update, but snapshot should not because the
    # 'keyid_hash_algorithms' is wrong. 
    assert client.refresh(init_data) == 0 # TODO: DOUBLE CHECK THIS IS CORRECT
    assert client._version_equals(Root.type, 8) # TODO: DOUBLE CHECK THIS IS CORRECT
    assert client._version_equals(Snapshot.type, 5) # TODO: DOUBLE CHECK THIS IS CORRECT



def test_simple_signing(client: ClientRunner,
                        server: SimulatorServer) -> None:
    # Tests that add_key_to_role works as intended

    name = "test_simple_signing"

    # initialize a simulator with repository content we need
    repo = RepositorySimulator()
    server.repos[name] = repo
    init_data = server.get_client_init_data(name)
    assert client.init_client(init_data) == 0
    client.refresh(init_data)
    # Sanity checks
    assert client._files_exist([Root.type,
                                       Timestamp.type,
                                       Snapshot.type,
                                       Targets.type])
    assert client._version_equals(Snapshot.type, 1)

    # Add signature to Snapshot
    repo.add_key_to_role(Snapshot.type)
    repo.add_key_to_role(Snapshot.type)
    repo.add_key_to_role(Snapshot.type)

    repo.bump_root_by_one()

    repo.update_timestamp()
    repo.update_snapshot()

    assert client.refresh(init_data) == 0

    # There should be 4 snapshot signatures in the clients metadata
    md_obj = Metadata.from_file(
        os.path.join(client.metadata_dir, "root.json")).signed
    md_obj2 = Metadata.from_file(
        os.path.join(client.metadata_dir, "snapshot.json"))
    assert len(md_obj.roles[Snapshot.type].keyids) == 4
    assert len(md_obj2.signatures) == 4

    # Add another signature
    repo.add_key_to_role(Snapshot.type)
    repo.bump_root_by_one()

    # Sanity check
    repo_root = repo.load_metadata(Root.type)
    assert len(repo_root.signed.roles["snapshot"].keyids) == 5

    repo.update_timestamp()
    repo.update_snapshot()

    assert client.refresh(init_data) == 0

    # There should be 5 snapshot signatures in the clients metadata
    md_obj = Metadata.from_file(
        os.path.join(client.metadata_dir, "root.json")).signed
    md_obj2 = Metadata.from_file(
        os.path.join(client.metadata_dir, "snapshot.json"))
    assert len(md_obj.roles[Snapshot.type].keyids) == 5
    assert len(md_obj2.signatures) == 5

    # Test 1:
    # Set higher threshold than we have keys. Should fail
    new_root = repo.load_metadata(Root.type)
    new_root.signed.roles[Snapshot.type].threshold = 10
    repo.save_metadata(Root.type, new_root)
    initial_root_version = new_root.signed.version

    repo.bump_root_by_one()
    repo.update_timestamp()
    repo.update_snapshot()
    client.refresh(init_data)

    # Ensure that client does not refresh
    assert client.refresh(init_data) == 1
    assert client._version_equals(Snapshot.type, initial_root_version)


# Set/keep a threshold of 10 keys. All the keyids are different,
# but the keys are all identical. As such, the snapshot metadata
# has been signed by 1 key.
def test_duplicate_keys_root(client: ClientRunner,
                             server: SimulatorServer) -> None:
    # Tests that add_key_to_role works as intended

    name = "test_duplicate_keys_root"

    # initialize a simulator with repository content we need
    repo = RepositorySimulator()
    server.repos[name] = repo
    init_data = server.get_client_init_data(name)
    assert client.init_client(init_data) == 0
    client.refresh(init_data)
    # Sanity checks
    assert client._files_exist([Root.type,
                                       Timestamp.type,
                                       Snapshot.type,
                                       Targets.type])
    assert client._version_equals(Snapshot.type, 1)

    # Add the same signature to Snapshot 9 times in the repository
    repo.add_one_role_key_n_times_to_root(Snapshot.type, 9)
    repo.bump_root_by_one()
    ss_obj = json.loads(repo.md_root_json)
    assert len(ss_obj["signed"]["roles"]["snapshot"]["keyids"]) == 10
    
    repo.update_timestamp()
    repo.update_snapshot()

    # This should fail because the metadata should not have
    # the same key in more than 1 keyids. We check failure
    # here, and further down we check that the clients
    # metadata has not been updated.
    client.refresh(init_data)

    # Verify that the client has not updated its metadata
    try:
        md_root = Metadata.from_file(
            os.path.join(client.metadata_dir, "root.json")).signed
    except DeserializationError as e:
        assert False, "The client has updated its local root metadata with corrupted data"

    try:
        md_snapshot = Metadata.from_file(
            os.path.join(client.metadata_dir, "snapshot.json"))
    except DeserializationError as e:
        assert False, "The client has updated its local root metadata with corrupted data"

    md_root = Metadata.from_file(
            os.path.join(client.metadata_dir, "root.json")).signed
    md_snapshot = Metadata.from_file(
        os.path.join(client.metadata_dir, "snapshot.json"))

    # TODO: Double check that "1" is correct here:
    assert len(md_root.roles[Snapshot.type].keyids) == 1
    # TODO: Double check that "1" is correct here:
    assert len(md_snapshot.signatures) == 1