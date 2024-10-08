# Developing tests for tuf-conformance

tuf-conformance test development requires a basic understanding of TUF metadata mechanisms.
Everything else should be explained in this document.

**Table of contents**

* [Useful helper classes](#useful-helper-classes)
  * [RepositorySimulator](#repositorysimulator)
  * [ClientRunner](#measuring-client-actions-with-clientrunner)
* [Debugging](#debugging)
* [Practical example](#practical-example)


## Useful helper classes

A typical test setup looks like this:

```python
def test_example(client: ClientRunner, server: SimulatorServer) -> None:
    """example test"""
    init_data, repo = server.new_test(client.test_name)
    client.init_client(init_data)

    # Use repo (RepositorySimulator) to setup the repository the test needs,
    # Use client (ClientRunner) to control and measure the clients actions
```

Let's look at how to use `RepositorySimulator` to build the test repository and `ClientRunner`
to control and measure the client-under-test.

### RepositorySimulator

Most tests in tuf-conformance use `RepositorySimulator`, a in-memory TUF repository implementation
designed for this test suite. It makes common repository actions fairly easy but still allows
tests to meddle with the repository in ways that are not spec-compliant.

#### Modifying repository content

"Current" metadata is stored in `repo.mds` dictionary but typically modifications are done via
helper properties like `repo.root.version = 99`. There are also helper methods to make tests a
easier to write:
* `repo.add_key()`: Modifies the delegation adding a signing key for the role. The private
    key is stored in `repo.signers` and will be automatically used when the role is signed
* `repo.add_delegation()`: Adds a new delegation, and the delegated roles metadata
* `repo.add_artifact()`: Adds a new artifact (or modifies an existing one)

Modifications are **not** visible to clients until they are published with `repo.publish()`.

#### Publishing metadata to make it available to client

Metadata changes must be explicitly made available to clients (with the exception of first
versions of the top level metadata roles: RepositorySimulator publishes those at
initialization). As an example, here we publish new versions of a delegated role "somerole"
as well as snapshot and timestamp roles:

```python
repo.publish(["somerole", Snapshot.type, Timestamp.type])
```

Publishing will bump the version number in the roles metadata, sign the metadata and store a
copy of the serialized bytes in `repo.signed_mds` (which is where clients will be served data
from).

Publishing has two side-effects:
* publishing any targets role will update that roles data in `repo.snapshot.meta`
* publishing snapshot role will update snapshot data in `repo.timestamp.snapshot_meta`

This makes the default case shown above work out of the box: Publishing "somerole" updates
snapshot so it's ready for publishing and publishing snapshot updates timestamp so it's ready
for publishing.

In some cases tests will want to modify the published, signed metadata: Tests can modify bytes in
`repo.signed_mds` at will.

### Measuring client actions with ClientRunner

The tests can control the client-under-test by calling `client.refresh()` and
`client.download_target()`. There are a few different ways of measuring if the client did the right
thing:
1. Return value of `client.refresh()` and `client.download_target()`: See [CLIENT-CLI](CLIENT-CLI.md)
1. Clients trusted metadata state
   * `client.version(Root.type) == 1`
   * `client.trusted_roles() == [(Root.type, 1), (Timestamp.type, 1)]`
3. What requests the client made: `repo.metadata_statistics` and `repo.artifact_statistics`. Note
   that these are requests so may include 404s

## Debugging

The test suite produces a debug dump of the test repositories (into `/tmp/tuf-conformance-dump`
by default), this can be very useful in ensuring the test repository looks as expected.
* Each test gets one repository dump for every client refresh/download
* The dump contains the _repository state_ at the time of the client refresh/download

## Practical example

Let's say we want to test to ensure clients do not accept a root version 4 when they requested
"3.root.json". We start with a simple skeleton test that sets up a repository and runs client
refresh against it:

```python
def test_root_version_mismatch(
    client: ClientRunner, server: SimulatorServer
) -> None:
    init_data, repo = server.new_test(client.test_name)
    client.init_client(init_data)

    # publish a valid root v2
    repo.publish([Root.type])

    # Run refresh on client-under-test
    client.refresh(init_data)
```

We can now run the test suite:

```bash
make test-go-tuf

# take a look at the repository 1.root.json that got debug dumped
cat /tmp/tuf-conformance-dump/test_root_version_mismatch/refresh-1/2.root.json
```

The metadata looks as expected: There is a 2.root.json and it contains `version: 2`. We now add
code that serves an incorrect version number:

```python
    # publish a 3.root.json but make it contain the field "version: 4"
    # Use verify_version=False to override the safety check for this
    repo.root.version += 1
    repo.publish([Root.type], verify_version=False)

    # Run refresh on client-under-test again
    client.refresh(init_data)
```

Running the test suite again results in a second repository version being dumped (each client
refresh leads to a dump):
```bash
make test-go-tuf

# take a look at repository root versions during the second refresh
cat /tmp/tuf-conformance-dump/test_root_version_mismatch/refresh-2/3.root.json
```

The repository metadata looks as expected (but not spec-compliant) as the version field in the metadata is 4.
We can now add some asserts for client behaviour to get the final test:

```python
def test_root_version_mismatch(
    client: ClientRunner, server: SimulatorServer
) -> None:
    init_data, repo = server.new_test(client.test_name)
    client.init_client(init_data)

    # publish a valid root v2
    repo.publish([Root.type])

    # Run successful client refresh
    assert client.refresh(init_data) == 0

    # publish a 3.root.json but make it contain the field "version: 4"
    # Use verify_version=False to override the safety check for this
    repo.root.version += 1
    repo.publish([Root.type], verify_version=False)

    # Run client refresh again: expect failure, expect clients trusted root to be v2
    assert client.refresh(init_data) == 1
    assert client.version(Root.type) == 2
```
