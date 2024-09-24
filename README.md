# TUF conformance test suite

This is the repository of the conformance test suite for TUF clients. The goal of this
repository is to allow client developers to
  1. test their clients against the TUF specification
  2. Achieve better practical compatibility with other implementations
  3. Collaborate on tests with other client developers

- [Usage](#Usage)
- [Development](#Development)


## Usage

The conformance test suite provides a GitHub action that can be used to test a TUF client.
There are two required steps:

1. Include an executable in the client project that implements the client-under-test
   [CLI protocol](CLIENT-CLI.md).
2. Use the `theupdateframework/tuf-conformance` action in your test workflow:
    ```yaml
    jobs:
      tuf-conformance:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v4

          # insert possible client compilation/installation steps here

          - uses: theupdateframework/tuf-conformance@v1
            with:
              entrypoint: path/to/my/test/executable
    ```

### Expected failures

The test suite also contains tests that are not strictly speaking specification requirements (such as
tests for specific keytype or hash algorithm suport). Clients can mark tests as "expected failures"
if they do not intend to support this specific feature.

The tests that are expected to fail can be listed in `<entrypoint>.xfails` file. In the previous
workflow example the xfails file would be `path/to/my/test/executable.xfails`

## Development

This repository contains two client-under-test CLI protocol implementations
to enable easy development and testing. The test suite depends on various
python modules which will be installed by the make commands into a virtual environment.
The suite also depends on `faketime` tool which needs to be available.

```bash
# run test suite against both included clients or just one of them:
make test-all
make test-python-tuf
make test-go-tuf
```

It's also possible to locally run the test suite with a client-under-test CLI that is locally installed elsewhere:

```bash
make dev
./env/bin/pytest tuf_conformance --entrypoint path/to/my/client-under-test/cli
```

linters can also be invoked with make:
```bash
# Run linters
make lint
# Fix issues that can be automatically fixed
make fix
```


### Creating (and debugging) tests

Let's say we want to test that clients will not accept a decreasing targets version. We start with a simple skeleton test that sets up a repository and runs client refresh against it:

```python
def test_targets_version_rollback(
    client: ClientRunner, server: SimulatorServer
) -> None:
    # Initialize our repository: modify targets version and make sure it's included in snapshot
    init_data, repo = server.new_test(client.test_name)

    # initialize client-under-test
    client.init_client(init_data)
    # Run refresh on client-under-test, expect success
    assert client.refresh(init_data) == 0
```

We can now run the test:

```bash
./env/bin/pytest tuf_conformance \
    -k test_targets_version                 # run a specific test only
    --entrypoint "./clients/go-tuf/go-tuf"  # use the included go-tuf client as client-under-test
    --repository-dump-dir /tmp/test-repos   # dump repository contents

# take a look at the repository targets.json that got debug dumped
cat /tmp/test-repos/test_targets_version/refresh-1/targets.json
cat /tmp/test-repos/test_targets_version/refresh-1/snapshot.json
```

Now, the repository publishes Targets 6 times so that it is version 7. The client then refreshes and the test asserts that the client has Targets version 7. Next, the repository attempts a rollback attack; It attempts to make the client download metadata for the Targets role that is a lower version than the version the client already has. To do that, the test deletes the already published Targets and republishes 5 times. Now, the repositorys Targets version is 5. The test publishes Snapshot and Timestamp too so the client can see the latest Targets changes. The client now refreshes which must fail to make the client spec-compliant. Finally, the test asserts that the client still has version 7. 

```python
  # Bump version of Targest 6 times.
    for i in range(6):
        repo.publish([Targets.type])
    repo.publish([Snapshot.type, Timestamp.type])
    
    # Client refreshes and downloads Targets version 7
    assert client.refresh(init_data) == 0
    assert client.version(Targets.type) == 7

    # The repository deletes all published Targets
    # and republishes to version 5.
    # This is a rollback attack.
    del repo.signed_mds[Targets.type]
    for i in range(5):
        repo.publish([Targets.type], verify_version=False)
    repo.publish([Snapshot.type, Timestamp.type])

    # Now the client should fail because it has version 7
    # locally and the repository is presenting it with
    # version 5
    assert client.refresh(init_data) == 1

    # Make sure the client still has version 7
    assert client.version(Targets.type) == 7
```

Running the test again results in a second repository version being dumped (each client refresh leads to a dump): 
```bash
./env/bin/pytest tuf_conformance \
    -k test_targets_version                 # run a specific test only
    --entrypoint "./clients/go-tuf/go-tuf"  # use the included go-tuf client as client-under-test
    --repository-dump-dir /tmp/test-repos   # dump repository contents

# take a look at targets versions in both snapshot versions that got debug dumped
cat /tmp/test-repos/test_targets_version/refresh-1/snapshot.json
cat /tmp/test-repos/test_targets_version/refresh-2/snapshot.json
```

The repository metadata looks as expected (but not spec-compliant) so we can add some asserts for client behaviour now.
The final test looks like this:

```python
def test_targets_version_rollback(
    client: ClientRunner, server: SimulatorServer
) -> None:
    # Initialize our repository: modify targets version and make sure it's included in snapshot
    init_data, repo = server.new_test(client.test_name)

    # initialize client-under-test
    client.init_client(init_data)
    # Run refresh on client-under-test, expect success
    assert client.refresh(init_data) == 0

    # Bump version of Targest 6 times.
    for i in range(6):
        repo.publish([Targets.type])
    repo.publish([Snapshot.type, Timestamp.type])
    
    # Client refreshes and downloads Targets version 7
    assert client.refresh(init_data) == 0
    assert client.version(Targets.type) == 7

    # The repository deletes all published Targets
    # and republishes to version 5.
    # This is a rollback attack.
    del repo.signed_mds[Targets.type]
    for i in range(5):
        repo.publish([Targets.type], verify_version=False)
    repo.publish([Snapshot.type, Timestamp.type])

    # Now the client should fail because it has version 7
    # locally and the repository is presenting it with
    # version 5
    assert client.refresh(init_data) == 1

    # Make sure the client still has version 7
    assert client.version(Targets.type) == 7
```

### Releasing

Checklist for making a new tuf-conformance release
* Review changes since last release, decide on version number
  * If the client-under-test CLI has changed or client workflows are otherwise likely to break, bump major version
  * otherwise if new tests were added, bump minor version
  * otherwise bump patch version
* Create and merge PR with README changes if needed (the workflow example contains the major version number)
* tag the new version from a commit in main branch. Example when releasing v1.1.1:
  ```
      git tag --sign v1.1.1 -m "v1.1.1"
      git push origin v1.1.1
      # now rewrite the major tag: yes rewriting tags is awful, it's also what GitHub recommends...
      git tag --delete v1
      git push --delete origin v1
      git tag --sign v1 -m "v1.1.1"
      git push origin v1
  ```
* Add release notes to GitHub release in the web UI: this will be shown to action users in the dependabot update.
  Release notes must mention all breaking changes.

### Some design notes

* pytest is used as the test infrastructure, the client-under-test executable is given with `--entrypoint`
* A single web server is started. Individual tests can create a simulated TUF repository that will be served in 
  subdirectories of the web server 
* Each test sets up a simulated repository, attaches it to the server, runs the client-under-test
  against that repository. It can then modify the repository state and run the client-under-test again
* the idea is that a test can run the client multiple times while modifying the repository state. After each client
  execution the test can verify 
  1. client success/failure
  2. clients internal  metadata state (what it considers currently valid metadata) and
  3. that the requests client made were the expected ones
* There should be helpers to make these verifications simple in the tests

