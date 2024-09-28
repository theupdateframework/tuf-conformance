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

          - uses: theupdateframework/tuf-conformance@v2
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

Let's say we want to test that clients will not accept a root version 4 when they requested
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

The metadata looks as expected: There is a 2.root.json and it contains `version: 2`. We now add code
that serves an incorrect version number:

```python
    # publish a 3.root.json but make it contain the field "version: 4"
    # Use verify_version=False to override the safety check for this
    repo.root.version += 1
    repo.publish([Root.type], verify_version=False)

    # Run refresh on client-under-test again
    client.refresh(init_data)
```

Running the test suite again results in a second repository version being dumped (each client refresh leads to a dump): 
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

