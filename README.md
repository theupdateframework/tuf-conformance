# TUF conformance test suite

This is the repository of the conformance test suite for TUF clients. The goal of this
repository is to allow client developers to
  1. test their clients against the TUF specification
  2. Achieve better practical compatibility with other implementations
  3. Collaborate on tests with other client developers

> [!NOTE]
> The conformance test suite is currently under rapid development. There is no stability guarantee
> on either the GitHub action inputs or the client-under-test CLI protocol yet. Please wait for
> initial release if that sounds unappealing. 


- [Usage](#Usage)
- [Development](#Development)


## Usage

The conformance test suite provides a GitHub action that can be used to test a TUF client.
There are two required steps:

1. Include an executable in the client project that implements the client-under-test
   [CLI protocol](clients/README.md). 
2. Use the `theupdateframework/tuf-conformance` action in your test workflow:
    ```yaml
    jobs:
      tuf-conformance:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v4

          # insert possible client compilation/installation steps here

          - uses: theupdateframework/tuf-conformance@main
            with:
              entrypoint: path/to/my/test/executable
    ```


## Development

This repository contains two client-under-test CLI protocol implementations
to enable easy development and testing. There is a Makefile that runs the test suite in
virtual environment:

```bash
# run against both clients or just one of them:
make test-all
make test-python-tuf
make test-go-tuf
```

It's also possible to locally run the test suite with a client-under-test CLI from another location:

```bash
pip install -e $CONFORMANCE_SUITE_DIR
pytest "$CONFORMANCE_SUITE_DIR/tuf_conformance" --entrypoint path/to/my/client-under-test/cli
```

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

