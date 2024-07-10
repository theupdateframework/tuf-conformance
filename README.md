# TUF conformance test suite

This is the repository of the conformance suite for TUF clients. The goal of this repository is to provide a test suite that allows client developers and maintainers to test their clients against the TUF specification. The repository has a series of conformance tests and an infrastructure to run the conformance tests. It is currently under heavy development, and some things will change. We work to keep the test suite in a state where client developers can integrate and test their clients at any time during the test suite's development. Currently, there are two clients integrated into the test suite; Over time, clients should consume the TUF conformance test suite through the GitHub action, and the two integrated clients will likely be removed from this repository.

- [Run a client against the conformance tests](#run-a-client-against-the-conformance-tests)
- [Rough design](#rough-design)
- [Integrating a client](#integrating-a-client)


## Run a client against the conformance tests

We have made it easy to run the clients from this project. 

### Install

Before running a client, we recommend setting up a virtual environment.

```bash
pip install -e .
```

### python-tuf

```bash
make test-python-tuf
```

### go-tuf-metadata

```bash
make test-go-tuf
```

## Rough design

* test runner is given a specific client wrapper as argument
* The client wrapper is an executable that implements a _client-under-test CLI_ (to be defined)
  -- each tested client will need a wrapper. That wrapper is responsible for doing the requested TUF client
  operations and also for making the client metadata cache available in the given location
* test runner runs a single web server that individual tests can attach a simulated TUF repository to
* each test sets up a simulated repository, attaches it to the server, runs the client-under-test
  against that repository. It can then modify the repository state and run the client-under-test again
* the testrunner and web server run in the same thread: when a client-under-test process is started
  the web server request handler is manually pumped until the client-under-test finishes
* the idea is that a test can run the client multiple times while modifying the repository state. After each client
  execution the test can verify 
  1. client success/failure
  2. clients internal  metadata state (what it considers currently valid metadata) and
  3. that the requests client made were the expected ones
* There should be helpers to make these verifications simple in the tests but these helpers are still
  largely unimplemented.

[Original ideas document](https://docs.google.com/document/d/11bKcRoC0G8b_YnLfK0tj1RfJjrMfXGhO8Li2LA1FUUk/edit?usp=sharing)

## Integrating a client

See [the documentation on integrating a client](https://github.com/theupdateframework/tuf-conformance/tree/main/clients).

