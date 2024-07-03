# Experiments related to tuf-conformance testing

Rough design:

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

## Install

Setting up the virtual environment (recommended):

```bash
pip install -e .
```

## Run the tests

How to run the test rig against each client.

### python-tuf

```bash
make test-python-tuf
```

### go-tuf-metadata

```bash
make test-go-tuf
```
