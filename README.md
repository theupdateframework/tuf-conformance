# TUF conformance test suite

This is a conformance test suite for [TUF](https://theupdateframework.io/) clients. The goal of is to help TUF client developers
  1. Measure the clients conformance with the [TUF specification](https://theupdateframework.github.io/specification/latest/)
  2. Achieve better practical compatibility with other implementations
  3. Collaborate on tests with other client developers

## Client Conformance Report

See [Client Conformance Report](https://theupdateframework.github.io/tuf-conformance/) for a list of conformant TUF clients.

## Usage

The conformance test suite provides a GitHub action that can be used to test a TUF client.
There are two required steps:

1. Include an executable in the client project that implements the client-under-test
   [CLI protocol](CLIENT-CLI.md).
2. Use the `theupdateframework/tuf-conformance` action in your test workflow:
    ```yaml
    
    on:
      push:
      pull_request:
      schedule:
        - cron: '30 6 * * 3' # weekly run to ensure the client conformance report has recent results

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

The test suite contains tests that are not strictly specification requirements (such as
tests for specific keytype or hash algorithm support). Clients can mark tests as "expected failures"
if they do not intend to support this specific feature.

The tests that are expected to fail can be listed in `<entrypoint>.xfails` file. In the previous
workflow example the xfails file would be `path/to/my/test/executable.xfails`

the `.xfails` file may contain singular tests, test groups or parameterized tests from a test group
```
# Comments are ok on separate lines
test-name
test-group
test-group[parameter]
```

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

Invoking the test suite manually enables all [pytest features](https://docs.pytest.org/en/stable/reference/reference.html#command-line-flags)
like running a single test only or seeing the client output even when test passes:

```bash
make dev
./env/bin/pytest tuf_conformance \
    --entrypoint path/to/my/client-under-test/cli \
    -k test_unsigned_metadata \
    -rA
```

linters can also be invoked with make:
```bash
# Run linters
make lint
# Fix issues that can be automatically fixed
make fix
```

### Writing new tests

Developing tests for tuf-conformance requires a basic understanding of how TUF metadata works: The
remaining details are documented in the [Test Development doc](DEVELOPMENT.md).

### Releasing

Checklist for making a new tuf-conformance release
* Review changes since last release, decide on version number
  * If the client-under-test CLI has changed or client workflows are otherwise likely to break, bump major version
  * otherwise if new tests were added, bump minor version
  * otherwise bump patch version
* Create and merge PR with README changes if needed (the workflow example contains the major version number)
* tag the new version from a commit in main branch. Example when releasing v1.1.1:
  ```
      VERSION="v1.1.1"

      git tag --sign $VERSION -m "$VERSION"
      git push origin $VERSION
      # now rewrite the major tag: yes rewriting tags is awful, it's also what GitHub recommends...
      MAJOR="${VERSION%%.*}"
      git tag --delete $MAJOR
      git push --delete origin $MAJOR
      git tag --sign $MAJOR -m "$VERSION"
      git push origin $MAJOR
  ```
* Create GitHub release in the web UI: The release notes will be shown to action users in the dependabot update and
  must mention all breaking changes.
