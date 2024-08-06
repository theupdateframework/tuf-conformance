# tuf-conformance client-under-test CLI

Before a TUF client can be tested with the tuf-conformance test suite, an executable must be provided
that implements this CLI protocol. There are three required commands: `init`, `refresh` and `download`.

## Commands

### Init command

Initialize the clients local trusted metadata.

`<client> --metadata-dir <METADATA_DIR> init <TRUSTED_ROOT>`

where
- `METADATA_DIR` is a directory where the client is expected to store metadata it considers valid
- `TRUSTED_ROOT` is a file that contains initial root.json content

Client must initialize with the given trusted root (this may involve simply copying the
trusted root into `METADATA_DIR`: no checks are expected). No requests should be made to the repository at this point.
Client must use exit code 0 if the initialization succeeded and exit code 1 otherwise.

This command will be called only once for a specific test.

**Example**

`my-tuf-client --metadata-dir /tmp/metadata init ./initial_root.json`


### Refresh command

Update local metadata from the repository.

`<client> --metadata-dir <METADATA_DIR> --metadata-url <METADATA_URL> refresh`

where
- `METADATA_DIR` is a directory where the client is expected to read and write trusted local metadata
- `METADATA_URL` is a URL to the repository metadata store

Client must update its top-level metadata according to the TUF client workflow. Client must use exit code
0 if the refresh succeeded fully and exit code 1 if any part of the refresh failed. 

Client must use non-versioned filenames for metadata in `METADATA_DIR` (so "root.json" instead of "1.root.json").

This command may be called multiple times in a test.

**Example**

```
my-tuf-client \
    --metadata-dir /tmp/metadata \
    --metadata-url http://localhost:8888/test-repo/metadata \
    refresh`
```


### Download command

Download an artifact from repository, store it in local disk.

`<client> --metadata-dir <METADATA_DIR> --metadata-url <METADATA_URL> --target-name <TARGET_PATH> --target-base-url <TARGET_URL> --target-dir <TARGET_DIR> download`

where
- `METADATA_DIR` is a directory where the client is expected to store metadata it considers valid
- `METADATA_URL` is a URL to the repository metadata store
- `TARGET_PATH` is the TUF targetpath of the artifact that should be downloaded
- `TARGET_URL` is the base URL for repository target store
- `TARGET_DIR`: is a directory where the client should store downloaded and verified files

Client must download the given artifact (targetpath) according to TUF client workflow, and store it in
given targets directory. Client must ensure that metadata is up-to-date before downloading artifacts
(see _Refresh command_ for rules on metadata storage in `METADATA_DIR`).
Client must use exit code 0 if the download succeeded fully and exit code 1 if any part of
the download failed.

Client may use any filename or directory structure it wants within `TARGET_DIR`: The expectation is that if a 
targetpath is downloaded twice it is stored with the same filename (even if the content changed).

This command may be called multiple times in a test.

**Example**

```
my-tuf-client \
    --metadata-dir /tmp/metadata \
    --metadata-url http://localhost:8888/test-repo/metadata \
    --target-name path/to/artifact.txt \
    --target-base-url http://localhost:8888/test-repo/targets \
    --target-dir /tmp/targets
    download
```

## What does the test suite measure?

The test suite has limited visibility into client decisions so uses various signals to measure conformance:
* Client command success/failure
* The metadata the client considers trusted (`METADATA_DIR`)
* The artifacts the client downloads (`TARGET_DIR`)
* The HTTP requests made by the client to the repository

Sometimes test suite expectations are not strictly part of TUF specification: As an example the test suite expects
a specific sequence of metadata HTTP requests to assert that the client handled delegations correctly.
