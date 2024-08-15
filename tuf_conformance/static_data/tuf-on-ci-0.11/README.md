This is a repository created with tuf-on-ci 0.11 in
https://github.com/jku/test-data-for-tuf-conformance.

Notes:
* Contains Yubikey and Google Cloud KMS keys (both in practice ecdsa keys)
* There's one delegated targets role with one artifact
* "Unsigned" keys have an empty signature string in signatures
* The metadata contains custom fields in keys and roles
* Should stay valid until 2044
* There are a few additional files in the metadata dir (index.html, index.md)
