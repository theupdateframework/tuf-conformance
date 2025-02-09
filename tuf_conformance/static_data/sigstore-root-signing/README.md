This repository was downloaded from https://tuf-repo-cdn.sigstore.dev/ on the date
documented in `faketime` file.

Notes:
* The initial root is root v12: v11 has a keyid compliance issue that on paper
  is not spec compliant. Some earlier versions have more serious compliance issues
* The repository expires every few days: this means faketime is required to test this
* signatures may contain empty strings (when some keyholders have not signed)
* metadata contains custom fields that tuf-on-ci uses
