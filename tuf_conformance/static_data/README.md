## Static test data from actual repository implementations

Subdirectories should contain complete repositories produced by a specific repository
implementation. Each repository in a `<SUBDIR>` should
* demonstrate all of the TUF features that the implementation uses
* not expire for a very long time
* Store metadata in `<SUBDIR/metadata>` and artifacts in `<SUBDIR/targets>` 
* be ready to be published with just `python -m http.server <SUBDIR>` (in other words filenames
  should match the TUF http API)

Additionally there should be 
  * A version of root in `<SUBDIR>/initial_root.json`: This will be used to initialize the client
  * `<SUBDIR>/targetpath` containing a targetpath of an artifact that exists in the repository
