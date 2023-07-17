# Client implementation wrappers

This directory contains some client wrappers: they are executables that provide a specific
command line interface that the test suite uses. Embedding these wrappers here is likely temporary:
The intention is that TUF implementations that want to use the test suite will include wrappers like this in
their source code, and will run the test suite in their CI systems.

This project may then also run the test suite using the wrappers from the TUF implementations, but the intention
is that this repository would not have to e.g. maintain dependency lists for the client wrappers.

That said, some wrappers are included for now:
* We will likely tweak the "wrapper API" while we build the initial test suite: while this goes on, it makes
  sense to keep the wrappers here
* We do need something to test the test suite itself
* There is no easy way to run the test suite in a TUF implementation CI yet
