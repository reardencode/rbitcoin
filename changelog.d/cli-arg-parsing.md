Fixed

- **rbitcoin-cli now parses negative arguments and types parameters per method.**
A negative number such as `getnetworkhashps -1` was rejected as an unknown
argument, and parameters were converted by trial JSON parsing, so a digit-only
hex string was sent as a number and the node rejected it. A bare `--` now ends
option parsing, and each method converts only the positions it declares, so
hashes stay strings while heights, verbosity, booleans, and arrays become JSON.