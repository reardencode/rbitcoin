Fixed

- **A fuse8 filter file that does not match its header is corrupt on open.** That is a declared body longer than the file, or a segment-count length that is not a multiple of the segment length.
- **A chain-data body read longer than 64 MiB is refused before the buffer grows.** Index write-behind is included, not only the variable-length table.
- **A scripthash page chain stops after 1,000,000 links.** The free walk also stops when a page offset repeats, so a cycle stays corrupt after the page header is overwritten.
