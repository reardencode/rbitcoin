Added

- **IBD keeps checking blocks while headers are still below the work floor.** A second peer bounds how far that can run ahead of a chain anyone else has matched. A lying first header peer can leave at most the lead on disk after the tip moves away: 65,536 blocks, or 1 GiB of those blocks, whichever comes first.
