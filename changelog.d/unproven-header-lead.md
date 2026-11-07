Added

- **IBD keeps checking blocks while headers are still below the work floor.** A second peer bounds how far that can run ahead of a chain anyone else has matched. A lying first header peer can leave at most the lead on disk after the tip moves away: 65,536 blocks past that match, or 1 GiB of Class A above it, whichever comes first. A later match moves that line, so blocks already matched stay available to confirm.
