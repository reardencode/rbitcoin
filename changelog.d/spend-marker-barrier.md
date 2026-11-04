Fixed

- **Open replay does not publish the spend marker before the device barrier.**
  A rewrite that left the replay files clean still runs `sync_data` on those
  stems and on `spenders` before the marker file is written. A failed barrier
  leaves the previous marker in place.
