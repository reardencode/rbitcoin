Fixed

- **Open does not publish the spend marker ahead of the files it covers.**
  Replay flushes those stems and the spender index before the marker file
  is written, even when the replay files were already clean. If that flush
  fails, the previous marker stays.
