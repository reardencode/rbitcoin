Fixed

- **The IBD tip-flush test counts this query's thread.** A process-wide
  `/proc` scan also sees other queries in the same suite, so coverage
  failed `two_ibd_flushes_share_one_named_thread` after drop while the
  uninstrumented job passed.
