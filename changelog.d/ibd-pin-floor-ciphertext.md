Changed

- **IBD in-flight outputs keep a 50 MiB floor.** The allowance is the
  larger of 50 MiB and the room left under 1 GiB after every other
  accounted byte. The window grows one step only when a prune would drop
  packs. When that room is already under 50 MiB, the floor still applies,
  so the accounted total can pass 1 GiB. The 1 GiB release of older
  outputs does not count this floor.
- **Each IBD block-download connection keeps one 4 MiB ciphertext buffer**
  for the life of that reader and decrypts into a buffer sized to the
  message. Tip-follow connections allocate ciphertext per packet and do
  not keep that buffer.
