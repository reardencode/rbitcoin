Changed

- **IBD keeps at least 50 MiB of recent in-flight outputs** when the body queue fills the 1 GiB accounted heap. When that heap is under 1 GiB, the output window still grows only into the room under 1 GiB.
- **Each IBD block download keeps one 4 MiB ciphertext buffer** and decrypts into a buffer sized to the message. Tip-follow connections allocate ciphertext per packet and do not keep that buffer.
