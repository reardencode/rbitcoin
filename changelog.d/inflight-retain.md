Changed

- **IBD keeps recent in-flight outputs while the accounted heap is under 1 GiB.**
  A lookup wave that would drop outputs retains 64 more blocks below the
  normal drop. Over 1 GiB, each wave releases 64 blocks. That line counts
  the accounted heap other than the in-flight pin floor (body queue, write
  locations, hash index, height fence, confirm wire, and fuse/MPHF/Class C
  heap), not a separate `ibd: sizes` line. The pin floor can carry the
  total past 1 GiB.
