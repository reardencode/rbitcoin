Fixed

- **A held side-branch body is shared, not copied.** The hub copied a held
  body each time it read it: once per ancestor when it assembled a branch
  for connect, from every held block rather than the branch tips, and the
  old path once more on a restore. Accepting a side branch block by block
  grew with the square of its length. A branch is now the bodies the hub
  holds, walked from the held tips first and never again under a branch
  already ranked, and a restore reconnects the old path without a copy.
