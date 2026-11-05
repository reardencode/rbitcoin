Fixed

- **A side branch is accepted without copying every held body.** The node
  walks the bodies it already holds, starting from the branch tips, and
  skips a branch it has already ranked. Restoring the old path reconnects
  it without another copy. Copying on every read had grown with the square
  of the branch.
