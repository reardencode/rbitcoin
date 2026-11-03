Fixed

- **Header height during catch-up is the headers this node accepted.** Health metrics and `getblockchaininfo` count that walk, including headers ahead of the validated tip and checkpoints restored at startup. They no longer report the validated block tip as if verification were finished. A height a peer only advertised does not count. Invalidating or reconsidering a block rechecks that chain and does not silence a different valid walk.
