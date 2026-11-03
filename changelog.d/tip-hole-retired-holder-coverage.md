Fixed

- **A block that every peer was asked for, and none delivered, is asked for again.** Those finished requests used to count toward the cap, so once each peer had been asked and then dropped, nothing requested the block again. Download sat at that height with idle peers and an empty queue until restart. A hole with finished requests and no live request is raced again, up to the cap. When every connected peer has already been asked, the one that has waited longest is asked again after that wait expires. Finished requests still count toward the cap while a live request exists.
