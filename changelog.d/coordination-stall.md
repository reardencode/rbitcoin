Fixed

- **Script checks stop once the milestone block is on the header path.** A block whose hash is that path's hash at its height skips scripts before chain work meets the minimum. A different hash at that height still runs scripts. Previous outputs are still checked.
- **A header batch that does not connect is ignored while the node is below the work minimum, even when the pending-header map is full.** That ignore does not walk parent headers.
- **A connected-block check uses the published height index.** Peer handling and initial download both do. A hash the index has not recorded is not connected. The check does not read headers to catch the index up.
