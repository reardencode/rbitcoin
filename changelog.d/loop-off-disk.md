Fixed

- **A header batch below the minimum chain work is ignored without reading parent headers.** Peers without the noban permission no longer walk the header store on the way to that ignore. Noban peers still store the headers. A full batch of that kind does not ask for the next headers. The headers are stored once the pending path has enough work, and that batch does not move the peer's best-known tip.
- **A gap in front of later queued blocks is still requested.** The next height to assign moves back to the first height that is not ready. A request whose peer is gone does not count as covering that height. A full request window still moves that cursor back. Heights already ready are not walked again until the tip moves back or a request is freed.
- **A block with no stored header is not kept.** A confirm failure whose parent header is missing is an internal fault. It does not ban the peer.
- **The height index does not publish a height the store has already left.** Catch-up reads the headers it is missing before it takes the index lock. A header read that loses a race with a disconnect is not published. Disconnect still drops heights above the new tip.
