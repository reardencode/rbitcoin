Fixed

- **A peer that asks for a block this node cannot serve gets `notfound`.**
  Silence held that getdata until the 30s stall floor, so a lighter fork
  peer could pin a heavier tip for two stall waits. An unknown hash, a
  header-only row, and a pruned body are `notfound`. The peer is asked
  again later: a `notfound` before they have the block is not a ban.
