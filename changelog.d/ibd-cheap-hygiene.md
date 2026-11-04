Fixed

- **IBD work-path hygiene no longer sweeps the whole header chain every
  second.** `IbdWorkState::hygiene` retained `header_fks`, `hash_height`,
  `path_prev`, and `known_headers` — three or four SipHash probes per entry
  over maps the size of the header chain — on the main loop thread while it
  held the state lock. At a mainnet tip that is ~21 M probes and ~0.8 s of
  every second, so the loop turned about once a second instead of every
  50 ms and getdata went out in one burst per second. The chain-sized
  sweeps moved to `IbdWorkState::deep_hygiene` at a 60 s cadence; the
  per-second path keeps `compact_ordered`, the `height_to_hash` retain, and
  the body-cache retain, which are O(live).
