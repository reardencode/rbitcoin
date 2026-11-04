Fixed

- **IBD deep hygiene walks a work-path map only when that map is past the
  rows it keeps.** The per-minute sweep compared `known_headers` to the live
  download queue. During a header walk the map is chain-sized because those
  heights are occupied, so the sweep ran every minute, held the coordination
  lock, and dropped almost nothing. It now walks `known_headers` when that
  set exceeds the ordered queue, inflight, and `height_to_hash` by more than
  4,096, and walks `header_fks` / `hash_height` / `path_prev` when those
  exceed `known_headers` by that same slack. Rows a retired fork leaves
  behind after `forget_queue_hashes` are in that second check. A height
  occupant keeps its row when it is absent from `known_headers`. The
  per-second pass still drops occupants at or below the queue tail, and it
  no longer walks the indexed header walk above that tail.
