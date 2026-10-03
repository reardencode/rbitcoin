Fixed

- **A re-connected block records its spends of earlier-archived outputs.**
  Confirm skipped the spent-slot read and annotation when a spend's parent
  was created in the same run, trusting a Class A pre-fill. A parent stored
  by an earlier batch (for example one rejected after its bodies were
  stored, then re-driven after a reorg) never got that pre-fill, so the
  slot stayed empty and a later block could spend the same output again.
  Only outputs this batch's Class A append wrote now skip the read.
- **A failed write after the tip commit no longer lets the next block
  validate without its spends.** If a confirm write failed after the tip
  advanced (for example in the spend annotate or the live index seal), the
  next batch read spent slots that were never written and could accept a
  double spend. The next write now replays the missing annotations first
  and logs `confirm: replay spend annotations`. If that replay fails, the
  batch is not validated.
