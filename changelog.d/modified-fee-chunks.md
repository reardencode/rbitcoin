Fixed

- **A deprioritised child no longer keeps its parent out of the block.**
  Block templates, `fees.chunk`, `getmempoolcluster`, and the feerate
  diagram chunk on modified fees. A negative `prioritisetransaction` on a
  child splits that child off, so the parent is still mined and its chunk
  fee is only its own. A child boosted the other way shares one chunk with
  its parent. Fee estimates stay on base-fee chunks.
