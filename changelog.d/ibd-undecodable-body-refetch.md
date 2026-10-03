Fixed

- **IBD no longer stalls on an undecodable block body.** A peer that
  answered `getdata` with the real header and transactions that do not
  parse left the body queued forever, so the honest copy was dropped and
  confirm stopped at that height until restart. Intake now refuses such a
  body and disconnects the sender, and lookup drops any queued row that
  does not decode. The hash is requested again and is never marked
  invalid.
