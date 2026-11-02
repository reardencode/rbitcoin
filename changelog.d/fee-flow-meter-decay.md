Fixed

- **Fee estimates count the full arrival rate.** The flow meter behind
  `estimatesmartfee`, Electrum `blockchain.estimatefee` and Esplora
  `/fee-estimates` decayed the bucket it updated twice on each admit, so a
  steady stream counted near half its rate (10,000 WU/s read as 5,012) and
  near targets could quote low. A fee refresh between admits also changed
  the next sample: the admit's weight was divided by the time since the
  refresh instead of since the last admit.
