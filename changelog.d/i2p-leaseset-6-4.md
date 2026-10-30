Changed

- **I2P SAM sessions request leaseset encryption types `6,4`.** As in Core
  (bitcoin/bitcoin#35696), `SESSION CREATE` sends
  `i2cp.leaseSetEncType=6,4` (ML-KEM-768 hybrid, then ECIES-X25519) instead
  of `4,0`. ElGamal (type 0) is dropped. Java I2P routers older than 2.10.0
  reject type 6 and fail the session; upgrade the router. i2pd ignores
  unknown types, and has supported type 6 since 2.58.0. The node no longer
  talks to I2P peers whose leasesets offer only ElGamal (Core before
  v26.1).
