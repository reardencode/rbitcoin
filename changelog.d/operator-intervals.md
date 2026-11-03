Changed

- **Redial, I2P retry, and the Stratum v2 budget wait use one interval in every build.** A debug node used 250 ms, 50 ms, and 100 ms. The binary now uses 2 seconds, 500 ms, and 1 second, and it no longer warns about short test timings. Shutdown still wakes on the stop signal and on the 750 ms grace.
