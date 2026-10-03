Fixed

- **Testnet3 BIP16 exception.** The testnet3 block Bitcoin Core exempts
  from script checks (`00000000dd30457c…a432b105`) no longer enforces
  P2SH, so full script validation accepts that historical block.
