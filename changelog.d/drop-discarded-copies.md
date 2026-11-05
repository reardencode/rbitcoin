Changed

- **P2PKH verification keeps one copy of the signature and pubkey.** A write batch that spends two outputs of one in-window create widens the checked vout list without copying those scripts. A sparse pin that lists a vout and has no script for it still takes the other batch's record.
