Fixed

- **Consensus: an empty signature in legacy `CHECKMULTISIG` deletes `OP_0`
  from scriptCode.** Core's FindAndDelete of an empty signature removes
  every `OP_0` opcode before the other signatures are hashed. We left
  scriptCode unchanged, so a spend that mixed an empty signature with
  signed and malformed ones could get the opposite result from Core,
  in either direction.
