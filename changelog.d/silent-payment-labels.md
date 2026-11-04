- **Silent Payments remote scanning:** recognize BIP-352 labeled payments by
  deriving the labeled spend key, including change label 0. Previously, label
  numbers were used as output counters and labeled payments were missed.
  Official receiving vectors cover even/odd parity, large labels, mixed and
  multiple outputs, and change with no explicit label list.
