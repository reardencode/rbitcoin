Fixed

- **A missed overflow-header write does not seal the tip.**
  Open keeps the prefix the durable overflow header still names. A disconnect
  that dies after shortening the locator header, or before it, reopens at
  that shorter prefix instead of refusing the datadir.
