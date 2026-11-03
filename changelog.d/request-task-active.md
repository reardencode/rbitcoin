Fixed

- **Shutdown waits for request-task mining and submit commands.** HTTP `generate`, `generatetoaddress`, `generateblock`, and `submitblock` stay in the active-command list until they return.
