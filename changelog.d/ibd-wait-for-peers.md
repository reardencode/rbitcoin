Changed

- **Catch-up waits for peers instead of exiting.** A node that still has catch-up indexes no longer stops when every peer is gone. It used to give up after the initial dial waves (`no peers connected`) or after four empty redial rounds in the middle of catch-up (`all peers dead mid catch-up`), then exit with `restart to resume IBD`. Behind a SOCKS proxy that restarts, those rounds were refused within milliseconds, so the node exited before the proxy came back.
- **Empty rounds back off, and only shutdown stops the wait.** The pause is 1 second, then 2, 4, and so on up to 60 seconds. A node whose indexes are already at the tip still hands a peerless catch-up to tip follow. That supervisor's one-wave retry of a stale tip still returns on its own clock.
- **An empty address book stays in catch-up while discovery is still in flight.** Proxy seed names are queued again, and dialing resumes when a target appears. The process does not exit, and it does not enter tip mode on a partial chain.
- **RPC starts before a catch-up that may wait.** `stop`, `addnode`, and status stay available during the wait.
