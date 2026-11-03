Changed

- **An existing `{datadir}/rpc.token` must be mode 0600 on Unix.** Group or world bits refuse startup. The node still creates a missing token at 0600 and does not change the mode of a file that is already there. Windows has no mode bits.
- **A token file that was group- or world-readable stays refused until you delete it.** chmod to 0600 passes the check and keeps the secret that was already readable. Delete the file and start again to mint a new token. The node mints one only when the file is gone.
