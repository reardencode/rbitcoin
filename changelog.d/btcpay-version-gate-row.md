Fixed

- **`docs/wallets.md` no longer lists an NBXplorer version gate as a BTCPay
  gap.** NBXplorer 2.6.21 (BTCPay Server 2.4.7) accepts
  `getnetworkinfo.version` `190000` (`MinRPCVersion = 150000`), and its v1
  P2P link has the `--net-permission-bind v1` listener (#1424), as the BTCPay
  section above the table says.
