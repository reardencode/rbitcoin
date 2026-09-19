{
  expectedPackage,
  module,
  nixpkgs,
  pkgs,
}:
let
  fakePackage = pkgs.runCommand "rbitcoin-test-package" { } ''
    mkdir -p "$out/bin"
    touch "$out/bin/rbitcoin-node"
  '';
  system = nixpkgs.lib.nixosSystem {
    inherit (pkgs.stdenv.hostPlatform) system;
    modules = [
      module
      {
        services.rbitcoin = {
          enable = true;
          package = fakePackage;
          dataDir = "/srv/rbitcoin";
          coldDataDir = "/srv/rbitcoin-cold";
          network = "regtest";
          logLevel = "debug";
          scripthashIndex = true;
          silentPaymentIndex = true;
          environment.RBITCOIN_IO = "uring";
          extraArgs = [
            "--max-outbound"
            "8"
          ];
          proxy = "127.0.0.1:9050";
          onionProxy = "127.0.0.1:9050";
          proxyRandomize = true;
          p2p = {
            address = "127.0.0.1";
            openFirewall = true;
          };
          rpc.enable = true;
          electrum = {
            enable = true;
            openFirewall = true;
          };
          esplora = {
            enable = true;
            openFirewall = true;
          };
        };
      }
    ];
  };
  cfg = system.config;
  service = cfg.systemd.services.rbitcoin;
  execStart = service.serviceConfig.ExecStart;
  defaultSystem = nixpkgs.lib.nixosSystem {
    inherit (pkgs.stdenv.hostPlatform) system;
    modules = [
      module
      { services.rbitcoin.enable = true; }
    ];
  };
  defaultCfg = defaultSystem.config.services.rbitcoin;
in
assert defaultCfg.package == expectedPackage;
assert defaultCfg.network == "mainnet";
assert defaultCfg.p2p.port == 8333;
assert defaultCfg.rpc.port == 8332;
assert defaultCfg.proxy == null;
assert defaultCfg.onionProxy == null;
assert defaultCfg.proxyRandomize == true;
assert cfg.services.rbitcoin.p2p.port == 18444;
assert cfg.services.rbitcoin.rpc.port == 18443;
assert
  builtins.sort builtins.lessThan cfg.networking.firewall.allowedTCPPorts == [
    3000
    18444
    50001
  ];
assert service.environment.RBITCOIN_IO == "uring";
assert service.serviceConfig.User == "rbitcoin";
assert service.serviceConfig.Group == "rbitcoin";
assert service.serviceConfig.KillSignal == "SIGTERM";
assert builtins.match ".*--datadir /srv/rbitcoin.*" execStart != null;
assert builtins.match ".*--datadir-cold /srv/rbitcoin-cold.*" execStart != null;
assert builtins.match ".*--network regtest.*" execStart != null;
assert builtins.match ".*--listen 127.0.0.1:18444.*" execStart != null;
assert builtins.match ".*--rpc-listen 127.0.0.1:18443.*" execStart != null;
assert builtins.match ".*--electrum-listen 127.0.0.1:50001.*" execStart != null;
assert builtins.match ".*--esplora-listen 127.0.0.1:3000.*" execStart != null;
assert builtins.match ".*--shindex.*" execStart != null;
assert builtins.match ".*--sptweaks.*" execStart != null;
assert builtins.match ".*--log-level debug.*" execStart != null;
assert builtins.match ".*--max-outbound 8.*" execStart != null;
assert builtins.match ".*--proxy 127.0.0.1:9050.*" execStart != null;
assert builtins.match ".*--onion 127.0.0.1:9050.*" execStart != null;
pkgs.runCommand "rbitcoin-nixos-module-eval" { } "touch $out"
