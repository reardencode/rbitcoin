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
          onlyNet = [
            "onion"
            "i2p"
            "cjdns"
          ];
          tor = {
            control = "127.0.0.1:9051";
            controlCookie = "/run/tor/control.authcookie";
          };
          i2p = {
            sam = "127.0.0.1:7656";
            acceptIncoming = true;
          };
          cjdns.reachable = true;
          pruneSeqSigWit = true;
          p2p = {
            address = "127.0.0.1";
            openFirewall = true;
            listenOnion = true;
          };
          rpc = {
            enable = true;
            socketPath = "/run/rbitcoin/rpc.sock";
            cookieFile = "/run/rbitcoin/rpc.cookie";
          };
          electrum = {
            enable = true;
            openFirewall = true;
            hiddenService = true;
          };
          esplora = {
            enable = true;
            openFirewall = true;
            hiddenService = true;
          };
          sv2.tp = {
            enable = true;
            port = 18447;
            authoritySecretFile = "/run/keys/sv2-authority";
            certValidity = 600;
            staleGrace = 0;
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
  listenOffSystem = nixpkgs.lib.nixosSystem {
    inherit (pkgs.stdenv.hostPlatform) system;
    modules = [
      module
      {
        services.rbitcoin = {
          enable = true;
          package = fakePackage;
          p2p = {
            listen = false;
            maxInbound = 0;
            discover = false;
            openFirewall = true;
          };
        };
      }
    ];
  };
  listenOffExec = listenOffSystem.config.systemd.services.rbitcoin.serviceConfig.ExecStart;
  cookieWithoutTcp = nixpkgs.lib.nixosSystem {
    inherit (pkgs.stdenv.hostPlatform) system;
    modules = [
      module
      {
        services.rbitcoin = {
          enable = true;
          package = fakePackage;
          rpc.socketPath = "/run/rbitcoin/rpc.sock";
          rpc.cookieFile = "/run/rbitcoin/rpc.cookie";
        };
      }
    ];
  };
  # Core keeps its cookie in the datadir; the option must not loosen that directory.
  cookieInDataDir = nixpkgs.lib.nixosSystem {
    inherit (pkgs.stdenv.hostPlatform) system;
    modules = [
      module
      {
        services.rbitcoin = {
          enable = true;
          package = fakePackage;
          rpc.enable = true;
          rpc.cookieFile = "/var/lib/rbitcoin/.cookie";
        };
      }
    ];
  };
  cookieDataDirMode =
    cookieInDataDir.config.systemd.tmpfiles.settings."10-rbitcoin"."/var/lib/rbitcoin".d.mode;
  cookieTcpOnly = "services.rbitcoin.rpc.cookieFile requires rpc.enable (the cookie is accepted on TCP only)";
  # "${./key}" interpolation copies the secret into the world-readable store.
  sv2KeyInStore = nixpkgs.lib.nixosSystem {
    inherit (pkgs.stdenv.hostPlatform) system;
    modules = [
      module
      {
        services.rbitcoin = {
          enable = true;
          package = fakePackage;
          sv2.tp = {
            enable = true;
            authoritySecretFile = "${builtins.storeDir}/0000000000000000000000000000000-sv2-authority";
          };
        };
      }
    ];
  };
  sv2KeyNotInStore = "services.rbitcoin.sv2.tp.authoritySecretFile must not be a store path (the store is world-readable)";
  failedAssertions =
    sys: map (a: a.message) (builtins.filter (a: !a.assertion) sys.config.assertions);
in
assert defaultCfg.package == expectedPackage;
assert defaultCfg.network == "mainnet";
assert defaultCfg.p2p.port == 8333;
assert defaultCfg.p2p.listen == true;
assert defaultCfg.p2p.maxInbound == 125;
assert defaultCfg.p2p.discover == true;
assert defaultCfg.p2p.listenOnion == false;
assert defaultCfg.rpc.port == 8332;
assert defaultCfg.rpc.socketPath == null;
assert defaultCfg.rpc.cookieFile == null;
assert defaultCfg.proxy == null;
assert defaultCfg.onionProxy == null;
assert defaultCfg.proxyRandomize == true;
assert defaultCfg.onlyNet == [ ];
assert defaultCfg.tor.control == null;
assert defaultCfg.tor.controlCookie == null;
assert defaultCfg.electrum.hiddenService == false;
assert defaultCfg.esplora.hiddenService == false;
assert defaultCfg.i2p.sam == null;
assert defaultCfg.i2p.acceptIncoming == false;
assert defaultCfg.cjdns.reachable == false;
assert defaultCfg.sv2.tp.enable == false;
assert defaultCfg.sv2.tp.port == 8442;
assert defaultCfg.sv2.tp.authoritySecretFile == null;
assert defaultCfg.sv2.tp.certValidity == 3600;
assert defaultCfg.sv2.tp.staleGrace == 10;
assert cfg.services.rbitcoin.p2p.port == 18444;
assert cfg.services.rbitcoin.rpc.port == 18443;
assert
  builtins.sort builtins.lessThan cfg.networking.firewall.allowedTCPPorts == [
    3000
    18444
    18447
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
assert builtins.match ".*--rpc-socket /run/rbitcoin/rpc.sock.*" execStart != null;
assert builtins.match ".*--rpc-cookie-file /run/rbitcoin/rpc.cookie.*" execStart != null;
assert builtins.elem "/run/rbitcoin" service.serviceConfig.ReadWritePaths;
assert cfg.systemd.tmpfiles.settings."10-rbitcoin"."/run/rbitcoin".d.mode == "0750";
assert builtins.match ".*--electrum-listen 127.0.0.1:50001.*" execStart != null;
assert builtins.match ".*--esplora-listen 127.0.0.1:3000.*" execStart != null;
assert builtins.match ".*--esplora-onion.*" execStart != null;
assert builtins.match ".*--sh-index.*" execStart != null;
assert builtins.match ".*--sp-tweaks.*" execStart != null;
assert builtins.match ".*--shindex.*" execStart == null;
assert builtins.match ".*--sptweaks.*" execStart == null;
assert builtins.match ".*--log-level debug.*" execStart != null;
assert builtins.match ".*--max-outbound 8.*" execStart != null;
assert builtins.match ".*--proxy 127.0.0.1:9050.*" execStart != null;
assert builtins.match ".*--onion 127.0.0.1:9050.*" execStart != null;
assert builtins.match ".*--only-net onion.*" execStart != null;
assert builtins.match ".*--only-net i2p.*" execStart != null;
assert builtins.match ".*--only-net cjdns.*" execStart != null;
assert builtins.match ".*--tor-control 127.0.0.1:9051.*" execStart != null;
assert builtins.match ".*--tor-control-cookie /run/tor/control.authcookie.*" execStart != null;
assert builtins.match ".*--i2p-sam 127.0.0.1:7656.*" execStart != null;
assert builtins.match ".*--i2p-accept-incoming.*" execStart != null;
assert builtins.match ".*--listen-onion.*" execStart != null;
assert builtins.match ".*--cjdns-reachable.*" execStart != null;
assert builtins.match ".*--prune-seqsigwit.*" execStart != null;
assert builtins.match ".*--sv2-tp-listen 127.0.0.1:18447.*" execStart != null;
assert builtins.match ".*--sv2-tp-authority-sec-file /run/keys/sv2-authority.*" execStart != null;
assert builtins.match ".*--sv2-tp-authority-sec .*" execStart == null;
assert builtins.match ".*--sv2-tp-cert-validity 600.*" execStart != null;
assert builtins.match ".*--sv2-tp-stale-grace 0.*" execStart != null;
assert builtins.match ".*--max-outbound 8$" execStart != null;
assert builtins.elem "tor.service" service.after;
assert builtins.elem "tor.service" service.wants;
assert builtins.elem "i2pd.service" service.after;
assert builtins.elem "i2pd.service" service.wants;
assert builtins.elem "cjdns.service" service.after;
assert builtins.elem "cjdns.service" service.wants;
assert builtins.match ".*--no-listen.*" listenOffExec != null;
assert builtins.match ".*--rpc-socket.*" listenOffExec == null;
assert builtins.match ".*--rpc-cookie-file.*" listenOffExec == null;
assert !builtins.elem cookieTcpOnly (failedAssertions system);
assert builtins.elem cookieTcpOnly (failedAssertions cookieWithoutTcp);
assert !builtins.elem sv2KeyNotInStore (failedAssertions system);
assert builtins.elem sv2KeyNotInStore (failedAssertions sv2KeyInStore);
assert cookieDataDirMode == "0700";
assert builtins.match ".*--listen .*" listenOffExec == null;
assert builtins.match ".*--max-inbound 0.*" listenOffExec != null;
assert builtins.match ".*--no-discover.*" listenOffExec != null;
assert builtins.match ".*--sv2-tp.*" listenOffExec == null;
assert listenOffSystem.config.networking.firewall.allowedTCPPorts == [ ];
pkgs.runCommand "rbitcoin-nixos-module-eval" { } "touch $out"
