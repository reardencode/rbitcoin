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
          environment.RBITCOIN_IO = "uring";
          extraArgs = [
            "--max-run-secs"
            "1"
          ];
          asmap = "/srv/rbitcoin/ip_asn.dat";
          uaComment = [ "nixos" ];
          blockFilterIndex = true;
          pruneSeqSigwitRamThresholdBytes = 0;
          maxShCreates = 0;
          mempool = {
            sizeMb = 100;
            expiry = 72;
            minRelayTxFee = "0.00001000";
            blocksOnly = true;
            persist = false;
            prefillCompact = false;
            limitClusterCount = 10;
            limitClusterSize = 100;
            bytesPerSigop = 0;
            blockReservedSigops = 400;
          };
          trusted = true;
          alwaysRelay = true;
          relay = true;
          netPermission = [ "noban@192.0.2.0/24" ];
          netPermissionBind = [ "noban@127.0.0.1:18444" ];
          netPermissionRelay = false;
          netPermissionForceRelay = true;
          blockVersion = 2;
          blockMinTxFee = "0.00001000";
          apiLog = "/srv/rbitcoin/api.jsonl";
          minChainWork = "01";
          maxTipAge = 0;
          checkBlocks = 0;
          alertNotify = "/run/rbitcoin/alert";
          startupNotify = "/run/rbitcoin/ready";
          inhibitSuspend = true;
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
          datadirHdd = true;
          p2p = {
            address = "127.0.0.1";
            openFirewall = true;
            listenOnion = true;
            maxOutbound = 8;
            connect = [
              "192.0.2.10:8333"
              "peer.example:8333"
            ];
            seedNodes = [ "seed.example" ];
            noSeeds = true;
            externalIp = [ "203.0.113.5" ];
            peerTimeout = 60;
          };
          rpc = {
            enable = true;
            socketPath = "/run/rbitcoin/rpc.sock";
            cookieFile = "/run/rbitcoin/rpc.cookie";
            clientVersion = 310000;
            tokenFile = "/run/rbitcoin/rpc.token";
            workQueue = 32;
          };
          electrum = {
            enable = true;
            openFirewall = true;
            hiddenService = true;
            maxSubs = 25000;
          };
          esplora = {
            enable = true;
            openFirewall = true;
            hiddenService = true;
            maxInflight = 1024;
            blockTemplate = true;
          };
          health.enable = true;
          metrics = true;
          heavyShCreates = 20000;
          storeReadBudget = 8;
          sv2.tp = {
            enable = true;
            port = 18447;
            authoritySecretFile = "/run/keys/sv2-authority";
            certValidity = 600;
            staleGrace = 0;
            feeDelta = 0;
            templateInterval = 30;
            idleTimeout = 30;
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
          electrum.maxSubs = 25000;
          heavyShCreates = 0;
          esplora.maxInflight = 1024;
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
  cookiePermsNeedFile = "services.rbitcoin.rpc.cookiePerms requires rpc.cookieFile";
  cookieGroup = nixpkgs.lib.nixosSystem {
    inherit (pkgs.stdenv.hostPlatform) system;
    modules = [
      module
      {
        services.rbitcoin = {
          enable = true;
          package = fakePackage;
          rpc.enable = true;
          rpc.cookieFile = "/run/rbitcoin/rpc.cookie";
          rpc.cookiePerms = "group";
        };
      }
    ];
  };
  cookieGroupExec = cookieGroup.config.systemd.services.rbitcoin.serviceConfig.ExecStart;
  cookiePermsAlone = nixpkgs.lib.nixosSystem {
    inherit (pkgs.stdenv.hostPlatform) system;
    modules = [
      module
      {
        services.rbitcoin = {
          enable = true;
          package = fakePackage;
          rpc.enable = true;
          rpc.cookiePerms = "group";
        };
      }
    ];
  };
  metricsNeedHealth = "services.rbitcoin.metrics requires health.enable (--metrics needs --health-listen)";
  metricsWithoutHealth = nixpkgs.lib.nixosSystem {
    inherit (pkgs.stdenv.hostPlatform) system;
    modules = [
      module
      {
        services.rbitcoin = {
          enable = true;
          package = fakePackage;
          metrics = true;
        };
      }
    ];
  };
  prometheus = nixpkgs.lib.nixosSystem {
    inherit (pkgs.stdenv.hostPlatform) system;
    modules = [
      module
      {
        services.prometheus.enable = true;
        services.rbitcoin = {
          enable = true;
          package = fakePackage;
          health.enable = true;
          metrics = true;
        };
      }
    ];
  };
  rbitcoinScrape = builtins.head (
    builtins.filter (j: j.job_name == "rbitcoin") prometheus.config.services.prometheus.scrapeConfigs
  );
  # Bind the eval. `.` binds tighter than application, so
  # `nixosSystem { ... }.config` reads `config` off the attrset argument.
  restOnSystem = nixpkgs.lib.nixosSystem {
    inherit (pkgs.stdenv.hostPlatform) system;
    modules = [
      module
      {
        services.rbitcoin = {
          enable = true;
          package = fakePackage;
          rpc.enable = true;
          rpc.rest = true;
        };
      }
    ];
  };
  restOnExec = restOnSystem.config.systemd.services.rbitcoin.serviceConfig.ExecStart;
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
  execOf =
    opts:
    (nixpkgs.lib.nixosSystem {
      inherit (pkgs.stdenv.hostPlatform) system;
      modules = [
        module
        {
          services.rbitcoin = {
            enable = true;
            package = fakePackage;
          } // opts;
        }
      ];
    }).config.systemd.services.rbitcoin.serviceConfig.ExecStart;
  spExec = execOf {
    silentPaymentIndex = true;
    spTweaksDust = 546;
  };
  inboundExec = execOf {
    p2p.maxInbound = 125;
  };
  unixExec = execOf {
    rpc.unixSocket = true;
    esplora = {
      enable = true;
      socketPath = "/run/rbitcoin/esplora.sock";
      openFirewall = true;
    };
  };
  unixSystem = nixpkgs.lib.nixosSystem {
    inherit (pkgs.stdenv.hostPlatform) system;
    modules = [
      module
      {
        services.rbitcoin = {
          enable = true;
          package = fakePackage;
          rpc.unixSocket = true;
          esplora = {
            enable = true;
            socketPath = "/run/rbitcoin/esplora.sock";
            openFirewall = true;
          };
        };
      }
    ];
  };
  onionOffExec = execOf {
    tor.control = "127.0.0.1:9051";
    esplora = {
      enable = true;
      hiddenService = false;
    };
  };
  signetExec = execOf {
    network = "signet";
    signet = {
      challenge = "51";
      blockTime = 120;
    };
  };
  spAndPruneMsg = "services.rbitcoin.silentPaymentIndex cannot be combined with pruneSeqSigWit";
  signetChallengeMsg = "services.rbitcoin.signet.challenge requires network = \"signet\"";
  signetTimeMsg = "services.rbitcoin.signet.blockTime requires signet.challenge";
  trustSeedMsg = "services.rbitcoin.trustPeer cannot be combined with p2p.seedNodes";
  bindNeedsListenMsg = "services.rbitcoin.netPermissionBind requires p2p.listen";
  bindTrustMsg = "services.rbitcoin.netPermissionBind cannot be combined with trustPeer";
  esploraSockNeedsEnableMsg = "services.rbitcoin.esplora.socketPath requires esplora.enable";
  blockTemplateOffExec = execOf {
    esplora.blockTemplate = true;
  };
  apiLogSystem = nixpkgs.lib.nixosSystem {
    inherit (pkgs.stdenv.hostPlatform) system;
    modules = [
      module
      {
        services.rbitcoin = {
          enable = true;
          package = fakePackage;
          dataDir = "/srv/rbitcoin";
          apiLog = "/var/log/rbitcoin/api.jsonl";
        };
      }
    ];
  };
  badSystem = opts: nixpkgs.lib.nixosSystem {
    inherit (pkgs.stdenv.hostPlatform) system;
    modules = [
      module
      {
        services.rbitcoin = {
          enable = true;
          package = fakePackage;
        } // opts;
      }
    ];
  };
in
assert defaultCfg.package == expectedPackage;
assert defaultCfg.network == "mainnet";
assert defaultCfg.p2p.port == 8333;
assert defaultCfg.p2p.listen == true;
assert defaultCfg.p2p.maxInbound == 200;
assert defaultCfg.p2p.maxOutbound == null;
assert defaultCfg.p2p.connect == [ ];
assert defaultCfg.p2p.seedNodes == [ ];
assert defaultCfg.p2p.noSeeds == false;
assert defaultCfg.blockFilterIndex == false;
assert defaultCfg.mempool.persist == true;
assert defaultCfg.mempool.prefillCompact == true;
assert defaultCfg.mempool.sizeMb == null;
assert defaultCfg.netPermissionRelay == true;
assert defaultCfg.netPermissionForceRelay == false;
assert defaultCfg.rpc.unixSocket == false;
assert defaultCfg.inhibitSuspend == false;
assert defaultCfg.esplora.blockTemplate == false;
assert defaultCfg.esplora.socketPath == null;
assert defaultCfg.sv2.tp.idleTimeout == 0;
assert defaultCfg.p2p.discover == true;
assert defaultCfg.p2p.listenOnion == false;
assert defaultCfg.rpc.port == 8332;
assert defaultCfg.rpc.socketPath == null;
assert defaultCfg.rpc.cookieFile == null;
assert defaultCfg.rpc.cookiePerms == null;
assert defaultCfg.proxy == null;
assert defaultCfg.onionProxy == null;
assert defaultCfg.proxyRandomize == true;
assert defaultCfg.onlyNet == [ ];
assert defaultCfg.tor.control == null;
assert defaultCfg.tor.controlCookie == null;
assert defaultCfg.electrum.hiddenService == false;
assert defaultCfg.electrum.maxSubs == null;
assert defaultCfg.heavyShCreates == null;
assert defaultCfg.storeReadBudget == null;
assert defaultCfg.esplora.hiddenService == false;
assert defaultCfg.esplora.maxInflight == null;
assert defaultCfg.rpc.clientVersion == null;
assert defaultCfg.i2p.sam == null;
assert defaultCfg.i2p.acceptIncoming == false;
assert defaultCfg.cjdns.reachable == false;
assert defaultCfg.health.enable == false;
assert defaultCfg.health.address == "127.0.0.1";
assert defaultCfg.health.port == 9332;
assert defaultCfg.health.openFirewall == false;
assert defaultCfg.metrics == false;
assert defaultCfg.sv2.tp.enable == false;
assert defaultCfg.sv2.tp.port == 8442;
assert defaultCfg.sv2.tp.authoritySecretFile == null;
assert defaultCfg.sv2.tp.certValidity == 3600;
assert defaultCfg.sv2.tp.staleGrace == 10;
assert defaultCfg.sv2.tp.feeDelta == 1000;
assert defaultCfg.sv2.tp.templateInterval == 5;
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
assert builtins.match ".*--rest.*" execStart == null;
assert builtins.match ".*--rest.*" restOnExec != null;
assert builtins.match ".*--trust-peer.*" (
  defaultSystem.config.systemd.services.rbitcoin.serviceConfig.ExecStart
) == null;
assert builtins.match ".*--listen.*" (
  defaultSystem.config.systemd.services.rbitcoin.serviceConfig.ExecStart
) != null;
let
  trustPeerSystem = nixpkgs.lib.nixosSystem {
    inherit (pkgs.stdenv.hostPlatform) system;
    modules = [
      module
      {
        services.rbitcoin = {
          enable = true;
          package = fakePackage;
          trustPeer = "192.0.2.1:8333";
        };
      }
    ];
  };
  trustPeerExec = trustPeerSystem.config.systemd.services.rbitcoin.serviceConfig.ExecStart;
  trustPeerListen = nixpkgs.lib.nixosSystem {
    inherit (pkgs.stdenv.hostPlatform) system;
    modules = [
      module
      {
        services.rbitcoin = {
          enable = true;
          package = fakePackage;
          trustPeer = "192.0.2.1:8333";
          p2p.listen = true;
        };
      }
    ];
  };
in
assert builtins.match ".*--trust-peer 192.0.2.1:8333.*" trustPeerExec != null;
assert builtins.match ".*--no-listen.*" trustPeerExec != null;
assert builtins.match ".*--max-inbound 0.*" trustPeerExec != null;
assert builtins.match ".*--listen .*" trustPeerExec == null;
assert builtins.any (m: builtins.match ".*trustPeer.*" m != null) (
  failedAssertions trustPeerListen
);
assert builtins.match ".*--milestone 100.*" (
  (nixpkgs.lib.nixosSystem {
    inherit (pkgs.stdenv.hostPlatform) system;
    modules = [
      module
      {
        services.rbitcoin = {
          enable = true;
          package = fakePackage;
          milestone = 100;
        };
      }
    ];
  }).config.systemd.services.rbitcoin.serviceConfig.ExecStart
) != null;
assert builtins.match ".*--rpc-socket /run/rbitcoin/rpc.sock.*" execStart != null;
assert builtins.match ".*--rpc-cookie-file /run/rbitcoin/rpc.cookie.*" execStart != null;
assert builtins.match ".*--rpc-cookie-perms.*" execStart == null;
assert builtins.match ".*--rpc-cookie-perms group.*" cookieGroupExec != null;
assert builtins.match ".*--rpc-client-version 310000.*" execStart != null;
assert builtins.match ".*--rpc-client-version.*" (
  defaultSystem.config.systemd.services.rbitcoin.serviceConfig.ExecStart
) == null;
assert builtins.match ".*--rpc-cookie-file /run/rbitcoin/rpc.cookie.*" cookieGroupExec != null;
assert builtins.elem "/run/rbitcoin" service.serviceConfig.ReadWritePaths;
assert cfg.systemd.tmpfiles.settings."10-rbitcoin"."/run/rbitcoin".d.mode == "0750";
assert builtins.match ".*--electrum-listen 127.0.0.1:50001.*" execStart != null;
assert builtins.match ".*--electrum-max-subs 25000.*" execStart != null;
assert builtins.match ".*--electrum-max-subs.*" listenOffExec == null;
assert builtins.match ".*--heavy-sh-creates 20000.*" execStart != null;
assert builtins.match ".*--heavy-sh-creates 0.*" listenOffExec != null;
assert builtins.match ".*--heavy-sh-creates.*" (
  defaultSystem.config.systemd.services.rbitcoin.serviceConfig.ExecStart
) == null;
assert builtins.match ".*--store-read-budget 8.*" execStart != null;
assert builtins.match ".*--store-read-budget.*" (
  defaultSystem.config.systemd.services.rbitcoin.serviceConfig.ExecStart
) == null;
assert builtins.match ".*--esplora-listen 127.0.0.1:3000.*" execStart != null;
assert builtins.match ".*--esplora-onion.*" execStart != null;
assert builtins.match ".*--esplora-max-inflight 1024.*" execStart != null;
assert builtins.match ".*--esplora-max-inflight.*" listenOffExec == null;
assert builtins.match ".*--sh-index.*" execStart != null;
assert builtins.match ".*--sp-tweaks.*" execStart == null;
assert builtins.match ".*--shindex.*" execStart == null;
assert builtins.match ".*--sptweaks.*" execStart == null;
assert builtins.match ".*--log-level debug.*" execStart != null;
assert builtins.match ".*--max-outbound 8.*" execStart != null;
assert builtins.match ".*--connect 192.0.2.10:8333.*" execStart != null;
assert builtins.match ".*--connect peer.example:8333.*" execStart != null;
assert builtins.match ".*--seed-node seed.example.*" execStart != null;
assert builtins.match ".*--no-seeds.*" execStart != null;
assert builtins.match ".*--external-ip 203.0.113.5.*" execStart != null;
assert builtins.match ".*--peer-timeout 60.*" execStart != null;
assert builtins.match ".*--asmap /srv/rbitcoin/ip_asn.dat.*" execStart != null;
assert builtins.match ".*--ua-comment nixos.*" execStart != null;
assert builtins.match ".*--block-filter-index.*" execStart != null;
assert builtins.match ".*--prune-seqsigwit-ram-threshold-bytes 0.*" execStart != null;
assert builtins.match ".*--max-sh-creates 0.*" execStart != null;
assert builtins.match ".*--esplora-block-template.*" execStart != null;
assert builtins.match ".*--blocks-only.*" execStart != null;
assert builtins.match ".*--persist-mempool=0.*" execStart != null;
assert builtins.match ".*--prefill-compact=0.*" execStart != null;
assert builtins.match ".*--mempool-size-mb 100.*" execStart != null;
assert builtins.match ".*--mempool-expiry 72.*" execStart != null;
assert builtins.match ".*--min-relay-tx-fee 0.00001000.*" execStart != null;
assert builtins.match ".*--limit-cluster-count 10.*" execStart != null;
assert builtins.match ".*--limit-cluster-size 100.*" execStart != null;
assert builtins.match ".*--bytes-per-sigop 0.*" execStart != null;
assert builtins.match ".*--block-reserved-sigops 400.*" execStart != null;
assert builtins.match ".*--trusted.*" execStart != null;
assert builtins.match ".*--always-relay.*" execStart != null;
assert builtins.match ".*--relay .*" execStart != null;
assert builtins.match ".*--net-permission noban@192.0.2.0/24.*" execStart != null;
assert builtins.match ".*--net-permission-bind noban@127.0.0.1:18444.*" execStart != null;
assert builtins.match ".*--net-permission-relay=0.*" execStart != null;
assert builtins.match ".*--net-permission-force-relay.*" execStart != null;
assert builtins.match ".*--block-version 2.*" execStart != null;
assert builtins.match ".*--block-min-tx-fee 0.00001000.*" execStart != null;
assert builtins.match ".*--rpc-token-file /run/rbitcoin/rpc.token.*" execStart != null;
assert builtins.match ".*--rpc-work-queue 32.*" execStart != null;
assert builtins.match ".*--api-log /srv/rbitcoin/api.jsonl.*" execStart != null;
assert builtins.match ".*--min-chain-work 01.*" execStart != null;
assert builtins.match ".*--max-tip-age 0.*" execStart != null;
assert builtins.match ".*--check-blocks 0.*" execStart != null;
assert builtins.match ".*--alert-notify /run/rbitcoin/alert.*" execStart != null;
assert builtins.match ".*--startup-notify /run/rbitcoin/ready.*" execStart != null;
assert builtins.match ".*--inhibit-suspend.*" execStart != null;
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
assert builtins.match ".*--datadir-hdd.*" execStart != null;
assert builtins.match ".*--datadir-hdd.*" (
  defaultSystem.config.systemd.services.rbitcoin.serviceConfig.ExecStart
) == null;
assert builtins.match ".*--health-listen 127.0.0.1:9332.*" execStart != null;
assert builtins.match ".*--metrics.*" execStart != null;
assert builtins.match ".*--health-listen.*" (
  defaultSystem.config.systemd.services.rbitcoin.serviceConfig.ExecStart
) == null;
assert builtins.match ".*--metrics.*" (
  defaultSystem.config.systemd.services.rbitcoin.serviceConfig.ExecStart
) == null;
assert builtins.match ".*--sv2-tp-listen 127.0.0.1:18447.*" execStart != null;
assert builtins.match ".*--sv2-tp-authority-sec-file /run/keys/sv2-authority.*" execStart != null;
assert builtins.match ".*--sv2-tp-authority-sec .*" execStart == null;
assert builtins.match ".*--sv2-tp-cert-validity 600.*" execStart != null;
assert builtins.match ".*--sv2-tp-stale-grace 0.*" execStart != null;
assert builtins.match ".*--sv2-tp-fee-delta 0.*" execStart != null;
assert builtins.match ".*--sv2-tp-template-interval 30.*" execStart != null;
assert builtins.match ".*--sv2-tp-idle-timeout 30.*" execStart != null;
assert builtins.match ".*--max-run-secs 1$" execStart != null;
assert builtins.match ".*--max-inbound.*" (
  defaultSystem.config.systemd.services.rbitcoin.serviceConfig.ExecStart
) == null;
assert builtins.match ".*--block-filter-index.*" (
  defaultSystem.config.systemd.services.rbitcoin.serviceConfig.ExecStart
) == null;
assert builtins.match ".*--inhibit-suspend.*" (
  defaultSystem.config.systemd.services.rbitcoin.serviceConfig.ExecStart
) == null;
assert builtins.match ".*--connect.*" (
  defaultSystem.config.systemd.services.rbitcoin.serviceConfig.ExecStart
) == null;
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
assert !builtins.elem metricsNeedHealth (failedAssertions system);
assert builtins.elem cookieTcpOnly (failedAssertions cookieWithoutTcp);
assert builtins.elem cookiePermsNeedFile (failedAssertions cookiePermsAlone);
assert !builtins.elem cookiePermsNeedFile (failedAssertions cookieGroup);
assert builtins.elem metricsNeedHealth (failedAssertions metricsWithoutHealth);
assert builtins.elem "127.0.0.1:9332" (builtins.head rbitcoinScrape.static_configs).targets;
assert !builtins.elem sv2KeyNotInStore (failedAssertions system);
assert builtins.elem sv2KeyNotInStore (failedAssertions sv2KeyInStore);
assert cookieDataDirMode == "0700";
assert builtins.match ".*--listen .*" listenOffExec == null;
assert builtins.match ".*--max-inbound 0.*" listenOffExec != null;
assert builtins.match ".*--no-discover.*" listenOffExec != null;
assert builtins.match ".*--sv2-tp.*" listenOffExec == null;
assert listenOffSystem.config.networking.firewall.allowedTCPPorts == [ ];
assert builtins.match ".*--sp-tweaks .*" spExec != null;
assert builtins.match ".*--sp-tweaks-dust 546.*" spExec != null;
assert builtins.match ".*--max-inbound 125.*" inboundExec != null;
assert builtins.match ".*--rpc .*" unixExec != null;
assert builtins.match ".*--rpc-listen.*" unixExec == null;
assert builtins.match ".*--esplora-listen /run/rbitcoin/esplora.sock.*" unixExec != null;
assert builtins.match ".*--esplora-listen 127.0.0.1:3000.*" unixExec == null;
assert unixSystem.config.networking.firewall.allowedTCPPorts == [ ];
assert unixSystem.config.systemd.tmpfiles.settings."10-rbitcoin"."/run/rbitcoin".d.mode == "0750";
assert builtins.elem "/run/rbitcoin" unixSystem.config.systemd.services.rbitcoin.serviceConfig.ReadWritePaths;
assert builtins.match ".*--esplora-onion=0.*" onionOffExec != null;
assert builtins.match ".*--network signet.*" signetExec != null;
assert builtins.match ".*--signet-challenge 51.*" signetExec != null;
assert builtins.match ".*--signet-block-time 120.*" signetExec != null;
assert builtins.elem spAndPruneMsg (failedAssertions (badSystem {
  silentPaymentIndex = true;
  pruneSeqSigWit = true;
}));
assert builtins.elem signetChallengeMsg (failedAssertions (badSystem {
  signet.challenge = "51";
}));
assert builtins.elem signetTimeMsg (failedAssertions (badSystem {
  network = "signet";
  signet.blockTime = 120;
}));
assert builtins.elem trustSeedMsg (failedAssertions (badSystem {
  trustPeer = "192.0.2.1:8333";
  p2p.seedNodes = [ "seed.example" ];
}));
assert builtins.elem bindNeedsListenMsg (failedAssertions (badSystem {
  p2p.listen = false;
  netPermissionBind = [ "noban@127.0.0.1:18444" ];
}));
assert builtins.elem bindTrustMsg (failedAssertions (badSystem {
  trustPeer = "192.0.2.1:8333";
  netPermissionBind = [ "noban@127.0.0.1:8333" ];
}));
assert builtins.elem esploraSockNeedsEnableMsg (failedAssertions (badSystem {
  esplora.socketPath = "/run/rbitcoin/esplora.sock";
}));
assert builtins.match ".*--esplora-block-template.*" blockTemplateOffExec == null;
assert builtins.elem "/var/log/rbitcoin" apiLogSystem.config.systemd.services.rbitcoin.serviceConfig.ReadWritePaths;
assert apiLogSystem.config.systemd.tmpfiles.settings."10-rbitcoin"."/var/log/rbitcoin".d.mode == "0750";
assert cfg.systemd.tmpfiles.settings."10-rbitcoin"."/srv/rbitcoin".d.mode == "0700";
assert builtins.match ".*--check-blocks 4294967296.*" (execOf { checkBlocks = 4294967296; }) != null;
assert !builtins.elem spAndPruneMsg (failedAssertions system);
pkgs.runCommand "rbitcoin-nixos-module-eval" { } "touch $out"
