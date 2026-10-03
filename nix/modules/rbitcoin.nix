{ defaultPackage }:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib)
    concatStringsSep
    escapeShellArg
    mkEnableOption
    mkIf
    mkOption
    optional
    types
    ;

  cfg = config.services.rbitcoin;

  p2pPorts = {
    mainnet = 8333;
    testnet = 18333;
    signet = 38333;
    regtest = 18444;
  };

  rpcPorts = {
    mainnet = 8332;
    testnet = 18332;
    signet = 38332;
    regtest = 18443;
  };

  socket =
    address: port:
    if lib.hasInfix ":" address && !lib.hasPrefix "[" address then
      "[${address}]:${toString port}"
    else
      "${address}:${toString port}";

  needTorControl = cfg.tor.control != null || cfg.electrum.hiddenService || cfg.esplora.hiddenService || cfg.p2p.listenOnion;
  needI2pSam = cfg.i2p.sam != null;
  needCjdns = cfg.cjdns.reachable;
  torControlAddr =
    if cfg.tor.control != null then
      cfg.tor.control
    else if cfg.electrum.hiddenService || cfg.esplora.hiddenService || cfg.p2p.listenOnion then
      "127.0.0.1:9051"
    else
      null;

  command = [
    "${cfg.package}/bin/rbitcoin-node"
    "--datadir"
    cfg.dataDir
    "--network"
    cfg.network
  ]
  ++ (
    if cfg.p2p.listen then
      [
        "--listen"
        (socket cfg.p2p.address cfg.p2p.port)
      ]
    else
      [ "--no-listen" ]
  )
  ++ [
    "--log-level"
    cfg.logLevel
  ]
  ++ optional (cfg.p2p.maxInbound != 125) "--max-inbound"
  ++ optional (cfg.p2p.maxInbound != 125) (toString cfg.p2p.maxInbound)
  ++ optional (!cfg.p2p.discover) "--no-discover"
  ++ optional cfg.p2p.listenOnion "--listen-onion"
  ++ optional (cfg.coldDataDir != null) "--datadir-cold"
  ++ optional (cfg.coldDataDir != null) cfg.coldDataDir
  ++ optional cfg.rpc.enable "--rpc-listen"
  ++ optional cfg.rpc.enable (socket cfg.rpc.address cfg.rpc.port)
  ++ optional (cfg.rpc.socketPath != null) "--rpc-socket"
  ++ optional (cfg.rpc.socketPath != null) cfg.rpc.socketPath
  ++ optional (cfg.rpc.cookieFile != null) "--rpc-cookie-file"
  ++ optional (cfg.rpc.cookieFile != null) (toString cfg.rpc.cookieFile)
  ++ optional cfg.electrum.enable "--electrum-listen"
  ++ optional cfg.electrum.enable (socket cfg.electrum.address cfg.electrum.port)
  ++ optional (cfg.electrum.enable && cfg.electrum.maxSubs != null) "--electrum-max-subs"
  ++ optional (cfg.electrum.enable && cfg.electrum.maxSubs != null) (
    toString cfg.electrum.maxSubs
  )
  ++ optional cfg.esplora.enable "--esplora-listen"
  ++ optional cfg.esplora.enable (socket cfg.esplora.address cfg.esplora.port)
  ++ optional cfg.health.enable "--health-listen"
  ++ optional cfg.health.enable (socket cfg.health.address cfg.health.port)
  ++ optional cfg.metrics "--metrics"
  ++ optional (cfg.scripthashIndex || cfg.electrum.enable || cfg.esplora.enable) "--sh-index"
  ++ optional cfg.silentPaymentIndex "--sp-tweaks"
  ++ optional (cfg.proxy != null) "--proxy"
  ++ optional (cfg.proxy != null) cfg.proxy
  ++ optional (cfg.onionProxy != null) "--onion"
  ++ optional (cfg.onionProxy != null) cfg.onionProxy
  ++ optional (!cfg.proxyRandomize) "--proxy-randomize=0"
  ++ lib.concatMap (n: [ "--only-net" n ]) cfg.onlyNet
  ++ optional (torControlAddr != null) "--tor-control"
  ++ optional (torControlAddr != null) torControlAddr
  ++ optional (cfg.tor.controlCookie != null) "--tor-control-cookie"
  ++ optional (cfg.tor.controlCookie != null) (toString cfg.tor.controlCookie)
  ++ optional needI2pSam "--i2p-sam"
  ++ optional needI2pSam cfg.i2p.sam
  ++ optional cfg.i2p.acceptIncoming "--i2p-accept-incoming"
  ++ optional cfg.cjdns.reachable "--cjdns-reachable"
  ++ optional cfg.esplora.hiddenService "--esplora-onion"
  ++ optional cfg.pruneSeqSigWit "--prune-seqsigwit"
  ++ cfg.extraArgs;
in
{
  options.services.rbitcoin = {
    enable = mkEnableOption "rbitcoin full node";

    package = mkOption {
      type = types.package;
      default =
        if builtins.isFunction defaultPackage then
          defaultPackage pkgs.stdenv.hostPlatform.system
        else
          defaultPackage;
      defaultText = lib.literalExpression "inputs.rbitcoin.packages.\${pkgs.system}.rbitcoin-musl";
      description = "The rbitcoin package to run.";
    };

    dataDir = mkOption {
      type = types.path;
      default = "/var/lib/rbitcoin";
      description = "Directory for the node store, mempool, peers, logs, and RPC cookie.";
    };

    coldDataDir = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Optional directory for the large, rarely read Class A seqsigwit store.";
    };

    user = mkOption {
      type = types.str;
      default = "rbitcoin";
      description = "User account under which the node runs.";
    };

    group = mkOption {
      type = types.str;
      default = "rbitcoin";
      description = "Group under which the node runs.";
    };

    network = mkOption {
      type = types.enum [
        "mainnet"
        "testnet"
        "signet"
        "regtest"
      ];
      default = "mainnet";
      description = "Bitcoin network to join.";
    };

    logLevel = mkOption {
      type = types.enum [
        "error"
        "warn"
        "info"
        "debug"
        "trace"
        "off"
      ];
      default = "info";
      description = "Node stderr log level.";
    };

    scripthashIndex = mkOption {
      type = types.bool;
      default = false;
      description = "Build the Class B scripthash index. Electrum and Esplora enable it automatically.";
    };

    silentPaymentIndex = mkOption {
      type = types.bool;
      default = false;
      description = "Build and serve the BIP-352 silent-payment tweak index.";
    };

    pruneSeqSigWit = mkOption {
      type = types.bool;
      default = false;
      description = "Drop Class A seqsigwit below tip-288 heights and advertise NETWORK_LIMITED. Not Core -prune of headers/txout.";
    };

    environment = mkOption {
      type = types.attrsOf types.str;
      default = { };
      description = "Additional environment variables for advanced rbitcoin settings.";
    };

    extraArgs = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = "Additional command-line arguments appended after module-managed arguments.";
    };

    tor = {
      control = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "127.0.0.1:9051";
        description = "System tor control HOST:PORT. Unset skips the control connection.";
      };

      controlCookie = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "/run/tor/control.authcookie";
        description = "Tor control cookie file. Default in the node is /run/tor/control.authcookie when --tor-control is set.";
      };
    };

    i2p = {
      sam = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "127.0.0.1:7656";
        description = "I2P SAM v3 HOST:PORT (system i2pd). Unset skips SAM.";
      };

      acceptIncoming = mkOption {
        type = types.bool;
        default = false;
        description = "STREAM FORWARD to the P2P bind. Requires i2p.sam and (p2p.listen or p2p.listenOnion). Persists {dataDir}/i2p/p2p.priv.";
      };
    };

    cjdns = {
      reachable = mkOption {
        type = types.bool;
        default = false;
        description = "Treat fc00::/8 as CJDNS (dial and advertise). --only-net=cjdns requires this. After/Wants cjdns.service. No in-process router.";
      };
    };

    proxy = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "127.0.0.1:9050";
      description = "SOCKS5 proxy HOST:PORT for all P2P outbound. Also enables isolated local-tx broadcast (new SOCKS circuit after sendraw / Electrum / Esplora submit; not Dandelion++). Standing peers do not INV those txs.";
    };

    onionProxy = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "127.0.0.1:9050";
      description = "SOCKS5 proxy HOST:PORT for onion destinations.";
    };

    proxyRandomize = mkOption {
      type = types.bool;
      default = true;
      description = "Fresh SOCKS username per peer so Tor isolates circuits.";
    };

    onlyNet = mkOption {
      type = types.listOf (types.enum [
        "ipv4"
        "ipv6"
        "onion"
        "i2p"
        "cjdns"
      ]);
      default = [ ];
      description = "Restrict P2P to these networks. onion requires proxy or onionProxy; i2p requires i2p.sam.";
    };

    p2p = {
      address = mkOption {
        type = types.str;
        default = "0.0.0.0";
        description = "Address on which to accept Bitcoin P2P connections.";
      };

      port = mkOption {
        type = types.port;
        default = p2pPorts.${cfg.network};
        description = "Bitcoin P2P listen port.";
      };

      listen = mkOption {
        type = types.bool;
        default = true;
        description = "Bind a P2P listen socket. Set false for outbound-only (no ISP port forward).";
      };

      maxInbound = mkOption {
        type = types.ints.unsigned;
        default = 125;
        description = "Inbound P2P session cap. 0 with listen=false is outbound-only.";
      };

      discover = mkOption {
        type = types.bool;
        default = true;
        description = "Advertise local addresses to peers. Off with --no-discover.";
      };

      listenOnion = mkOption {
        type = types.bool;
        default = false;
        description = "ADD_ONION for the P2P port. Binds 127.0.0.1 even with p2p.listen = false. Requires tor.control (implied 127.0.0.1:9051) and maxInbound > 0. Gossip the onion, not a home IPv4, when discover is off.";
      };

      openFirewall = mkOption {
        type = types.bool;
        default = false;
        description = "Open the P2P listen port in the NixOS firewall. Ignored when listen is false.";
      };
    };

    health = {
      enable = mkEnableOption "the loopback health listener (/healthz, /readyz, and /progress)";

      address = mkOption {
        type = types.str;
        default = "127.0.0.1";
        description = "Address for --health-listen. Keep this on loopback; it is unauthenticated.";
      };

      port = mkOption {
        type = types.port;
        default = 9332;
        description = "Health listen port. Same default as a bare --health-listen.";
      };

      openFirewall = mkOption {
        type = types.bool;
        default = false;
        description = "Open the health port in the firewall. Leave this off unless a probe must dial a non-loopback address.";
      };
    };

    metrics = mkEnableOption "Prometheus GET /metrics on the health listener";

    rpc = {
      enable = mkEnableOption "the JSON-RPC listener";

      address = mkOption {
        type = types.str;
        default = "127.0.0.1";
        description = "Address on which to expose JSON-RPC.";
      };

      port = mkOption {
        type = types.port;
        default = rpcPorts.${cfg.network};
        description = "JSON-RPC listen port.";
      };

      socketPath = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "/run/rbitcoin/rpc.sock";
        description = ''
          Bind the unix JSON-RPC socket here (mode 0660) instead of {dataDir}/rpc.sock (0600).
          Its directory is created mode 0750, so members of `group` (for example mempool's
          backend) can connect without reading the datadir. Independent of `enable` (TCP).
        '';
      };

      cookieFile = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "/run/rbitcoin/rpc.cookie";
        description = ''
          Existing Core-format `username:password` cookie (no trailing newline) accepted as
          HTTP Basic on the TCP listener, alongside the Bearer token. Lets stock mempool use
          `CORE_RPC.COOKIE`. Requires `enable`. The node checks it at startup and never
          creates it or its directory: write both before every start if they live on tmpfs,
          e.g. from a root `ExecStartPre` shell script (`"+" + pkgs.writeShellScript ...`,
          since the unit runs as `user` under ProtectSystem=strict). `user` must be able to
          read it, and mempool must be able to traverse its directory and read the file.
          The unit's PrivateTmp and ProtectHome hide /tmp and /home, so keep it elsewhere
          (e.g. /run/rbitcoin). Format: docs/operator/interfaces.md.
        '';
      };
    };

    electrum = {
      enable = mkEnableOption "the Electrum listener";

      address = mkOption {
        type = types.str;
        default = "127.0.0.1";
        description = "Address on which to expose the Electrum protocol.";
      };

      port = mkOption {
        type = types.port;
        default = 50001;
        description = "Electrum listen port.";
      };

      openFirewall = mkOption {
        type = types.bool;
        default = false;
        description = "Open the Electrum listen port in the NixOS firewall.";
      };

      hiddenService = mkOption {
        type = types.bool;
        default = false;
        description = "ADD_ONION for Electrum when --electrum-listen is on. Implies tor.control 127.0.0.1:9051 if unset.";
      };

      maxSubs = mkOption {
        type = types.nullOr types.ints.positive;
        default = null;
        example = 25000;
        description = ''
          blockchain.scripthash.subscribe cap per Electrum connection (--electrum-max-subs).
          Null keeps the node default (10000). Wallets subscribe every address up to their
          gap limit.
        '';
      };
    };

    esplora = {
      enable = mkEnableOption "the Esplora REST listener";

      address = mkOption {
        type = types.str;
        default = "127.0.0.1";
        description = "Address on which to expose the Esplora REST API.";
      };

      port = mkOption {
        type = types.port;
        default = 3000;
        description = "Esplora REST listen port.";
      };

      openFirewall = mkOption {
        type = types.bool;
        default = false;
        description = "Open the Esplora listen port in the NixOS firewall.";
      };

      hiddenService = mkOption {
        type = types.bool;
        default = false;
        description = "ADD_ONION for Esplora when --esplora-listen is on. Implies tor.control 127.0.0.1:9051 if unset. REST and /ws share the TCP port.";
      };
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.coldDataDir == null || cfg.coldDataDir != cfg.dataDir;
        message = "services.rbitcoin.coldDataDir must differ from dataDir";
      }
      {
        assertion = !cfg.i2p.acceptIncoming || cfg.i2p.sam != null;
        message = "services.rbitcoin.i2p.acceptIncoming requires i2p.sam";
      }
      {
        assertion = !cfg.i2p.acceptIncoming || cfg.p2p.listen || cfg.p2p.listenOnion;
        message = "services.rbitcoin.i2p.acceptIncoming requires p2p.listen or p2p.listenOnion (STREAM FORWARD needs a P2P bind)";
      }
      {
        assertion = !(builtins.elem "cjdns" cfg.onlyNet) || cfg.cjdns.reachable;
        message = "services.rbitcoin.onlyNet cjdns requires cjdns.reachable";
      }
      {
        assertion = cfg.rpc.cookieFile == null || cfg.rpc.enable;
        message = "services.rbitcoin.rpc.cookieFile requires rpc.enable (the cookie is accepted on TCP only)";
      }
      {
        assertion = !cfg.metrics || cfg.health.enable;
        message = "services.rbitcoin.metrics requires health.enable (--metrics needs --health-listen)";
      }
    ];

    users.groups.${cfg.group} = { };
    users.users.${cfg.user} = {
      isSystemUser = true;
      group = cfg.group;
      home = cfg.dataDir;
    };

    systemd.tmpfiles.settings."10-rbitcoin" = {
      "${cfg.dataDir}".d = {
        mode = "0700";
        user = cfg.user;
        group = cfg.group;
      };
    }
    // lib.optionalAttrs (cfg.coldDataDir != null) {
      "${cfg.coldDataDir}".d = {
        mode = "0700";
        user = cfg.user;
        group = cfg.group;
      };
    }
    // lib.optionalAttrs (cfg.rpc.socketPath != null) {
      "${dirOf cfg.rpc.socketPath}".d = {
        mode = "0750";
        user = cfg.user;
        group = cfg.group;
      };
    };

    systemd.services.rbitcoin = {
      description = "rbitcoin full node";
      documentation = [ "https://github.com/reardencode/rbitcoin/blob/master/OPERATOR.md" ];
      wantedBy = [ "multi-user.target" ];
      wants = [
        "network-online.target"
      ]
      ++ optional needTorControl "tor.service"
      ++ optional needI2pSam "i2pd.service"
      ++ optional needCjdns "cjdns.service";
      after = [
        "network-online.target"
      ]
      ++ optional needTorControl "tor.service"
      ++ optional needI2pSam "i2pd.service"
      ++ optional needCjdns "cjdns.service";
      environment = cfg.environment;

      serviceConfig = {
        ExecStart = concatStringsSep " " (map escapeShellArg command);
        User = cfg.user;
        Group = cfg.group;
        Restart = "on-failure";
        RestartSec = "10s";
        KillSignal = "SIGTERM";
        TimeoutStopSec = "5min";
        NoNewPrivileges = true;
        PrivateTmp = true;
        ProtectHome = true;
        ProtectSystem = "strict";
        ReadWritePaths = [
          cfg.dataDir
        ]
        ++ optional (cfg.coldDataDir != null) cfg.coldDataDir
        ++ optional (cfg.rpc.socketPath != null) (dirOf cfg.rpc.socketPath);
      }
      // lib.optionalAttrs (cfg.tor.controlCookie != null) {
        SupplementaryGroups = [ "tor" ];
      };
    };

    networking.firewall.allowedTCPPorts =
      optional (cfg.p2p.openFirewall && cfg.p2p.listen) cfg.p2p.port
      ++ optional (cfg.electrum.enable && cfg.electrum.openFirewall) cfg.electrum.port
      ++ optional (cfg.esplora.enable && cfg.esplora.openFirewall) cfg.esplora.port
      ++ optional (cfg.health.enable && cfg.health.openFirewall) cfg.health.port;

    services.prometheus.scrapeConfigs = mkIf (cfg.metrics && config.services.prometheus.enable) [
      {
        job_name = "rbitcoin";
        static_configs = [
          {
            targets = [ (socket cfg.health.address cfg.health.port) ];
          }
        ];
      }
    ];

    environment.systemPackages = [ cfg.package ];
  };
}
