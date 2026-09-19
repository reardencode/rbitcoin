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
  ++ optional (cfg.coldDataDir != null) "--datadir-cold"
  ++ optional (cfg.coldDataDir != null) cfg.coldDataDir
  ++ optional cfg.rpc.enable "--rpc-listen"
  ++ optional cfg.rpc.enable (socket cfg.rpc.address cfg.rpc.port)
  ++ optional cfg.electrum.enable "--electrum-listen"
  ++ optional cfg.electrum.enable (socket cfg.electrum.address cfg.electrum.port)
  ++ optional cfg.esplora.enable "--esplora-listen"
  ++ optional cfg.esplora.enable (socket cfg.esplora.address cfg.esplora.port)
  ++ optional (cfg.scripthashIndex || cfg.electrum.enable || cfg.esplora.enable) "--shindex"
  ++ optional cfg.silentPaymentIndex "--sptweaks"
  ++ optional (cfg.proxy != null) "--proxy"
  ++ optional (cfg.proxy != null) cfg.proxy
  ++ optional (cfg.onionProxy != null) "--onion"
  ++ optional (cfg.onionProxy != null) cfg.onionProxy
  ++ optional (!cfg.proxyRandomize) "--proxy-randomize=0"
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
      description = "Optional directory for the large, rarely read Class A inwit store.";
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

    proxy = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "127.0.0.1:9050";
      description = "SOCKS5 proxy HOST:PORT for all P2P outbound.";
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

      openFirewall = mkOption {
        type = types.bool;
        default = false;
        description = "Open the P2P listen port in the NixOS firewall. Ignored when listen is false.";
      };
    };

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
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.coldDataDir == null || cfg.coldDataDir != cfg.dataDir;
        message = "services.rbitcoin.coldDataDir must differ from dataDir";
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
    };

    systemd.services.rbitcoin = {
      description = "rbitcoin full node";
      documentation = [ "https://github.com/reardencode/rbitcoin/blob/master/OPERATOR.md" ];
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];
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
        ReadWritePaths = [ cfg.dataDir ] ++ optional (cfg.coldDataDir != null) cfg.coldDataDir;
      };
    };

    networking.firewall.allowedTCPPorts =
      optional (cfg.p2p.openFirewall && cfg.p2p.listen) cfg.p2p.port
      ++ optional (cfg.electrum.enable && cfg.electrum.openFirewall) cfg.electrum.port
      ++ optional (cfg.esplora.enable && cfg.esplora.openFirewall) cfg.esplora.port;

    environment.systemPackages = [ cfg.package ];
  };
}
