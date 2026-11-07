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
    mkDefault
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
    testnet4 = 48333;
    signet = 38333;
    regtest = 18444;
  };

  rpcPorts = {
    mainnet = 8332;
    testnet = 18332;
    testnet4 = 48332;
    signet = 38332;
    regtest = 18443;
  };

  socket =
    address: port:
    if lib.hasInfix ":" address && !lib.hasPrefix "[" address then
      "[${address}]:${toString port}"
    else
      "${address}:${toString port}";

  needTorControl = cfg.tor.control != null || (cfg.electrum.enable && cfg.electrum.hiddenService) || (cfg.esplora.enable && cfg.esplora.hiddenService) || cfg.p2p.listenOnion;
  needI2pSam = cfg.i2p.sam != null;
  needCjdns = cfg.cjdns.reachable;
  rpcListening = cfg.rpc.enable || cfg.rpc.unixSocket || cfg.rpc.socketPath != null;
  # Port after the last @. IPv6 is `[addr]:port`. A grant with no port is left out;
  # the node rejects it at start.
  whitebindPort = spec:
    let
      addr = lib.last (lib.splitString "@" spec);
      port =
        if lib.hasInfix "]" addr then
          lib.last (lib.splitString "]:" addr)
        else
          let
            parts = lib.splitString ":" addr;
          in
          if builtins.length parts == 2 then builtins.elemAt parts 1 else "";
    in
    if builtins.match "[0-9]+" port != null then lib.toInt port else null;
  whitebindPorts = lib.filter (p: p != null) (map whitebindPort cfg.netPermissionBind);
  torControlAddr =
    if cfg.tor.control != null then
      cfg.tor.control
    else if (cfg.electrum.enable && cfg.electrum.hiddenService) || (cfg.esplora.enable && cfg.esplora.hiddenService) || cfg.p2p.listenOnion then
      "127.0.0.1:9051"
    else
      null;
  # The node only speaks a TCP control port. An implied address is one this
  # module chose, so NixOS tor must listen there and write the cookie the node
  # reads. An explicit tor.control is the operator's daemon.
  impliedTorControl = cfg.tor.control == null && torControlAddr != null;
  torCookiePath =
    if cfg.tor.controlCookie != null then
      cfg.tor.controlCookie
    else
      "/run/tor/control.authcookie";
  # tmpfiles type d changes the owner of a directory that already exists, and
  # ReadWritePaths would open that whole tree. A child such as /var/lib/rbitcoin
  # is this service's own directory. A child of /run/tor is still Tor's.
  exactSystemDirs = [
    "/"
    "/bin"
    "/boot"
    "/dev"
    "/etc"
    "/home"
    "/lib"
    "/lib64"
    "/mnt"
    "/nix"
    "/opt"
    "/proc"
    "/root"
    "/run"
    "/sbin"
    "/srv"
    "/sys"
    "/tmp"
    "/usr"
    "/var"
    "/var/cache"
    "/var/lib"
    "/var/lock"
    "/var/log"
    "/var/spool"
    "/var/tmp"
  ];
  # The path itself and everything under it. /var/lib stays exact so
  # /var/lib/rbitcoin is allowed. /nix/var/nix is covered by /nix/var.
  ownedTrees = [
    "/boot/efi"
    "/etc/nixos"
    "/etc/ssh"
    "/etc/static"
    "/etc/systemd"
    "/nix/store"
    "/nix/var"
    "/run/booted-system"
    "/run/credentials"
    "/run/current-system"
    "/run/lock"
    "/run/media"
    "/run/nixos"
    "/run/opengl-driver"
    "/run/systemd"
    "/run/tor"
    "/run/user"
    "/run/wrappers"
    "/usr/bin"
    "/usr/include"
    "/usr/lib"
    "/usr/lib64"
    "/usr/local"
    "/usr/sbin"
    "/usr/share"
    "/var/db"
    "/var/empty"
    "/var/lib/i2pd"
    "/var/lib/nixos"
    "/var/lib/private"
    "/var/lib/systemd"
    "/var/lib/tor"
  ];
  unsafeServiceDir = p:
    let
      raw = toString p;
      parts = lib.filter (s: s != "") (lib.splitString "/" raw);
      key = if parts == [ ] then "/" else "/" + lib.concatStringsSep "/" parts;
      inTree = root: key == root || lib.hasPrefix "${root}/" key;
    in
    raw == ""
    || !lib.hasPrefix "/" raw
    || lib.any (s: s == "." || s == "..") parts
    || lib.elem key exactSystemDirs
    || lib.any inTree ownedTrees;
  # CJDNS is fc00::/8: the first octet is 0xfc. `fc::1` is 0x00fc and is not.
  padHextet = s:
    let
      n = lib.stringLength s;
    in
    if n == 0 || n > 4 || builtins.match "[0-9a-f]{1,4}" s == null then
      null
    else
      lib.substring n 4 ("0000" + s);
  expandV6 = ip:
    let
      lower = lib.toLower ip;
      halves = lib.splitString "::" lower;
      groups =
        if builtins.length halves > 2 then
          null
        else if builtins.length halves == 1 then
          let
            g = lib.splitString ":" lower;
          in
          if builtins.length g == 8 then g else null
        else
          let
            left =
              if builtins.elemAt halves 0 == "" then
                [ ]
              else
                lib.splitString ":" (builtins.elemAt halves 0);
            right =
              if builtins.elemAt halves 1 == "" then
                [ ]
              else
                lib.splitString ":" (builtins.elemAt halves 1);
            missing = 8 - builtins.length left - builtins.length right;
          in
          if missing < 0 then
            null
          else
            left ++ lib.genList (_: "0") missing ++ right;
    in
    if groups == null then null else map padHextet groups;
  isCjdnsV6 = ip:
    let
      groups = expandV6 ip;
      first = if groups == null || groups == [ ] then null else builtins.head groups;
    in
    first != null && lib.hasPrefix "fc" first;
  isCjdnsConnect = addr:
    let
      m = builtins.match "[[]([0-9A-Fa-f:.]+)[]]:([0-9]+)" (lib.trim addr);
      port = if m == null then null else lib.toInt (builtins.elemAt m 1);
    in
    m != null && port != null && port <= 65535 && isCjdnsV6 (builtins.head m);

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
  ++ optional (cfg.p2p.maxInbound != 200) "--max-inbound"
  ++ optional (cfg.p2p.maxInbound != 200) (toString cfg.p2p.maxInbound)
  ++ optional (cfg.p2p.maxOutbound != null) "--max-outbound"
  ++ optional (cfg.p2p.maxOutbound != null) (toString cfg.p2p.maxOutbound)
  ++ lib.concatMap (a: [ "--connect" a ]) cfg.p2p.connect
  ++ lib.concatMap (a: [ "--seed-node" a ]) cfg.p2p.seedNodes
  ++ optional cfg.p2p.noSeeds "--no-seeds"
  ++ lib.concatMap (a: [ "--external-ip" a ]) cfg.p2p.externalIp
  ++ optional (cfg.p2p.peerTimeout != null) "--peer-timeout"
  ++ optional (cfg.p2p.peerTimeout != null) (toString cfg.p2p.peerTimeout)
  ++ optional (cfg.asmap != null) "--asmap"
  ++ optional (cfg.asmap != null) cfg.asmap
  ++ lib.concatMap (c: [ "--ua-comment" c ]) cfg.uaComment
  ++ optional (!cfg.p2p.discover) "--no-discover"
  ++ optional cfg.p2p.listenOnion "--listen-onion"
  ++ optional (cfg.coldDataDir != null) "--datadir-cold"
  ++ optional (cfg.coldDataDir != null) cfg.coldDataDir
  ++ optional (cfg.rpc.unixSocket && !cfg.rpc.enable && cfg.rpc.socketPath == null) "--rpc"
  ++ optional cfg.rpc.enable "--rpc-listen"
  ++ optional cfg.rpc.enable (socket cfg.rpc.address cfg.rpc.port)
  ++ optional (cfg.rpc.enable && cfg.rpc.rest) "--rest"
  ++ optional (cfg.rpc.socketPath != null) "--rpc-socket"
  ++ optional (cfg.rpc.socketPath != null) cfg.rpc.socketPath
  ++ optional (cfg.rpc.cookieFile != null) "--rpc-cookie-file"
  ++ optional (cfg.rpc.cookieFile != null) (toString cfg.rpc.cookieFile)
  ++ optional (cfg.rpc.cookiePerms != null) "--rpc-cookie-perms"
  ++ optional (cfg.rpc.cookiePerms != null) cfg.rpc.cookiePerms
  ++ optional (cfg.rpc.clientVersion != null) "--rpc-client-version"
  ++ optional (cfg.rpc.clientVersion != null) (toString cfg.rpc.clientVersion)
  ++ optional (rpcListening && cfg.rpc.tokenFile != null) "--rpc-token-file"
  ++ optional (rpcListening && cfg.rpc.tokenFile != null) cfg.rpc.tokenFile
  ++ optional (rpcListening && cfg.rpc.workQueue != null) "--rpc-work-queue"
  ++ optional (rpcListening && cfg.rpc.workQueue != null) (toString cfg.rpc.workQueue)
  ++ optional cfg.electrum.enable "--electrum-listen"
  ++ optional cfg.electrum.enable (socket cfg.electrum.address cfg.electrum.port)
  ++ optional (cfg.electrum.enable && cfg.electrum.maxSubs != null) "--electrum-max-subs"
  ++ optional (cfg.electrum.enable && cfg.electrum.maxSubs != null) (
    toString cfg.electrum.maxSubs
  )
  ++ optional cfg.esplora.enable "--esplora-listen"
  ++ optional cfg.esplora.enable (
    if cfg.esplora.socketPath != null then
      cfg.esplora.socketPath
    else
      socket cfg.esplora.address cfg.esplora.port
  )
  ++ optional (cfg.esplora.enable && cfg.esplora.blockTemplate) "--esplora-block-template"
  ++ optional (cfg.esplora.enable && cfg.esplora.maxInflight != null) "--esplora-max-inflight"
  ++ optional (cfg.esplora.enable && cfg.esplora.maxInflight != null) (
    toString cfg.esplora.maxInflight
  )
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
  ++ optional (cfg.electrum.enable && cfg.electrum.hiddenService) "--electrum-onion"
  ++ optional (cfg.esplora.enable && cfg.esplora.hiddenService) "--esplora-onion"
  ++ optional (cfg.electrum.enable && cfg.electrum.i2p) "--electrum-i2p"
  ++ optional (cfg.esplora.enable && cfg.esplora.i2p) "--esplora-i2p"
  ++ optional cfg.pruneSeqSigWit "--prune-seqsigwit"
  ++ optional (cfg.pruneSeqSigwitRamThresholdBytes != null) "--prune-seqsigwit-ram-threshold-bytes"
  ++ optional (cfg.pruneSeqSigwitRamThresholdBytes != null) (
    toString cfg.pruneSeqSigwitRamThresholdBytes
  )
  ++ optional cfg.blockFilterIndex "--block-filter-index"
  ++ optional (cfg.maxShCreates != null) "--max-sh-creates"
  ++ optional (cfg.maxShCreates != null) (toString cfg.maxShCreates)
  ++ optional (cfg.spTweaksDust != null) "--sp-tweaks-dust"
  ++ optional (cfg.spTweaksDust != null) (toString cfg.spTweaksDust)
  ++ optional (cfg.signet.challenge != null) "--signet-challenge"
  ++ optional (cfg.signet.challenge != null) cfg.signet.challenge
  ++ optional (cfg.signet.blockTime != null) "--signet-block-time"
  ++ optional (cfg.signet.blockTime != null) (toString cfg.signet.blockTime)
  ++ optional cfg.mempool.blocksOnly "--blocks-only"
  ++ optional (!cfg.mempool.persist) "--persist-mempool=0"
  ++ optional (!cfg.mempool.prefillCompact) "--prefill-compact=0"
  ++ optional (cfg.mempool.sizeMb != null) "--mempool-size-mb"
  ++ optional (cfg.mempool.sizeMb != null) (toString cfg.mempool.sizeMb)
  ++ optional (cfg.mempool.expiry != null) "--mempool-expiry"
  ++ optional (cfg.mempool.expiry != null) (toString cfg.mempool.expiry)
  ++ optional (cfg.mempool.minRelayTxFee != null) "--min-relay-tx-fee"
  ++ optional (cfg.mempool.minRelayTxFee != null) cfg.mempool.minRelayTxFee
  ++ optional (cfg.mempool.limitClusterCount != null) "--limit-cluster-count"
  ++ optional (cfg.mempool.limitClusterCount != null) (toString cfg.mempool.limitClusterCount)
  ++ optional (cfg.mempool.limitClusterSize != null) "--limit-cluster-size"
  ++ optional (cfg.mempool.limitClusterSize != null) (toString cfg.mempool.limitClusterSize)
  ++ optional (cfg.mempool.bytesPerSigop != null) "--bytes-per-sigop"
  ++ optional (cfg.mempool.bytesPerSigop != null) (toString cfg.mempool.bytesPerSigop)
  ++ optional (cfg.mempool.blockReservedSigops != null) "--block-reserved-sigops"
  ++ optional (cfg.mempool.blockReservedSigops != null) (
    toString cfg.mempool.blockReservedSigops
  )
  ++ optional cfg.trusted "--trusted"
  ++ optional cfg.alwaysRelay "--always-relay"
  ++ optional cfg.relay "--relay"
  ++ lib.concatMap (s: [ "--net-permission" s ]) cfg.netPermission
  ++ lib.concatMap (s: [ "--net-permission-bind" s ]) cfg.netPermissionBind
  ++ optional (!cfg.netPermissionRelay) "--net-permission-relay=0"
  ++ optional cfg.netPermissionForceRelay "--net-permission-force-relay"
  ++ optional (cfg.blockVersion != null) "--block-version"
  ++ optional (cfg.blockVersion != null) (toString cfg.blockVersion)
  ++ optional (cfg.blockMinTxFee != null) "--block-min-tx-fee"
  ++ optional (cfg.blockMinTxFee != null) cfg.blockMinTxFee
  ++ optional (cfg.apiLog != null) "--api-log"
  ++ optional (cfg.apiLog != null) cfg.apiLog
  ++ optional (cfg.minChainWork != null) "--min-chain-work"
  ++ optional (cfg.minChainWork != null) cfg.minChainWork
  ++ optional (cfg.maxTipAge != null) "--max-tip-age"
  ++ optional (cfg.maxTipAge != null) (toString cfg.maxTipAge)
  ++ optional (cfg.checkBlocks != null) "--check-blocks"
  ++ optional (cfg.checkBlocks != null) (toString cfg.checkBlocks)
  ++ optional (cfg.alertNotify != null) "--alert-notify"
  ++ optional (cfg.alertNotify != null) cfg.alertNotify
  ++ optional (cfg.startupNotify != null) "--startup-notify"
  ++ optional (cfg.startupNotify != null) cfg.startupNotify
  ++ optional cfg.inhibitSuspend "--inhibit-suspend"
  ++ optional cfg.datadirHdd "--datadir-hdd"
  ++ optional (cfg.milestone != null) "--milestone"
  ++ optional (cfg.milestone != null) (toString cfg.milestone)
  ++ optional (cfg.heavyShCreates != null) "--heavy-sh-creates"
  ++ optional (cfg.heavyShCreates != null) (toString cfg.heavyShCreates)
  ++ optional (cfg.storeReadBudget != null) "--store-read-budget"
  ++ optional (cfg.storeReadBudget != null) (toString cfg.storeReadBudget)
  ++ optional (cfg.trustPeer != null) "--trust-peer"
  ++ optional (cfg.trustPeer != null) cfg.trustPeer
  ++ lib.optionals cfg.sv2.tp.enable [
    "--sv2-tp-listen"
    (socket cfg.sv2.tp.address cfg.sv2.tp.port)
    "--sv2-tp-authority-sec-file"
    (toString cfg.sv2.tp.authoritySecretFile)
    "--sv2-tp-cert-validity"
    (toString cfg.sv2.tp.certValidity)
    "--sv2-tp-stale-grace"
    (toString cfg.sv2.tp.staleGrace)
    "--sv2-tp-fee-delta"
    (toString cfg.sv2.tp.feeDelta)
    "--sv2-tp-template-interval"
    (toString cfg.sv2.tp.templateInterval)
    "--sv2-tp-idle-timeout"
    (toString cfg.sv2.tp.idleTimeout)
  ]
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
      description = ''
        Directory for the node store, mempool, peers, logs, and RPC cookie.
        A system directory such as `/`, `/var`, or `/var/lib` is refused.
        So is `/run/tor`, `/var/lib/tor`, `/var/lib/i2pd`, or anything inside those trees.
      '';
    };

    trustPeer = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "192.0.2.1:8333";
      description = ''
        Pass `--trust-peer ADDR`. Null omits the flag and leaves P2P listen on.
        The address uses the same grammar as `--connect` (host:port, and `[IPv6]:port`).
        An address in `fc00::/8` requires `cjdns.reachable`.
        Exactly one peer: the module also passes `--no-listen` and `--max-inbound 0`.
        Do not combine it with `p2p.listen`, `p2p.listenOnion`, or `p2p.maxInbound` above 0.
        Flag syntax and start errors: docs/operator/operations.md.
        Which faults warn: COMPAT.md.
      '';
    };

    milestone = mkOption {
      type = types.nullOr types.ints.unsigned;
      default = null;
      example = 840000;
      description = ''
        Pass `--milestone HEIGHT`. Null omits the flag: mainnet and testnet
        keep the anchored script-skip default, and signet and testnet4 check
        every script.
        An explicit height is height-only.
      '';
    };

    coldDataDir = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = ''
        Optional directory for append-only IBD files (seqsigwit, txstat, input, block filters, silent-payment tweaks).
        A system directory such as `/var` or `/srv` is refused.
        So is `/run/tor`, `/var/lib/tor`, `/var/lib/i2pd`, or anything inside those trees.
      '';
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
        "testnet4"
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

    heavyShCreates = mkOption {
      type = types.nullOr (types.ints.between 0 4294967295);
      default = null;
      example = 100000;
      description = ''
        Pass `--heavy-sh-creates N`. An unpaged Electrum or Esplora scripthash
        join with more than N creates waits until no other such join is running
        on the node. Null omits the flag and leaves the node default (10000).
        0 turns the wait off. It matters once `--max-sh-creates` is raised past it.
      '';
    };

    storeReadBudget = mkOption {
      type = types.nullOr types.ints.positive;
      default = null;
      example = 8;
      description = ''
        Pass `--store-read-budget N`. Concurrent API store reads across RPC,
        REST, Electrum, Esplora, and BlindBit. Null omits the flag. The node
        then allows 1 read when `datadirHdd` is set, otherwise one less than
        the core count (minimum 1). An explicit N overrides `datadirHdd`.
      '';
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

    datadirHdd = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Pass `--datadir-hdd`. The main datadir is on rotating media.
        The module does not probe the block device. Default off keeps the SSD confirm schedule.
      '';
    };

    asmap = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "/var/lib/rbitcoin/ip_asn.dat";
      description = ''
        Pass `--asmap PATH` (a Core `ip_asn.dat`, absolute or relative to the datadir).
        Null omits the flag: the node still uses `{dataDir}/ip_asn.dat` when that file exists.
      '';
    };

    uaComment = mkOption {
      type = types.listOf types.str;
      default = [ ];
      example = [ "nixos" ];
      description = "Repeatable `--ua-comment` strings in the BIP14 subversion.";
    };

    blockFilterIndex = mkOption {
      type = types.bool;
      default = false;
      description = "Pass `--block-filter-index` (BIP158 basic filters). Independent of the scripthash index.";
    };

    pruneSeqSigwitRamThresholdBytes = mkOption {
      type = types.nullOr types.ints.unsigned;
      default = null;
      example = 0;
      description = ''
        Pass `--prune-seqsigwit-ram-threshold-bytes`. Null keeps the node default
        (268435456). 0 keeps nothing in RAM.
      '';
    };

    maxShCreates = mkOption {
      type = types.nullOr (types.ints.between 0 4294967295);
      default = null;
      example = 0;
      description = ''
        Pass `--max-sh-creates`. Null keeps the node default (10000). 0 is unlimited.
        An unpaged Electrum or Esplora join above the cap is refused. A paged request still returns that page.
      '';
    };

    spTweaksDust = mkOption {
      type = types.nullOr types.ints.unsigned;
      default = null;
      example = 546;
      description = ''
        Pass `--sp-tweaks-dust SATS`. Null keeps the node default (1000).
        0 serves every P2TR output. 546 matches Cake electrs.
      '';
    };

    signet = {
      challenge = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "51";
        description = ''
          Pass `--signet-challenge HEX` for a custom signet. Requires `network = "signet"`.
          Null keeps the default global signet challenge.
        '';
      };

      blockTime = mkOption {
        type = types.nullOr types.ints.positive;
        default = null;
        example = 600;
        description = ''
          Pass `--signet-block-time SECS`. Requires `signet.challenge`.
          Null keeps the node default (600) once a custom challenge is set.
        '';
      };
    };

    mempool = {
      sizeMb = mkOption {
        type = types.nullOr types.ints.positive;
        default = null;
        example = 100;
        description = ''
          Pass `--mempool-size-mb`. The node stores `N × 1_000_000` weight units, not MiB.
          Null keeps the node default (300).
        '';
      };

      expiry = mkOption {
        type = types.nullOr types.ints.positive;
        default = null;
        example = 336;
        description = "Pass `--mempool-expiry` hours. Null keeps the node default. Minimum 1.";
      };

      minRelayTxFee = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "0.00000100";
        description = ''
          Pass `--min-relay-tx-fee` as a BTC decimal. Null keeps the Libre default (100 sat/kvB).
          `0` is no floor.
        '';
      };

      blocksOnly = mkOption {
        type = types.bool;
        default = false;
        description = "Pass `--blocks-only`.";
      };

      persist = mkOption {
        type = types.bool;
        default = true;
        description = "Mempool persistence. False passes `--persist-mempool=0`. True omits the flag.";
      };

      prefillCompact = mkOption {
        type = types.bool;
        default = true;
        description = "BIP152 compact prefills. False passes `--prefill-compact=0`. True omits the flag.";
      };

      limitClusterCount = mkOption {
        type = types.nullOr (types.ints.between 0 4294967295);
        default = null;
        description = "Pass `--limit-cluster-count`. Null keeps the node default.";
      };

      limitClusterSize = mkOption {
        type = types.nullOr (types.ints.between 0 4294967295);
        default = null;
        description = "Pass `--limit-cluster-size` in thousands of virtual bytes. Null keeps the node default.";
      };

      bytesPerSigop = mkOption {
        type = types.nullOr types.ints.unsigned;
        default = null;
        example = 20;
        description = "Pass `--bytes-per-sigop`. Null keeps the node default (20). 0 disables the sigop size floor.";
      };

      blockReservedSigops = mkOption {
        type = types.nullOr (types.ints.between 0 80000);
        default = null;
        description = "Pass `--block-reserved-sigops`. Null keeps the node default (400). At most 80000.";
      };
    };

    trusted = mkOption {
      type = types.bool;
      default = false;
      description = "Pass `--trusted` so inbound peers are not evicted or banned.";
    };

    alwaysRelay = mkOption {
      type = types.bool;
      default = false;
      description = "Pass `--always-relay` so inbound transactions are always announced.";
    };

    relay = mkOption {
      type = types.bool;
      default = false;
      description = "Pass `--relay` to permit transaction relay to inbound peers while `mempool.blocksOnly` is set.";
    };

    netPermission = mkOption {
      type = types.listOf types.str;
      default = [ ];
      example = [ "noban@192.0.2.0/24" ];
      description = "Repeatable `--net-permission` CIDR grants (IPv4 and IPv6).";
    };

    netPermissionBind = mkOption {
      type = types.listOf types.str;
      default = [ ];
      example = [ "noban@127.0.0.1:8333" ];
      description = ''
        Repeatable `--net-permission-bind` grants. Requires `p2p.listen`.
        Refused with `trustPeer`: the node turns a whitebind into a listen socket,
        and trust-peer then rejects that socket.
        When `p2p.openFirewall` is set, the firewall also opens each grant's port.
      '';
    };

    netPermissionRelay = mkOption {
      type = types.bool;
      default = true;
      description = "Implicit relay on a bare CIDR grant. False passes `--net-permission-relay=0`.";
    };

    netPermissionForceRelay = mkOption {
      type = types.bool;
      default = false;
      description = "Pass `--net-permission-force-relay` so a bare CIDR grant includes forcerelay.";
    };

    blockVersion = mkOption {
      type = types.nullOr (types.ints.between (-2147483648) 2147483647);
      default = null;
      description = "Pass `--block-version` for the generate and template version overlay. Null omits the flag.";
    };

    blockMinTxFee = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "0.00001000";
      description = "Pass `--block-min-tx-fee` as a BTC decimal for template selection. Null keeps the node default.";
    };

    apiLog = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "/var/lib/rbitcoin/api.jsonl";
      description = ''
        Pass `--api-log PATH` (one JSON line per Electrum, Esplora, and RPC call).
        The parent directory is created mode 0750 when it is not `dataDir`, `coldDataDir`,
        or an RPC or Esplora socket or token directory, and that directory is writable
        under ProtectSystem=strict. The parent must be a directory this service owns.
        A system directory such as `/`, `/run`, `/tmp`, `/var/log`, or `/var/lib` is refused.
        So is a file inside `/run/tor`, `/var/lib/tor`, or `/var/lib/i2pd`.
      '';
    };

    minChainWork = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "0x0000000000000000000000000000000000000000000000000000000100000000";
      description = ''
        Pass `--min-chain-work HEX` (optional `0x`, at most 64 hex digits).
        Null keeps Core's minimum on mainnet, testnet3, and testnet4, and leaves signet and regtest unset.
      '';
    };

    maxTipAge = mkOption {
      type = types.nullOr types.ints.unsigned;
      default = null;
      example = 86400;
      description = "Pass `--max-tip-age` seconds. Null keeps the node default (24h). 0 is allowed.";
    };

    checkBlocks = mkOption {
      type = types.nullOr types.int;
      default = null;
      example = 6;
      description = ''
        Pass `--check-blocks`. Null keeps the node default (6).
        0, a negative value, or a value above 4294967295 revalidates the whole chain.
      '';
    };

    alertNotify = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "/run/rbitcoin/alert";
      description = ''
        Pass `--alert-notify CMD`. The node substitutes `%s` with the warning and runs the command once.
        The unit writes each `%` as `%%` so systemd leaves it for the node.
      '';
    };

    startupNotify = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "/run/rbitcoin/ready";
      description = ''
        Pass `--startup-notify CMD`. The node runs it once the process is ready.
        The unit writes each `%` as `%%` so systemd leaves it for the node.
      '';
    };

    inhibitSuspend = mkOption {
      type = types.bool;
      default = false;
      description = "Pass `--inhibit-suspend` so logind does not suspend while the node runs.";
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
        description = ''
          System tor control HOST:PORT. Unset skips the control connection
          unless an onion flag implies 127.0.0.1:9051. An explicit address is
          the operator's daemon: the module does not enable services.tor for it.
        '';
      };

      controlCookie = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "/run/tor/control.authcookie";
        description = ''
          Tor control cookie file. When this is null and Tor control is on, the node reads
          /run/tor/control.authcookie. The unit joins group tor in either case, and creates
          that group when it is missing, with the NixOS tor gid.
          An implied control port also sets this path as CookieAuthFile.
          That path must be a file directly in `/run/tor` or `/var/lib/tor`, the only
          directories the NixOS tor unit can write. A `..` segment is refused.
        '';
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
      description = "Restrict P2P to these networks. onion requires proxy or onionProxy; i2p requires i2p.sam; cjdns requires cjdns.reachable.";
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
        default = 200;
        description = ''
          Inbound P2P session cap (`--max-inbound`). 200 omits the flag and matches the node default.
          0 with listen=false is outbound-only.
        '';
      };

      maxOutbound = mkOption {
        type = types.nullOr types.ints.positive;
        default = null;
        example = 8;
        description = "Pass `--max-outbound`. Null keeps the node default (16). Minimum 1.";
      };

      connect = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [ "192.0.2.10:8333" ];
        description = ''
          Repeatable `--connect` addresses (host:port, `.onion:port`, `{52}.b32.i2p:port`, or `[IPv6]:port`).
          An address in `fc00::/8` requires `cjdns.reachable`.
          With `trustPeer`, leave this empty or set it to that same single address.
        '';
      };

      seedNodes = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [ "seed.example.com" ];
        description = "Repeatable `--seed-node` hosts. Refused together with `trustPeer`.";
      };

      noSeeds = mkOption {
        type = types.bool;
        default = false;
        description = "Pass `--no-seeds`.";
      };

      externalIp = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [ "203.0.113.5" ];
        description = "Repeatable `--external-ip` values (an IP or a v3 `.onion` host) for `getnetworkinfo.localaddresses`.";
      };

      peerTimeout = mkOption {
        type = types.nullOr types.ints.positive;
        default = null;
        example = 60;
        description = "Pass `--peer-timeout` seconds. Null keeps the node default. 0 is refused.";
      };

      discover = mkOption {
        type = types.bool;
        default = true;
        description = "Advertise local addresses to peers. Off with --no-discover.";
      };

      listenOnion = mkOption {
        type = types.bool;
        default = false;
        description = ''
          ADD_ONION for the P2P port. Binds 127.0.0.1 even with p2p.listen = false.
          Requires tor.control (implied 127.0.0.1:9051) and maxInbound > 0.
          The module refuses a 0 cap. An implied port enables services.tor, opens
          127.0.0.1:9051, and writes a group-readable cookie at the control cookie path.
          The unit joins group tor, and creates that group with the NixOS tor gid
          when it is missing, so it can read the cookie.
          Gossip the onion, not a home IPv4, when discover is off.
        '';
      };

      openFirewall = mkOption {
        type = types.bool;
        default = false;
        description = "Open the P2P listen port, and any netPermissionBind port, in the NixOS firewall. Ignored when listen is false.";
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
          A parent that is a system directory, such as `/`, `/run`, `/tmp`, `/var/log`, `/run/tor`, or `/var/lib/tor`, is refused.
        '';
      };

      unixSocket = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Pass `--rpc` so `{dataDir}/rpc.sock` is served without TCP.
          `enable` and `socketPath` already turn the unix socket on, and then this option adds no flag.
        '';
      };

      tokenFile = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "/run/rbitcoin/rpc.token";
        description = ''
          Pass `--rpc-token-file`. Null keeps `{dataDir}/rpc.token`.
          Requires `enable`, `unixSocket`, or `socketPath` (the node writes the file only when an RPC listener starts).
          The node creates the file mode 0600. The parent directory is created mode 0750
          when it is not `dataDir` and not the `socketPath` directory.
          A parent that is a system directory, such as `/`, `/run`, `/tmp`, `/var/log`, `/run/tor`, or `/var/lib/tor`, is refused.
        '';
      };

      workQueue = mkOption {
        type = types.nullOr types.ints.unsigned;
        default = null;
        example = 32;
        description = ''
          Pass `--rpc-work-queue`. Null keeps the node default (16). 0 is that same default.
          Requires `enable`, `unixSocket`, or `socketPath`.
        '';
      };

      rest = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Pass `--rest` so unauthenticated `/rest/` is served on the RPC listener.
          Off by default. Requires `enable` (TCP). The route uses its own queue,
          not the RPC work queue.
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
          A group-readable cookie (mode 0640) also needs `cookiePerms = "group"`.
        '';
      };

      cookiePerms = mkOption {
        type = types.nullOr (types.enum [ "owner" "group" "all" ]);
        default = null;
        example = "group";
        description = ''
          Pass `--rpc-cookie-perms`. The node never creates or chmods the cookie.
          `null` leaves the node default (`owner`): group or world bits refuse startup.
          `group` allows a 0640 file (group read) shared with mempool and refuses
          group write. `all` allows world read (0644) and refuses group or world
          write. The check is Unix mode bits. Requires `cookieFile`. Omitted from the unit
          argv when null, so the default service command does not grow a flag.
        '';
      };

      clientVersion = mkOption {
        type = types.nullOr (types.ints.between 1 1000000);
        default = null;
        example = 310000;
        description = ''
          Pass `--rpc-client-version`: the integer `getnetworkinfo.version` reports.
          `null` leaves the node default (190000, the Core 0.19 response shapes).
          Only that integer changes; no RPC is added. Bark's captaind needs 310000.
          Omitted from the unit argv when null.
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
        description = ''
          ADD_ONION for Electrum (`--electrum-onion`). Requires `enable` on 127.0.0.1 or 0.0.0.0.
          Implies tor.control 127.0.0.1:9051 if unset. That implied port enables
          services.tor, opens 127.0.0.1:9051, and writes a group-readable cookie
          at the control cookie path. The unit joins group tor so it can read it.
        '';
      };

      i2p = mkOption {
        type = types.bool;
        default = false;
        description = "I2P destination ({dataDir}/i2p/electrum.priv) and STREAM FORWARD for Electrum (--electrum-i2p). Needs electrum.enable on 127.0.0.1 or 0.0.0.0 and i2p.sam. Independent of i2p.acceptIncoming.";
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

      socketPath = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "/run/rbitcoin/esplora.sock";
        description = ''
          Pass `--esplora-listen` a filesystem path (unix HTTP, mode 0660) instead of `address`:`port`.
          Requires `enable`. The parent directory is created mode 0750 when it is not `dataDir`.
          A parent that is a system directory, such as `/`, `/run`, `/tmp`, `/var/log`, `/run/tor`, or `/var/lib/tor`, is refused. `openFirewall` is ignored.
        '';
      };

      blockTemplate = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Pass `--esplora-block-template` so GET /block-template serves GBT JSON.
          Requires `enable`. The flag is omitted when the listener is off.
        '';
      };

      hiddenService = mkOption {
        type = types.bool;
        default = false;
        description = ''
          ADD_ONION for Esplora (`--esplora-onion`). Requires `enable` on 127.0.0.1 or 0.0.0.0.
          Implies tor.control 127.0.0.1:9051 if unset. That implied port enables
          services.tor, opens 127.0.0.1:9051, and writes a group-readable cookie
          at the control cookie path. The unit joins group tor so it can read it.
          REST and /ws share the TCP port.
        '';
      };

      i2p = mkOption {
        type = types.bool;
        default = false;
        description = "I2P destination ({dataDir}/i2p/esplora.priv) and STREAM FORWARD for Esplora (--esplora-i2p). Needs esplora.enable on 127.0.0.1 or 0.0.0.0 and i2p.sam. Independent of i2p.acceptIncoming.";
      };

      maxInflight = mkOption {
        # Upper bound is tokio's `Semaphore::MAX_PERMITS` on 64-bit (2^61 - 1).
        type = types.nullOr (types.ints.between 1 2305843009213693951);
        default = null;
        example = 1024;
        description = ''
          Esplora requests in flight across the whole listener (--esplora-max-inflight).
          Null keeps the node default (256). Further requests wait for a slot; the
          wait counts against the request timeout (408).
        '';
      };
    };

    sv2.tp = {
      enable = mkEnableOption "the Stratum v2 Template Provider (TDP over Noise)";

      address = mkOption {
        type = types.str;
        default = "127.0.0.1";
        description = "Address on which to serve SV2 templates.";
      };

      port = mkOption {
        type = types.port;
        default = 8442;
        description = "SV2 Template Provider listen port.";
      };

      authoritySecretFile = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "/run/keys/sv2-authority";
        description = "Runtime path to the secp256k1 authority secret (64 hex or SRI key-utils base58check), readable by the service user. Passed as --sv2-tp-authority-sec-file so the key stays out of argv. A store path (including an interpolated `./key`) is refused: the store is world-readable.";
      };

      certValidity = mkOption {
        type = types.ints.between 1 4294967295;
        default = 3600;
        description = "Seconds each per-connection Noise certificate is valid.";
      };

      staleGrace = mkOption {
        type = types.ints.between 0 86400;
        default = 10;
        description = "Seconds a replaced tip's templates still answer RequestTransactionData and SubmitSolution.";
      };

      feeDelta = mkOption {
        type = types.ints.unsigned;
        default = 1000;
        description = "Sats a same-tip rebuild must gain over a client's last template to be pushed.";
      };

      templateInterval = mkOption {
        type = types.ints.between 1 86400;
        default = 5;
        description = "Seconds between fee checks; a fee push never comes sooner than this after a client's last template.";
      };

      idleTimeout = mkOption {
        type = types.ints.between 0 86400;
        default = 0;
        description = ''
          Pass `--sv2-tp-idle-timeout` seconds after the first CoinbaseOutputConstraints with no client frame.
          0 never drops a quiet pool. Passed whenever `enable` is set.
        '';
      };

      openFirewall = mkOption {
        type = types.bool;
        default = false;
        description = "Open the SV2 Template Provider port in the NixOS firewall.";
      };
    };
  };

  config = mkIf cfg.enable {
    services.rbitcoin.p2p.listen = mkIf (cfg.trustPeer != null) (mkDefault false);
    services.rbitcoin.p2p.maxInbound = mkIf (cfg.trustPeer != null) (mkDefault 0);
    assertions = [
      {
        assertion = !cfg.electrum.i2p || cfg.electrum.enable;
        message = "services.rbitcoin.electrum.i2p requires electrum.enable";
      }
      {
        assertion = !cfg.esplora.i2p || cfg.esplora.enable;
        message = "services.rbitcoin.esplora.i2p requires esplora.enable";
      }
      {
        assertion = !(cfg.electrum.hiddenService || cfg.electrum.i2p) || builtins.elem cfg.electrum.address [ "127.0.0.1" "0.0.0.0" ];
        message = "services.rbitcoin.electrum.hiddenService and electrum.i2p forward to 127.0.0.1; electrum.address must be 127.0.0.1 or 0.0.0.0";
      }
      {
        assertion = !(cfg.esplora.hiddenService || cfg.esplora.i2p) || builtins.elem cfg.esplora.address [ "127.0.0.1" "0.0.0.0" ];
        message = "services.rbitcoin.esplora.hiddenService and esplora.i2p forward to 127.0.0.1; esplora.address must be 127.0.0.1 or 0.0.0.0";
      }
      {
        assertion = !(cfg.esplora.hiddenService || cfg.esplora.i2p) || cfg.esplora.socketPath == null;
        message = "services.rbitcoin.esplora.hiddenService and esplora.i2p need a TCP listener; unset esplora.socketPath";
      }
      {
        assertion = !(cfg.electrum.i2p || cfg.esplora.i2p) || cfg.i2p.sam != null;
        message = "services.rbitcoin.electrum.i2p and esplora.i2p require i2p.sam";
      }
      {
        assertion = cfg.trustPeer == null || !cfg.p2p.listen;
        message = "services.rbitcoin.trustPeer cannot be combined with p2p.listen";
      }
      {
        assertion = cfg.trustPeer == null || !cfg.p2p.listenOnion;
        message = "services.rbitcoin.trustPeer cannot be combined with p2p.listenOnion";
      }
      {
        assertion = !cfg.p2p.listenOnion || cfg.p2p.maxInbound > 0;
        message = "services.rbitcoin.p2p.listenOnion requires p2p.maxInbound > 0";
      }
      {
        assertion = cfg.trustPeer == null || cfg.p2p.maxInbound == 0;
        message = "services.rbitcoin.trustPeer cannot be combined with p2p.maxInbound greater than 0";
      }
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
        assertion = !(builtins.elem "onion" cfg.onlyNet) || cfg.proxy != null || cfg.onionProxy != null;
        message = "services.rbitcoin.onlyNet onion requires proxy or onionProxy";
      }
      {
        assertion = !(builtins.elem "i2p" cfg.onlyNet) || cfg.i2p.sam != null;
        message = "services.rbitcoin.onlyNet i2p requires i2p.sam";
      }
      {
        assertion = cfg.cjdns.reachable || !lib.any isCjdnsConnect cfg.p2p.connect;
        message = "services.rbitcoin.p2p.connect to a CJDNS address requires cjdns.reachable";
      }
      {
        assertion = cfg.trustPeer == null || cfg.cjdns.reachable || !isCjdnsConnect cfg.trustPeer;
        message = "services.rbitcoin.trustPeer to a CJDNS address requires cjdns.reachable";
      }
      {
        assertion = cfg.rpc.cookieFile == null || cfg.rpc.enable;
        message = "services.rbitcoin.rpc.cookieFile requires rpc.enable (the cookie is accepted on TCP only)";
      }
      {
        assertion = cfg.rpc.cookiePerms == null || cfg.rpc.cookieFile != null;
        message = "services.rbitcoin.rpc.cookiePerms requires rpc.cookieFile";
      }
      {
        assertion = !cfg.metrics || cfg.health.enable;
        message = "services.rbitcoin.metrics requires health.enable (--metrics needs --health-listen)";
      }
      {
        assertion = !cfg.sv2.tp.enable || cfg.sv2.tp.authoritySecretFile != null;
        message = "services.rbitcoin.sv2.tp.enable requires sv2.tp.authoritySecretFile";
      }
      {
        assertion =
          cfg.sv2.tp.authoritySecretFile == null
          || !lib.hasPrefix "${builtins.storeDir}/" cfg.sv2.tp.authoritySecretFile;
        message = "services.rbitcoin.sv2.tp.authoritySecretFile must not be a store path (the store is world-readable)";
      }
      {
        assertion = !cfg.silentPaymentIndex || !cfg.pruneSeqSigWit;
        message = "services.rbitcoin.silentPaymentIndex cannot be combined with pruneSeqSigWit";
      }
      {
        assertion = cfg.signet.challenge == null || cfg.network == "signet";
        message = "services.rbitcoin.signet.challenge requires network = \"signet\"";
      }
      {
        assertion = cfg.signet.blockTime == null || cfg.network == "signet";
        message = "services.rbitcoin.signet.blockTime requires network = \"signet\"";
      }
      {
        assertion = cfg.signet.blockTime == null || cfg.signet.challenge != null;
        message = "services.rbitcoin.signet.blockTime requires signet.challenge";
      }
      {
        assertion = cfg.trustPeer == null || cfg.p2p.seedNodes == [ ];
        message = "services.rbitcoin.trustPeer cannot be combined with p2p.seedNodes";
      }
      {
        assertion =
          cfg.trustPeer == null || cfg.p2p.connect == [ ] || cfg.p2p.connect == [ cfg.trustPeer ];
        message = "services.rbitcoin.trustPeer connect list must be empty or that same address";
      }
      {
        assertion = cfg.netPermissionBind == [ ] || cfg.p2p.listen;
        message = "services.rbitcoin.netPermissionBind requires p2p.listen";
      }
      {
        assertion = cfg.trustPeer == null || cfg.netPermissionBind == [ ];
        message = "services.rbitcoin.netPermissionBind cannot be combined with trustPeer";
      }
      {
        assertion = cfg.esplora.socketPath == null || cfg.esplora.enable;
        message = "services.rbitcoin.esplora.socketPath requires esplora.enable";
      }
      {
        assertion = !cfg.esplora.hiddenService || cfg.esplora.enable;
        message = "services.rbitcoin.esplora.hiddenService requires esplora.enable";
      }
      {
        assertion = !cfg.electrum.hiddenService || cfg.electrum.enable;
        message = "services.rbitcoin.electrum.hiddenService requires electrum.enable";
      }
      {
        assertion = cfg.rpc.tokenFile == null || rpcListening;
        message = "services.rbitcoin.rpc.tokenFile requires an RPC listener";
      }
      {
        assertion =
          !impliedTorControl
          || cfg.tor.controlCookie == null
          || (
            lib.hasPrefix "/" cfg.tor.controlCookie
            && !lib.hasInfix ".." cfg.tor.controlCookie
            && (
              dirOf cfg.tor.controlCookie == "/run/tor"
              || dirOf cfg.tor.controlCookie == "/var/lib/tor"
            )
          );
        message = "services.rbitcoin.tor.controlCookie must be a file in /run/tor or /var/lib/tor when the module configures tor";
      }
      {
        assertion = !unsafeServiceDir cfg.dataDir;
        message = "services.rbitcoin.dataDir must not be a system directory";
      }
      {
        assertion = cfg.coldDataDir == null || !unsafeServiceDir cfg.coldDataDir;
        message = "services.rbitcoin.coldDataDir must not be a system directory";
      }
      {
        assertion = cfg.apiLog == null || !unsafeServiceDir (dirOf cfg.apiLog);
        message = "services.rbitcoin.apiLog must not live in a system directory";
      }
      {
        assertion = cfg.rpc.tokenFile == null || !unsafeServiceDir (dirOf cfg.rpc.tokenFile);
        message = "services.rbitcoin.rpc.tokenFile must not live in a system directory";
      }
      {
        assertion = cfg.rpc.socketPath == null || !unsafeServiceDir (dirOf cfg.rpc.socketPath);
        message = "services.rbitcoin.rpc.socketPath must not live in a system directory";
      }
      {
        assertion = cfg.esplora.socketPath == null || !unsafeServiceDir (dirOf cfg.esplora.socketPath);
        message = "services.rbitcoin.esplora.socketPath must not live in a system directory";
      }
      {
        assertion = cfg.rpc.workQueue == null || rpcListening;
        message = "services.rbitcoin.rpc.workQueue requires an RPC listener";
      }
    ];

    users.groups = {
      ${cfg.group} = { };
    } // lib.optionalAttrs (needTorControl || cfg.tor.controlCookie != null) {
      tor.gid = config.ids.gids.tor;
    };
    services.tor = lib.mkIf impliedTorControl {
      enable = lib.mkDefault true;
      settings = {
        ControlPort = lib.mkDefault [
          {
            addr = "127.0.0.1";
            port = 9051;
          }
        ];
        CookieAuthentication = lib.mkDefault true;
        CookieAuthFile = lib.mkDefault torCookiePath;
        CookieAuthFileGroupReadable = lib.mkDefault true;
      };
    };
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
    }
    // lib.optionalAttrs (
      rpcListening
      && cfg.rpc.tokenFile != null
      && dirOf cfg.rpc.tokenFile != cfg.dataDir
      && (cfg.coldDataDir == null || dirOf cfg.rpc.tokenFile != cfg.coldDataDir)
      && (cfg.rpc.socketPath == null || dirOf cfg.rpc.tokenFile != dirOf cfg.rpc.socketPath)
    ) {
      "${dirOf cfg.rpc.tokenFile}".d = {
        mode = "0750";
        user = cfg.user;
        group = cfg.group;
      };
    }
    // lib.optionalAttrs (
      cfg.esplora.enable
      && cfg.esplora.socketPath != null
      && dirOf cfg.esplora.socketPath != cfg.dataDir
      && (cfg.coldDataDir == null || dirOf cfg.esplora.socketPath != cfg.coldDataDir)
      && (cfg.rpc.socketPath == null || dirOf cfg.esplora.socketPath != dirOf cfg.rpc.socketPath)
    ) {
      "${dirOf cfg.esplora.socketPath}".d = {
        mode = "0750";
        user = cfg.user;
        group = cfg.group;
      };
    }
    // lib.optionalAttrs (
      cfg.apiLog != null
      && dirOf cfg.apiLog != cfg.dataDir
      && (cfg.coldDataDir == null || dirOf cfg.apiLog != cfg.coldDataDir)
      && (cfg.rpc.socketPath == null || dirOf cfg.apiLog != dirOf cfg.rpc.socketPath)
      && (cfg.rpc.tokenFile == null || dirOf cfg.apiLog != dirOf cfg.rpc.tokenFile)
      && (cfg.esplora.socketPath == null || dirOf cfg.apiLog != dirOf cfg.esplora.socketPath)
    ) {
      "${dirOf cfg.apiLog}".d = {
        mode = "0750";
        user = cfg.user;
        group = cfg.group;
      };
    };

    systemd.services.rbitcoin = {
      description = "rbitcoin full node";
      documentation = [ "https://github.com/rbitcoin-org/rbitcoin/blob/master/OPERATOR.md" ];
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
        # systemd expands % in ExecStart before it splits words, quotes included.
        # %% is one percent, so the node still sees %s in alert-notify.
        ExecStart = concatStringsSep " " (
          map (arg: escapeShellArg (lib.replaceStrings [ "%" ] [ "%%" ] arg)) command
        );
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
        ReadWritePaths = lib.unique (
          [
            cfg.dataDir
          ]
          ++ optional (cfg.coldDataDir != null) cfg.coldDataDir
          ++ optional (cfg.rpc.socketPath != null) (dirOf cfg.rpc.socketPath)
          ++ optional (rpcListening && cfg.rpc.tokenFile != null) (dirOf cfg.rpc.tokenFile)
          ++ optional (cfg.esplora.enable && cfg.esplora.socketPath != null) (
            dirOf cfg.esplora.socketPath
          )
          ++ optional (cfg.apiLog != null) (dirOf cfg.apiLog)
        );
      }
      // lib.optionalAttrs (needTorControl || cfg.tor.controlCookie != null) {
        SupplementaryGroups = [ "tor" ];
      };
    };

    networking.firewall.allowedTCPPorts = lib.unique (
      optional (cfg.p2p.openFirewall && cfg.p2p.listen) cfg.p2p.port
      ++ lib.optionals (cfg.p2p.openFirewall && cfg.p2p.listen) whitebindPorts
      ++ optional (cfg.electrum.enable && cfg.electrum.openFirewall) cfg.electrum.port
      ++ optional (
        cfg.esplora.enable && cfg.esplora.openFirewall && cfg.esplora.socketPath == null
      ) cfg.esplora.port
      ++ optional (cfg.health.enable && cfg.health.openFirewall) cfg.health.port
      ++ optional (cfg.sv2.tp.enable && cfg.sv2.tp.openFirewall) cfg.sv2.tp.port
    );

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
