{
  module,
  pkgs,
}:
let
  fakePackage = pkgs.writeShellScriptBin "rbitcoin-node" ''
    set -eu
    printf '%s\n' "$@" > /var/lib/rbitcoin-test/args
    trap 'touch /var/lib/rbitcoin-test/stopped; exit 0' TERM
    # stands in for binding --rpc-socket under ProtectSystem=strict
    touch /run/rbitcoin/rpc.sock
    touch /var/lib/rbitcoin-test/started
    while true; do
      sleep 1
    done
  '';
in
pkgs.testers.runNixOSTest {
  name = "rbitcoin-nixos-module";

  nodes.machine =
    { ... }:
    {
      imports = [ module ];

      services.rbitcoin = {
        enable = true;
        package = fakePackage;
        dataDir = "/var/lib/rbitcoin-test";
        network = "regtest";
        p2p = {
          address = "127.0.0.1";
          port = 18445;
          listenOnion = true;
        };
        rpc = {
          enable = true;
          socketPath = "/run/rbitcoin/rpc.sock";
        };
        tor.control = "127.0.0.1:9051";
        i2p.sam = "127.0.0.1:7656";
        cjdns.reachable = true;
        health.enable = true;
        metrics = true;
        extraArgs = [
          "--max-outbound"
          "4"
        ];
      };

      systemd.services.tor = {
        description = "fake tor unit for After= ordering";
        wantedBy = [ "multi-user.target" ];
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart = "${pkgs.coreutils}/bin/true";
        };
      };

      systemd.services.i2pd = {
        description = "fake i2pd unit for After= ordering";
        wantedBy = [ "multi-user.target" ];
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart = "${pkgs.coreutils}/bin/true";
        };
      };
    };

  testScript = ''
    machine.wait_for_unit("rbitcoin.service")
    machine.wait_until_succeeds("test -e /var/lib/rbitcoin-test/started")
    machine.succeed("grep -Fx -- '--datadir' /var/lib/rbitcoin-test/args")
    machine.succeed("grep -Fx -- '/var/lib/rbitcoin-test' /var/lib/rbitcoin-test/args")
    machine.succeed("grep -Fx -- '--network' /var/lib/rbitcoin-test/args")
    machine.succeed("grep -Fx -- 'regtest' /var/lib/rbitcoin-test/args")
    machine.succeed("grep -Fx -- '127.0.0.1:18445' /var/lib/rbitcoin-test/args")
    machine.succeed("grep -Fx -- '127.0.0.1:18443' /var/lib/rbitcoin-test/args")
    machine.succeed("grep -Fx -- '--max-outbound' /var/lib/rbitcoin-test/args")
    machine.succeed("grep -Fx -- '4' /var/lib/rbitcoin-test/args")
    machine.succeed("grep -Fx -- '--tor-control' /var/lib/rbitcoin-test/args")
    machine.succeed("grep -Fx -- '127.0.0.1:9051' /var/lib/rbitcoin-test/args")
    machine.succeed("grep -Fx -- '--listen-onion' /var/lib/rbitcoin-test/args")
    machine.succeed("grep -Fx -- '--i2p-sam' /var/lib/rbitcoin-test/args")
    machine.succeed("grep -Fx -- '--cjdns-reachable' /var/lib/rbitcoin-test/args")
    machine.succeed("grep -Fx -- '127.0.0.1:7656' /var/lib/rbitcoin-test/args")
    machine.succeed("grep -Fx -- '--health-listen' /var/lib/rbitcoin-test/args")
    machine.succeed("grep -Fx -- '127.0.0.1:9332' /var/lib/rbitcoin-test/args")
    machine.succeed("grep -Fx -- '--metrics' /var/lib/rbitcoin-test/args")
    machine.succeed("grep -Fx -- '--rpc-socket' /var/lib/rbitcoin-test/args")
    machine.succeed("grep -Fx -- '/run/rbitcoin/rpc.sock' /var/lib/rbitcoin-test/args")
    machine.succeed("test -e /run/rbitcoin/rpc.sock")
    machine.succeed("test \"$(stat -c '%a %U %G' /run/rbitcoin)\" = '750 rbitcoin rbitcoin'")
    machine.succeed("systemctl show -p After rbitcoin.service | grep -F tor.service")
    machine.succeed("systemctl show -p After rbitcoin.service | grep -F i2pd.service")
    machine.succeed("systemctl stop rbitcoin.service")
    machine.succeed("test -e /var/lib/rbitcoin-test/stopped")
  '';
}
