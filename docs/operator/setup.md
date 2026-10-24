# Setup and installation

## Status

BIP324 v2-only P2P, cluster mempool (Libre admission + **consensus script checks on accept**),
Electrum confirmed + unconfirmed (TLS via reverse proxy). **0.7 mainnet** is
early production / high-scrutiny — see
[`docs/experimental-mainnet.md`](../../docs/experimental-mainnet.md). Watch reorgs and disk
headroom before any serious use. Default mainnet milestone is block **840000**
(`0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5`): script/sig
checks skip only when the header path contains that hash and the block is
the path hash at its height. Explicit `--milestone HEIGHT` is height-only. `--milestone 0` is
full scripts. Signet’s default is **0** (every script, slower on purpose).

Architecture and confirm pipeline: [`docs/architecture.md`](../../docs/architecture.md),
[`docs/concurrency.md`](../../docs/concurrency.md). Download defaults to **1024**
concurrent getdata (not a tip-distance cap), max **64** blocks in transit per
peer (a 16 MiB payload cap stops one peer holding 64 large bodies).

## Build

Portable **static musl** binary (runs on ordinary Linux without Nix):

```bash
nix build .#rbitcoin-musl
mkdir -p target/release
install -m 755 result/bin/rbitcoin-node result/bin/rbitcoin-cli target/release/
./target/release/rbitcoin-node --help
```

Do not use `cargo build --release` under `nix-shell` for the operator binary —
that produces a Nix-glibc dynamic link that fails outside the store. Release on
Linux is always musl static. Compiling the tree as a contributor (rustup, no
Nix, macOS/Windows): [`CONTRIBUTING.md`](../../CONTRIBUTING.md). See
[`docs/reproducible-builds.md`](../../docs/reproducible-builds.md).

### NixOS service

The flake exports `nixosModules.default` and `nixosModules.rbitcoin`. Import
either module into a NixOS configuration:

```nix
{
  inputs.rbitcoin.url = "github:reardencode/rbitcoin";

  outputs =
    {
      nixpkgs,
      rbitcoin,
      ...
    }:
    {
      nixosConfigurations.example = nixpkgs.lib.nixosSystem {
        system = "x86_64-linux";
        modules = [
          rbitcoin.nixosModules.default
          {
            services.rbitcoin = {
              enable = true;
              dataDir = "/var/lib/rbitcoin-mainnet";
            };
          }
        ];
      };
    };
}
```

The service defaults to mainnet, uses the flake's static musl operator package,
and leaves the firewall closed. It creates the configured data directory for
the `rbitcoin` service account without changing ownership below that directory.
Importing the module does not replace or overlay the NixOS system's `nixpkgs`.
Use the store-native glibc build instead when wanted:

```nix
({ pkgs, ... }: {
  services.rbitcoin.package =
    rbitcoin.packages.${pkgs.stdenv.hostPlatform.system}.rbitcoin-glibc;
})
```

This selects the glibc build from rbitcoin's pinned `nixpkgs`; it does not
rebuild the package against the NixOS system's `nixpkgs`.

RPC, Electrum, and Esplora listeners are disabled by default. Their module
options bind to loopback unless changed. Enabling Electrum or Esplora also
enables the required scripthash index. `p2p.openFirewall`,
`electrum.openFirewall`, and `esplora.openFirewall` are separate opt-ins.
JSON-RPC has no firewall option; expose it only through an explicitly managed
firewall or tunnel.

`health.enable` binds `--health-listen` (default `127.0.0.1:9332`) for
`/healthz`, `/readyz`, and `/progress`. `metrics` adds `--metrics` on that
listener and, when `services.prometheus.enable` is set, a scrape job for
the health address. Leave `health.openFirewall` off: the listener is
unauthenticated.

The default module is a validating listener. `services.rbitcoin.trustPeer`
is the one-peer option (`docs/operator/operations.md`).

The daemon does not terminate TLS. Keep its application listeners on loopback
and compose them with a proxy. This example serves Esplora and RPC over HTTPS,
and Electrum as TLS-wrapped TCP on port 50002, using one ACME certificate:

```nix
{
  services.rbitcoin = {
    rpc.enable = true;
    electrum.enable = true;
    esplora.enable = true;
  };

  security.acme = {
    acceptTerms = true;
    defaults.email = "operator@example.com";
  };

  services.nginx = {
    enable = true;
    recommendedProxySettings = true;
    virtualHosts."node.example.com" = {
      enableACME = true;
      forceSSL = true;
      locations."/" = {
        proxyPass = "http://127.0.0.1:3000";
      };
      locations."/rpc/".proxyPass = "http://127.0.0.1:8332/";
    };
    streamConfig = ''
      server {
        listen 50002 ssl;
        proxy_pass 127.0.0.1:50001;
        ssl_certificate /var/lib/acme/node.example.com/fullchain.pem;
        ssl_certificate_key /var/lib/acme/node.example.com/key.pem;
      }
    '';
  };

  networking.firewall.allowedTCPPorts = [ 80 443 50002 ];
}
```

Replace the hostname and email, then apply authentication and network policy to
RPC for your deployment. nginx `virtualHosts` proxy HTTP; `streamConfig`
proxies the Electrum TCP protocol.

Use `coldDataDir` to place the append-only store (`seqsigwit`, `txstat`, `input`, and the block-filter and tweak indexes) on another volume. The
service creates the directory but does not mount or size the volume. Set `datadirHdd` when the main datadir is spinning rust. Use
`environment` for documented advanced `RBITCOIN_*` settings and `extraArgs`
for daemon flags not represented by module options.

**GitHub Release** (`v*.*.*` tags) is the operator snapshot: Linux musl
(x86_64 and aarch64) + Windows CRT-static PE + Darwin aarch64 binaries +
SHA256SUMS, and the [container image](#container-image). Cut, merge,
tag, and `vX.Y.x` / `.99` follow-up: [`docs/releases.md`](../../docs/releases.md).

```bash
./scripts/release-post.sh --dry-run   # after the ship version is on the branch
./scripts/release.sh --dry-run
```

Retry from Actions → **release** → Run workflow (artifacts only, no tag).
PR `ci` **windows** / **macos** jobs run `./scripts/ci-os-smoke.sh` (native
store IO, mmap sealed fuse, a few-block query confirm, `--smoke`);
they do not upload binaries. Local Linux `target/release/` install is still
`nix build .#rbitcoin-musl` on a clean master tree. Windows IoRing is not
supported. Darwin/Windows are not Nix packages — see
[`docs/reproducible-builds.md`](../reproducible-builds.md).

**Darwin Gatekeeper:** the Darwin binaries are ad-hoc signed (`codesign -s -`), not
notarized. If Finder or a browser sets quarantine and the binary is killed
on launch:

```bash
xattr -d com.apple.quarantine rbitcoin-node rbitcoin-cli
```

**Windows store files** are opened `FILE_FLAG_OVERLAPPED` (IOCP). Header
create/open/grow use positional `ReadFile`/`WriteFile` +
`SetFileInformationByHandle`, not std `Read`/`Write`/`Seek`. Mixed
Default `--datadir` is cwd-relative `datadir` via `Path::new(".").join("datadir")`
(`./datadir` on Unix, `.\datadir` on Windows).

### Container image

Each `v*.*.*` tag publishes `ghcr.io/reardencode/rbitcoin` for
`linux/amd64` and `linux/arm64`, and Docker Hub `reardencode/rbitcoin` once
the maintainers enable it ([`releases.md`](../releases.md)). The image is
the Release musl binaries on `FROM scratch`: no shell, no libc, no base
image. Tags are `X.Y.Z`, `X.Y` (newest patch on that line), and `latest`
(newest release). A patch on an older line does not move `latest`.

```bash
docker volume create rbitcoin
docker run -d --name rbitcoin --stop-timeout 300 \
  -v rbitcoin:/data -p 8333:8333 \
  ghcr.io/reardencode/rbitcoin:X.Y.Z \
  --listen 0.0.0.0:8333 --rpc-listen 127.0.0.1:8332
docker logs -f rbitcoin
docker exec rbitcoin rbitcoin-cli getblockchaininfo
```

- **Datadir.** The image runs as uid 10001 in `/data`, so the default
  `./datadir` is `/data/datadir`, and `docker exec … rbitcoin-cli` finds the
  RPC token with no `--datadir`. A new named volume takes that ownership. A
  bind mount must be writable by 10001 (`chown -R 10001:10001 /srv/rbitcoin`).
- **Arguments** after the image name go to `rbitcoin-node` unchanged.
  Network, indexes, and listeners are the same flags as anywhere else.
- **Stop.** The node flushes the store on SIGTERM. Docker's default stop
  timeout is 10 s. Use `--stop-timeout 300` (compose:
  `stop_grace_period: 5m`), the same budget as the NixOS unit.
- **Listeners.** The loopback address inside a container is the
  container's own. P2P binds `127.0.0.1` when `--listen` is omitted, so
  inbound peers need `--listen 0.0.0.0:<port>` and the same port published;
  without it `-p 8333:8333` reaches nothing and the node is outbound-only.
  RPC, Electrum, Esplora, and health are opt-in. To reach one from the host,
  bind it to `0.0.0.0` inside and publish it on host loopback only:
  `--rpc-listen 0.0.0.0:8332 -p 127.0.0.1:8332:8332`. The health listener
  is unauthenticated; treat it the same way.
- **Store IO.** Docker's default seccomp profile blocks `io_uring`. The
  store logs `completion session unavailable` and uses the `pread` fallback
  ([`io-modality.md`](../io-modality.md)). A seccomp profile that allows the
  `io_uring_*` syscalls restores it. Do not run `seccomp=unconfined`.
- **Verify** the image binaries against the Release checksums:
  [`reproducible-builds.md`](../reproducible-builds.md).

### Low-priority service on a shared Linux host

Initial block download (IBD) sustains CPU and storage work for a long time. On
a workstation or multipurpose server, running the service at low priority can
keep interactive work and latency-sensitive services responsive while letting
rbitcoin use otherwise-idle resources. This is an opt-in host policy, not a
performance setting: sync can slow substantially under contention, and an idle
I/O class can starve while higher-priority storage work continues.

Idle `IOSchedulingClass` (and some filesystems, including bcachefs) can
starve `io_uring` completions. Expect `store: io_uring drain slow` then at most
one recover per ~1000 heights. If the node aborts (`store: completion session unusable`),
restart as-is or with `RBITCOIN_IO=pread`. There is no mid-IBD libc fallback.

For a regular systemd installation, create a service drop-in with
`systemctl edit rbitcoin.service`:

```ini
[Service]
Nice=19
CPUWeight=10
IOWeight=10
IOSchedulingClass=idle
```

Apply it at a planned service restart. The equivalent NixOS override composes
with the shipped module:

```nix
{
  systemd.services.rbitcoin.serviceConfig = {
    Nice = 19;
    CPUWeight = 10;
    IOWeight = 10;
    IOSchedulingClass = "idle";
  };
}
```

These controls cover different layers:

- `Nice=19` lowers CPU scheduling priority for every rbitcoin thread.
- `CPUWeight=10` requests a smaller relative CPU share than sibling cgroups
  with the default weight of 100 through the cgroup v2 CPU controller and the
  standard fair scheduler.
- `IOSchedulingClass=idle` requests the kernel's idle per-process I/O class.
- `IOWeight=10` gives the service a smaller relative share through the cgroup
  v2 I/O controller.

Weights divide resources only when eligible cgroups compete; they are not
bandwidth caps. On an otherwise idle host, these settings still allow rbitcoin
to use the available CPU and storage. They do not limit process memory or
network traffic. Add memory limits only from a separate, host-specific capacity
plan; an undersized limit can terminate the node or make IBD impractically slow.

I/O priority is also storage-stack dependent. Linux currently implements
per-process I/O priorities in the `bfq` and `mq-deadline` schedulers; `none`
does not make `IOSchedulingClass=idle` effective. `mq-deadline` honors that
process class but does not implement cgroup weights. `IOWeight` needs BFQ group
scheduling or a configured kernel I/O cost controller; accepting the systemd
setting alone does not prove that the storage stack enforces it. rbitcoin uses
multiple OS threads and bulk `io_uring` or positional I/O, but systemd places
all service tasks in the same cgroup; the kernel and active device scheduler
still decide how strongly these requests are separated from other workloads.

#### Select the block-device I/O scheduler

Identify every physical device that backs `dataDir` and `coldDataDir`; layered
storage such as LVM, RAID, dm-crypt, or multi-device filesystems may involve
more than the mount's immediate block device:

```bash
findmnt -no SOURCE --target /var/lib/rbitcoin-mainnet
lsblk -o NAME,TYPE,PKNAME,MOUNTPOINTS
cat /sys/block/nvme0n1/queue/scheduler
```

The active scheduler appears in brackets, for example:

```text
none [mq-deadline] kyber
```

When the goal is to honor the idle I/O class, `mq-deadline` is a conservative
choice when the device offers it. BFQ also implements process priorities and
cgroup weights, and may improve latency isolation, but its fairness machinery
can reduce throughput or add overhead on fast devices. Do not prescribe BFQ
solely because a device is rotational or NVMe; test the tradeoff on the actual
host. If maximum throughput matters more than isolation, leaving `none` active
may be correct even though process I/O priority will not apply.

Test a supported scheduler until reboot:

```bash
echo mq-deadline | sudo tee /sys/block/nvme0n1/queue/scheduler
```

The scheduler is device-wide, so this changes policy for every workload using
that device, not only rbitcoin. Persist it only after verifying the physical
device and available scheduler. A udev rule should match a stable device
identity rather than a probe-order name:

```udev
ACTION=="add", SUBSYSTEM=="block", ENV{DEVTYPE}=="disk", \
  ENV{ID_WWN}=="<device-WWN>", ATTR{queue/scheduler}="mq-deadline"
```

Check the property first with
`udevadm info --query=property --name=/dev/nvme0n1`; use another stable property
such as `ID_SERIAL` if the device exports no `ID_WWN`. NixOS can persist the
same exact-device rule:

```nix
{
  services.udev.extraRules = ''
    ACTION=="add", SUBSYSTEM=="block", ENV{DEVTYPE}=="disk", ENV{ID_WWN}=="<device-WWN>", ATTR{queue/scheduler}="mq-deadline"
  '';
}
```

Re-check `/sys/block/<device>/queue/scheduler` after reboot. See the kernel
documentation for [block I/O priorities](https://docs.kernel.org/block/ioprio.html),
[BFQ](https://docs.kernel.org/block/bfq-iosched.html), and
[switching schedulers](https://kernel.org/doc/html/latest/block/switching-sched.html),
plus systemd's
[`systemd.exec`](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html)
and
[`systemd.resource-control`](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html)
manuals for the enforcement boundaries. The shipped `nixosModules` unit does
not apply these settings.
