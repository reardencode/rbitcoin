# Portable / release package for rbitcoin-node + rbitcoin-cli (+ store utils).
#
# Built with **crane** so dependency crates are a separate fixed derivation
# (`cargoArtifacts` / `buildDepsOnly`). Workspace crate changes rebuild only the
# app layer when `Cargo.lock` is unchanged — same RUSTFLAGS / pins as before.
#
# Call as:
#   # dynamic glibc:
#   pkgs.callPackage ./nix/rbitcoin.nix { craneLib = crane.mkLib pkgs; }
#   # fully static musl:
#   pkgs.pkgsStatic.callPackage ./nix/rbitcoin.nix {
#     craneLib = crane.mkLib pkgs.pkgsStatic;
#   }
#
# Under pkgsStatic, build.rs / proc-macros must link with the *build* platform
# (dynamic gnu) compiler. Host product objects use the musl linker + `+crt-static`
# only via `CARGO_TARGET_<host>_RUSTFLAGS` — never global `RUSTFLAGS` alone
# (rustc 1.95 / nixos-26.05: global static flags break build scripts).
{
  lib,
  craneLib,
  pkg-config,
  stdenv,
  # pkgsStatic is cross-like: build scripts need the *build* platform cc.
  buildPackages,
}:

let
  # Cargo-aware source (crane) + drop local noise that would bust the NAR hash.
  src = lib.cleanSourceWith {
    src = craneLib.cleanCargoSource ../.;
    filter =
      path: type:
      let
        base = baseNameOf path;
      in
      !(lib.hasPrefix "datadir" base)
      && !(lib.hasSuffix ".log" base)
      && base != "coverage"
      && base != ".coverage"
      && base != "result"
      && base != "result-1"
      && base != "result-2"
      && base != ".repro-out";
  };

  # Deterministic flags. Do **not** embed `${src}` in RUSTFLAGS — that would
  # change the deps layer hash on every .rs edit and defeat crane caching.
  # Remap the Nix build top (always `/build` in the sandbox) instead.
  commonRUSTFLAGS = lib.concatStringsSep " " [
    "--remap-path-prefix"
    "/build/=/source/"
    "-C"
    "debuginfo=0"
    "-C"
    "strip=symbols"
  ];
  hostRUSTFLAGS = lib.concatStringsSep " " (
    [
      commonRUSTFLAGS
    ]
    ++ lib.optionals stdenv.hostPlatform.isMusl [
      "-C"
      "target-feature=+crt-static"
    ]
  );

  # Product packages only (not the full workspace / tests).
  cargoExtraArgs = lib.concatStringsSep " " [
    "-p"
    "rbitcoin-node"
    "-p"
    "rbitcoin-cli"
    "-p"
    "rbitcoin-store"
  ];

  # Host (product) triple — musl when callPackage under pkgsStatic.
  rustTarget =
    stdenv.hostPlatform.rust.rustcTarget or stdenv.hostPlatform.rust.cargoShortTarget
      or stdenv.hostPlatform.config;
  rustTargetEnv = lib.toUpper (builtins.replaceStrings [ "-" ] [ "_" ] rustTarget);

  # Build platform triple (gnu on Linux) — build.rs / proc-macros.
  buildRustTarget =
    stdenv.buildPlatform.rust.rustcTarget or stdenv.buildPlatform.rust.cargoShortTarget
      or stdenv.buildPlatform.config;
  buildRustTargetEnv = lib.toUpper (builtins.replaceStrings [ "-" ] [ "_" ] buildRustTarget);

  isCross = stdenv.buildPlatform != stdenv.hostPlatform;

  buildCc = buildPackages.stdenv.cc;
  hostCc = stdenv.cc;

  commonArgs = {
    inherit src;
    pname = "rbitcoin";
    version = "0.5.2";
    strictDeps = true;
    nativeBuildInputs = [
      pkg-config
      # Prefer build-platform cc on PATH so cargo's default `cc` for build
      # scripts is dynamic gnu when cross/static.
      buildCc
    ]
    ++ lib.optionals isCross [ hostCc ];
    # Build-platform cc for build.rs / proc-macros when cross (pkgsStatic).
    depsBuildBuild = lib.optionals isCross [ buildCc ];
    inherit cargoExtraArgs;
    # Build-script flags: never `+crt-static`.
    RUSTFLAGS = commonRUSTFLAGS;
    # Force cargo to emit host (musl) objects into target/<triple>/…; without
    # this, build can land in target/release linked with the build-platform
    # gnu linker (dynamic glibc).
    CARGO_BUILD_TARGET = rustTarget;
    "CARGO_TARGET_${rustTargetEnv}_LINKER" = "${hostCc}/bin/${hostCc.targetPrefix}cc";
    "CARGO_TARGET_${rustTargetEnv}_RUSTFLAGS" = hostRUSTFLAGS;
    # Explicit build-platform linker so proc-macro/build-script links stay dynamic.
    "CARGO_TARGET_${buildRustTargetEnv}_LINKER" = "${buildCc}/bin/${buildCc.targetPrefix}cc";
    "CARGO_TARGET_${buildRustTargetEnv}_RUSTFLAGS" = commonRUSTFLAGS;
    # Also set CC_*/HOST_CC for crates that shell out to the C compiler.
    "CC_${buildRustTargetEnv}" = "${buildCc}/bin/${buildCc.targetPrefix}cc";
    "CC_${rustTargetEnv}" = "${hostCc}/bin/${hostCc.targetPrefix}cc";
    HOST_CC = "${buildCc}/bin/${buildCc.targetPrefix}cc";
    # pkgsStatic's stdenv injects `-static` into NIX_* link flags for *every*
    # cc invocation — including build-platform gcc used for build.rs. That
    # yields "attempted static link of dynamic object … glibc" under rustc
    # 1.95. Strip forced static from the env; host product staticity comes
    # from `+crt-static` on CARGO_TARGET_<musl>_RUSTFLAGS instead.
    preConfigure = lib.optionalString stdenv.hostPlatform.isStatic ''
      strip_static() {
        printf '%s' "$1" | tr ' ' '\n' | grep -v '^-static$' | tr '\n' ' '
      }
      export NIX_CFLAGS_LINK="$(strip_static "''${NIX_CFLAGS_LINK-}")"
      export NIX_LDFLAGS="$(strip_static "''${NIX_LDFLAGS-}")"
      export NIX_LDFLAGS_FOR_TARGET="$(strip_static "''${NIX_LDFLAGS_FOR_TARGET-}")"
      export NIX_CFLAGS_LINK_FOR_TARGET="$(strip_static "''${NIX_CFLAGS_LINK_FOR_TARGET-}")"
    '';
    # Release product only — full workspace tests stay on the CI/dev path.
    doCheck = false;
  };

  # Layer 1: registry/git deps (+ build scripts). Invalidates on Cargo.lock /
  # Cargo.toml graph changes, not on .rs edits under crates/.
  cargoArtifacts = craneLib.buildDepsOnly (
    commonArgs
    // {
      pname = "rbitcoin-deps";
    }
  );

  # Layer 2: workspace crates linked against cargoArtifacts.
  rbitcoin = craneLib.buildPackage (
    commonArgs
    // {
      inherit cargoArtifacts;
      meta = with lib; {
        description = "Experimental Bitcoin full node (rbitcoin-node) and CLI";
        license = with licenses; [
          mit
          asl20
        ];
        mainProgram = "rbitcoin-node";
        platforms = platforms.linux;
      };
    }
  );
in
rbitcoin
