# Portable / release package for rbitcoin-node + rbitcoin-cli (+ store utils).
#
# Built with **crane** so dependency crates are a separate fixed derivation
# (`cargoArtifacts` / `buildDepsOnly`). Workspace crate changes rebuild only the
# app layer when `Cargo.lock` is unchanged — same RUSTFLAGS / pins as before.
#
# Call as:
#   callPackage ./nix/rbitcoin.nix { craneLib = crane.mkLib pkgs; }
# with `pkgs` = pkgsStatic for musl, or plain pkgs for glibc.
{
  lib,
  craneLib,
  pkg-config,
  stdenv,
  # pkgsStatic is a cross-like stdenv: build scripts need the *build* platform cc.
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
  commonRUSTFLAGS = lib.concatStringsSep " " (
    [
      "--remap-path-prefix"
      "/build/=/source/"
      "-C"
      "debuginfo=0"
      "-C"
      "strip=symbols"
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

  # pkgsStatic: buildPlatform is gnu, hostPlatform is musl — must target musl
  # explicitly and point cargo at the *host* linker (not depsBuildBuild's gnu cc).
  rustTarget =
    stdenv.hostPlatform.rust.rustcTarget or stdenv.hostPlatform.rust.cargoShortTarget
      or stdenv.hostPlatform.config;
  rustTargetEnv = lib.toUpper (builtins.replaceStrings [ "-" ] [ "_" ] rustTarget);
  isCross = stdenv.buildPlatform != stdenv.hostPlatform;

  commonArgs = {
    inherit src;
    pname = "rbitcoin";
    version = "0.1.0";
    strictDeps = true;
    nativeBuildInputs = [
      pkg-config
      stdenv.cc
    ];
    # Build-platform cc only for build.rs / proc-macros when cross (pkgsStatic).
    depsBuildBuild = lib.optionals isCross [ buildPackages.stdenv.cc ];
    inherit cargoExtraArgs;
    RUSTFLAGS = commonRUSTFLAGS;
    # Force cargo to emit host (musl) objects into target/<triple>/…; without
    # this, build can land in target/release linked with the build-platform
    # gnu linker (dynamic glibc).
    CARGO_BUILD_TARGET = rustTarget;
    "CARGO_TARGET_${rustTargetEnv}_LINKER" = "${stdenv.cc.targetPrefix}cc";
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
        platforms = platforms.linux ++ platforms.darwin;
      };
    }
  );
in
rbitcoin
