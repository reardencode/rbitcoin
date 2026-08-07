{
  description = "rbitcoin — pinned Nix builds for byte-identical release binaries";

  # Pin advanced via flake.lock (nix flake lock). Do not use import <nixpkgs> {}.
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
  # Layered cargo builds: deps derivation + app derivation (faster rebuilds).
  # Pin a crane that works with nixos-24.11 rustc (1.82). Latest crane wants
  # nixpkgs ≥26.05 and pulls edition2024 crates into crane-utils.
  inputs.crane.url = "github:ipetkov/crane/v0.20.1";

  outputs =
    { self, nixpkgs, crane }:
    let
      # Systems we expose packages for (native builds when host matches).
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;

      mkRbitcoin =
        pkgs:
        pkgs.callPackage ./nix/rbitcoin.nix {
          craneLib = crane.mkLib pkgs;
        };
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
            # Disable impure overlays; pure evaluation for reproducibility.
            config = { };
            overlays = [ ];
          };
          isLinux = nixpkgs.lib.hasSuffix "-linux" system;
          # Native build (Nix-store linked): glibc on Linux, plain darwin stdenv on macOS.
          rbitcoin-native = mkRbitcoin pkgs;
          # Primary / default on Linux: fully static musl — portable operator binary.
          # musl is Linux-only, so darwin defaults to the native build instead.
          rbitcoin-default = if isLinux then mkRbitcoin pkgs.pkgsStatic else rbitcoin-native;
        in
        {
          default = rbitcoin-default;
          rbitcoin = rbitcoin-default;
          rbitcoin-node = rbitcoin-default;
          rbitcoin-cli = rbitcoin-default;
        }
        // nixpkgs.lib.optionalAttrs isLinux {
          rbitcoin-musl = rbitcoin-default;
          # Kept for store-native Nix environments / optional dual-platform repro.
          rbitcoin-glibc = rbitcoin-native;
        }
        // nixpkgs.lib.optionalAttrs (system == "x86_64-linux") {
          # Optional third platform: aarch64-linux cross from x86_64 (heavy toolchain).
          rbitcoin-aarch64 =
            let
              pkgsAarch64 = import nixpkgs {
                system = "x86_64-linux";
                crossSystem = {
                  config = "aarch64-unknown-linux-gnu";
                };
                config = { };
                overlays = [ ];
              };
            in
            mkRbitcoin pkgsAarch64;
        }
      );

      # Dev shell uses the **same pinned** nixpkgs (not floating <nixpkgs>).
      devShells = forAllSystems (
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
            config = { };
            overlays = [ ];
          };
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              rustc
              cargo
              rustfmt
              clippy
              llvmPackages_19.bintools
              llvmPackages_19.llvm
              cargo-llvm-cov
              pkg-config
            ];
            RUST_BACKTRACE = "1";
            # Dev shell still denies warnings; release package uses its own RUSTFLAGS.
            RUSTFLAGS = "-Dwarnings";
            shellHook = ''
              export LLVM_COV="${pkgs.llvmPackages_19.llvm}/bin/llvm-cov"
              export LLVM_PROFDATA="${pkgs.llvmPackages_19.llvm}/bin/llvm-profdata"
              echo "rbitcoin devShell: rustc=$(rustc --version) (pinned nixpkgs via flake)"
            '';
          };
        }
      );

      # `nix flake check` can validate the package builds on the current system.
      checks = forAllSystems (
        system:
        {
          # musl on Linux, native on darwin — matches the default package.
          rbitcoin = self.packages.${system}.default;
        }
      );
    };
}
