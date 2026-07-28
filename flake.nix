{
  description = "podping-gossipwatcher — iroh p2p gossip watcher for podping";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    crane.url = "github:ipetkov/crane";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      crane,
      flake-utils,
      rust-overlay,
    }:
    flake-utils.lib.eachSystem [ "x86_64-linux" ] (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };

        rustToolchain = pkgs.rust-bin.stable.latest.default;

        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

        # Custom filter: keep markdown files (for include_str!) AND Cargo files
        markdownFilter = path: _type: builtins.match ".*md$" path != null;
        cargoOrMarkdown = path: type: (markdownFilter path type) || (craneLib.filterCargoSources path type);

        workspaceSrc = pkgs.lib.cleanSourceWith {
          src = ./.;
          filter = cargoOrMarkdown;
        };

        commonArgs = {
          src = workspaceSrc;
          strictDeps = true;

          cargoToml = ./Cargo.toml;
          cargoLock = ./Cargo.lock;

          postUnpack = ''
            export sourceRoot=$sourceRoot/podping-gossipwatcher
          '';

          cargoExtraArgs = "--offline";

          nativeBuildInputs = with pkgs; [
            pkg-config
          ];

          buildInputs = with pkgs; [
            openssl
          ];
        };

        cargoArtifacts = craneLib.buildDepsOnly commonArgs;

        podping-gossipwatcher = craneLib.buildPackage (
          commonArgs
          // {
            cargoArtifacts = cargoArtifacts;
          }
        );

      in
      {
        packages = {
          default = podping-gossipwatcher;
          podping-gossipwatcher = podping-gossipwatcher;
        };

        apps = {
          default = flake-utils.lib.mkApp {
            drv = podping-gossipwatcher;
            name = "podping-gossipwatcher";
          };
        };

        devShells.default = craneLib.devShell {
          inputsFrom = [ podping-gossipwatcher ];

          packages = with pkgs; [
            cargo-watch
            rust-analyzer
          ];
        };
      }
    );
}
