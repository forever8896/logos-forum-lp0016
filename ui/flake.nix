{
  description = "Logos Forum — Basecamp UI plugin (Qt6 + Rust FFI). Adapted from logos-co/whisper-wall.";

  inputs = {
    # Track logos-workspace's pinned nixpkgs so Qt versions match Basecamp.
    logos-nix.url = "github:logos-co/logos-nix";
    nixpkgs.follows = "logos-nix/nixpkgs";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
    nix-bundle-lgx = {
      url = "github:logos-co/nix-bundle-lgx";
      inputs.logos-nix.follows = "logos-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, logos-nix, rust-overlay, flake-utils, nix-bundle-lgx }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };

        rustToolchain = pkgs.rust-bin.stable."1.94.0".default;

        rustPlatform = pkgs.makeRustPlatform {
          cargo = rustToolchain;
          rustc = rustToolchain;
        };

        # ── ZK circuit artifacts (transitive dep of nssa via logos-blockchain-pol)
        logosCircuits = pkgs.fetchurl {
          url = "https://github.com/logos-blockchain/logos-blockchain-circuits/releases/download/v0.4.2/logos-blockchain-circuits-v0.4.2-linux-x86_64.tar.gz";
          sha256 = "13c5gkfsa70kca0nwffbsis2difmspyk8aqmlzhq12mhr3x1y4z9";
        };

        circuitsDir = pkgs.runCommand "logos-blockchain-circuits" {} ''
          mkdir -p $out
          tar -xzf ${logosCircuits} -C $out --strip-components=1
        '';

        # ── LEZ source (nssa build.rs reads artifacts/program_methods/*.bin) ──
        lezSrc = pkgs.fetchgit {
          url = "https://github.com/logos-blockchain/logos-execution-zone.git";
          rev = "35d8df0d031315219f94d1546ceb862b0e5b208f";  # v0.2.0-rc1
          hash = "sha256-j0DzDvH88IUIReYi6N4FD6+mTIJOklQjaa9qjw4yHEg=";
        };

        # ── Rust FFI cdylib (libforum_ffi.so) ────────────────────────────────
        ffi = rustPlatform.buildRustPackage {
          pname = "forum-ffi";
          version = "0.1.0";
          src = ./ffi;

          cargoLock = {
            lockFile = ./ffi/Cargo.lock;
            outputHashes = {
              "amm_core-0.1.0"                          = "sha256-j0DzDvH88IUIReYi6N4FD6+mTIJOklQjaa9qjw4yHEg=";
              "jf-crhf-0.1.1"                           = "sha256-TUm91XROmUfqwFqkDmQEKyT9cOo1ZgAbuTDyEfe6ltg=";
              "jf-poseidon2-0.1.0"                      = "sha256-QeCjgZXO7lFzF2Gzm2f8XI08djm5jyKI6D8U0jNTPB8=";
              "logos-blockchain-blend-crypto-0.1.2"     = "sha256-ypgXXvAUR4WbXGaOhoPy9AqTyYjqtIUye/Uyr1RF030=";
              "overwatch-0.1.0"                         = "sha256-L7R1GdhRNNsymYe3RVyYLAmd6x1YY08TBJp4hG4/YwE=";
            };
          };

          LOGOS_BLOCKCHAIN_CIRCUITS = "${circuitsDir}";

          preBuild = ''
            ln -sf "${lezSrc}/artifacts" ../cargo-vendor-dir/artifacts
          '';

          doCheck = false;
        };

        # ── Qt6 plugin (libforum_ui_plugin.so) ───────────────────────────────
        # logos-module-builder injects LogosAPI headers + LOGOS_CPP_SDK_ROOT
        # which activates the live delivery_module wiring in ForumBackend.
        plugin = pkgs.stdenv.mkDerivation {
          pname = "forum-ui-plugin";
          version = "0.1.0";
          src = ./.;

          nativeBuildInputs = [
            pkgs.cmake
            pkgs.ninja
            pkgs.pkg-config
            pkgs.qt6.wrapQtAppsHook
          ];

          buildInputs = with pkgs.qt6; [
            qtbase
            qtdeclarative
          ];

          cmakeFlags = [
            "-DFORUM_FFI_LIB_DIR=${ffi}/lib"
          ];

          installPhase = ''
            runHook preInstall
            cmake --install .
            cp ${./manifest.json} $out/manifest.json
            cp ${./metadata.json} $out/metadata.json
            cp -r ${./qml} $out/qml
            runHook postInstall
          '';
        };

        # ── Install helper: copies into Basecamp dev plugins dir ─────────────
        installScript = pkgs.writeShellScriptBin "install-forum-ui-plugin" ''
          PLUGIN_DIR="$HOME/.local/share/Logos/LogosBasecampDev/plugins/forum_ui"
          mkdir -p "$PLUGIN_DIR"
          cp -f ${plugin}/lib/libforum_ui_plugin.so  "$PLUGIN_DIR/"
          cp -f ${plugin}/lib/libforum_ffi.so        "$PLUGIN_DIR/"
          cp -f ${plugin}/manifest.json              "$PLUGIN_DIR/"
          cp -f ${plugin}/metadata.json              "$PLUGIN_DIR/"
          cp -r ${plugin}/qml                        "$PLUGIN_DIR/"
          echo "Installed to $PLUGIN_DIR"
        '';

        lgx = nix-bundle-lgx.bundlers.${system}.portable plugin;

      in {
        packages = {
          default = plugin;
          ffi     = ffi;
          install = installScript;
          lgx     = lgx;
        };

        devShells.default = pkgs.mkShell {
          nativeBuildInputs = [
            rustToolchain
            pkgs.cmake pkgs.ninja pkgs.pkg-config
            pkgs.qt6.wrapQtAppsHook
          ];
          buildInputs = with pkgs.qt6; [ qtbase qtdeclarative ];
          shellHook = ''
            echo "logos-forum UI dev shell"
            echo "  Build FFI:    cargo build --release  (in ffi/)"
            echo "  Build plugin: cmake -B build -GNinja && cmake --build build"
            echo "  Build .lgx:   nix build .#lgx"
            echo "  Install:      nix run .#install"
          '';
        };
      });
}
