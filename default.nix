rec {
  ledger-platform = import ./dep/ledger-platform {};

  inherit (ledger-platform)
    lib
    pkgs ledgerPkgs
    crate2nix
    buildRustCrateForPkgsLedger;

  app = import ./Cargo.nix {
    pkgs = ledgerPkgs;
    buildRustCrateForPkgs = pkgs: (buildRustCrateForPkgsLedger pkgs).override {
      defaultCrateOverrides = pkgs.defaultCrateOverrides // {
        nanos_sdk = _: {
          RUSTC_BOOTSTRAP = true;
        };
        ledger-parser-combinators = _: {
          RUSTC_BOOTSTRAP = true;
        };
        rust-app = attrs: let
          sdk = lib.findFirst (p: lib.hasPrefix "rust_nanos_sdk" p.name) (builtins.throw "no sdk!") attrs.dependencies;
        in {
          preHook = ledger-platform.gccLibsPreHook;
          extraRustcOpts = [
            "-C" "relocation-model=ropi"
            "-C" "link-arg=-T${sdk.lib}/lib/nanos_sdk.out/script.ld"
          ];
        };
      };
    };
  };

  # For CI
  rootCrate = app.rootCrate.build;

  tarSrc = pkgs.runCommandNoCC "tarSrc" { } ''
    install -d $out/kadena/target/thumbv6m-none-eabi/release/
    cp ${./tarball-default.nix} $out/kadena/default.nix
    cp ${./rust-app/app.json} $out/kadena/app.json
    cp ${./rust-app/kadena.gif} $out/kadena/kadena.gif
    cp ${./rust-app/target/thumbv6m-none-eabi/release/app.hex} $out/kadena/target/thumbv6m-none-eabi/release/app.hex
  '';
  tarball = pkgs.runCommandNoCC "app-tarball.tar.gz" { } ''
    tar -czvhf $out -C ${tarSrc} kadena
  '';
}
