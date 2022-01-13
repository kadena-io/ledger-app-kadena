rec {
  ledger-platform = import ./dep/ledger-platform {};

  inherit (ledger-platform)
    lib
    pkgs ledgerPkgs
    crate2nix
    buildRustCrateForPkgsLedger;

  app = import ./Cargo.nix {
    pkgs = ledgerPkgs;
    buildRustCrateForPkgs = pkgs: let
      fun = (buildRustCrateForPkgsLedger pkgs).override {
        defaultCrateOverrides = pkgs.defaultCrateOverrides // {
          kadena = attrs: let
            sdk = lib.findFirst (p: lib.hasPrefix "rust_nanos_sdk" p.name) (builtins.throw "no sdk!") attrs.dependencies;
          in {
            preHook = ledger-platform.gccLibsPreHook;
            extraRustcOpts = [
              "-C" "relocation-model=ropi"
              "-C" "link-arg=-T${sdk.lib}/lib/nanos_sdk.out/script.ld"
              "-C" "linker=${pkgs.stdenv.cc.targetPrefix}lld"
            ];
          };
        };
      };
    in
      args: fun (args // lib.optionalAttrs pkgs.stdenv.hostPlatform.isAarch32 {
        RUSTC_BOOTSTRAP = true;
        dependencies = map (d: d // { stdlib = true; }) [
          ledger-platform.ledgerCore
          ledger-platform.ledgerCompilerBuiltins
        ] ++ args.dependencies;
      });
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
