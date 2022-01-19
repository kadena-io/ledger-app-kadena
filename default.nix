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

  tarSrc = ledgerPkgs.runCommandCC "tarSrc" {
    nativeBuildInputs = [
      ledger-platform.cargo-ledger
      ledger-platform.ledgerRustPlatform.rust.cargo
    ];
  } (ledger-platform.cargoLedgerPreHook + ''

    cp ${./rust-app/Cargo.toml} ./Cargo.toml
    # So cargo knows it's a binary
    mkdir src
    touch src/main.rs

    cargo-ledger --use-prebuilt ${rootCrate}/bin/kadena --hex-next-to-json

    mkdir -p $out/kadena
    cp app.json app.hex $out/kadena
    cp ${./tarball-default.nix} $out/kadena/default.nix
    cp ${./rust-app/kadena.gif} $out/kadena/kadena.gif
  '');

  tarball = pkgs.runCommandNoCC "app-tarball.tar.gz" { } ''
    tar -czvhf $out -C ${tarSrc} kadena
  '';

  testPackage = (import ./ts-tests/override.nix { inherit pkgs; }).package;

  runTests = { appExe ? rootCrate + "/bin/kadena" }: pkgs.runCommandNoCC "run-tests" { buildInputs = [pkgs.wget ledger-platform.speculos.speculos pkgs.coreutils testPackage pkgs.nodejs-12_x ]; } ''
    RUST_APP=${rootCrate}/bin/*
    echo RUST APP IS $RUST_APP
    # speculos -k 2.0 $RUST_APP --display headless &
    mkdir $out
    (
    speculos -k 2.0 ${appExe} --display headless &
    SPECULOS=$!

    until wget -O/dev/null -o/dev/null http://localhost:5000; do sleep 0.1; done;

    pushd ${testPackage}/lib/node_modules/*/
    NO_UPDATE_NOTIFIER=true npm --offline test
    rv=$?
    popd
    kill $SPECULOS
    exit $rv) | tee $out/short |& tee $out/full
    rv=$?
    cat $out/short
    exit $rv
  '';
}
