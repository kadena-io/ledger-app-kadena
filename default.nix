rec {
  ledger-platform = import ./dep/ledger-platform {};

  inherit (ledger-platform) pkgs ;

  ledger-app = ledger-platform.ledger-app {
    appName = "kadena";
    appGif = ./rust-app/kadena.gif;
    appToml = ./rust-app/Cargo.toml;
    cargoNix = import ./Cargo.nix;
    testPackage = (import ./ts-tests/override.nix { inherit pkgs; }).package;

  };
  inherit (ledger-app) loadApp tarball test;
  inherit (pkgs.nodePackages) node2nix;
}
