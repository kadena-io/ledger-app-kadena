{pkgs ? import <nixpkgs> {}}:
let
  ledgerPlatform = import (fetchTarball "https://github.com/obsidiansystems/ledger-platform/archive/develop.tar.gz") {};
  ledgerctl = ledgerPlatform.ledgerctl;
  this = ./.;
in
pkgs.writeScriptBin "load-app" ''
  cd ${this}
  ${ledgerctl}/bin/ledgerctl install -f ${this}/app.json
''
