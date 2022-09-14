let self = import ./.;
    lib = self.pkgs.lib;
in
  {
    generic-cli = self.alamgu.generic-cli;
  }
    # Tests are broken on nanos due to some weird speculos issues
  // lib.mapAttrs' (n: lib.nameValuePair ("nanos--" + n)) (builtins.removeAttrs self.nanos ["test" "test-with-loging"])
  // lib.mapAttrs' (n: lib.nameValuePair ("nanox--" + n)) self.nanox
  // lib.mapAttrs' (n: lib.nameValuePair ("nanosplus--" + n)) self.nanosplus
