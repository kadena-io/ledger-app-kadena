#!/bin/sh

cargo-ledger --hex-next-to-json
tar -czvf release.tar.gz --transform 's,.*/,,;s,tarball-,,;s,^,kadena/,' app.json app.hex ../tarball-default.nix kadena.gif --mtime=0

echo
echo "==== Release sha256 ===="
echo

sha256sum release.tar.gz

