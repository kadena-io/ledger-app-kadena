# Kadena Ledger App

This application is compatible with Ledger Nano S devices running FW 2.1.0 and above.

### Installation using the pre-packaged tarball

Before installing please ensure that your device is plugged, unlocked, and on the device home screen. 

Installing the app from a tarball can be done using `ledgerctl`. For more information on how to install and use that tool see the [instructions from LedgerHQ](https://github.com/LedgerHQ/ledgerctl).

```bash
tar xzf release.tar.gz
cd kadena
ledgerctl install -f app.json
```

Using nix, `ledgerctl` can only so be obtained by running this from the root of the repo.

```
$(nix-build --no-out-link -A ledger-platform.ledgerctl)/bin/ledgerctl install -f app.json
```

## Using the app with generic CLI tool

The bundled `generic-cli` tool can be used to obtaining the public key and do signing.

To use this tool first install it using Nix. From the root level of this repo, run:

```bash
nix-build -A ledger-platform.generic-cli -o result-generic-cli
```

This command will create a file (symlink) named `result-generic-cli` which could be used as described below.

```bash
./result-generic-cli/bin/generic-cli getAddress "44'/626'/0'/0/0"
```

For signing, the "cmd" of the transaction (in the JSON format) should be provided like this

```bash
./result-generic-cli/bin/generic-cli sign --json "44'/626'/0'/0/0" '{"networkId":"mainnet01","payload":{"exec":{"data":{"ks":{"pred":"keys-all","keys":["368820f80c324bbc7c2b0610688a7da43e39f91d118732671cd9c7500ff43cca"]}},"code":"(coin.transfer-create \"alice\" \"bob\" (read-keyset \"ks\") 100.1)\n(coin.transfer \"bob\" \"alice\" 0.1)"}},"signers":[{"pubKey":"6be2f485a7af75fedb4b7f153a903f7e6000ca4aa501179c91a2450b777bd2a7","clist":[{"args":["alice","bob",100.1],"name":"coin.TRANSFER"},{"args":[],"name":"coin.GAS"}]},{"pubKey":"368820f80c324bbc7c2b0610688a7da43e39f91d118732671cd9c7500ff43cca","clist":[{"args":["bob","alice",0.1],"name":"coin.TRANSFER"}]}],"meta":{"creationTime":1580316382,"ttl":7200,"gasLimit":1200,"chainId":"0","gasPrice":1.0e-5,"sender":"alice"},"nonce":"2020-01-29 16:46:22.916695 UTC"}'
```

Alternatively the contents of JSON could be copied to a file, and the name of the file could be used in the command-line instead. This is necessary when the size of the JSON being signed is very big, as the command-line has limits to the length.

The following command demonstrates signing a big transaction specified in the file `./ts-tests/marmalade-tx.json`

```bash
./result-generic-cli/bin/generic-cli sign --file --json "44'/626'/0'/0/0" ./ts-tests/marmalade-tx.json
```

## Building the app from source

**Note**: the latest release branch is `main`, but the default branch in the git repo is `develop`.
If you want to use the latest release, make sure you have the `main` branch checked out before doing the build.

This application has been packaged up with [Nix](https://nixos.org/).

### Nix/Linux

Using Nix, from the root level of this repo, run:

```bash
nix-shell -A ledger-platform.rustShell
cd rust-app/
cargo-ledger load
````

The [cargo-ledger](https://github.com/LedgerHQ/cargo-ledger.git) builds, outputs a `hex` file and a manifest file for `ledgerctl`, and loads it on a device in a single `cargo-ledger load` command in the rust-app folder within app directory.

You do not need to install cargo-ledger outside of the nix-shell.

This application is compatible with Ledger Nano S devices running FW 2.1.0 and above. Before installing, please ensure that your device is plugged, unlocked, and on the device home screen. 

## Running tests

Using Nix, from the root level of this repo, run:
```bash
nix-shell -A ledger-platform.rustShell
cd rust-app/
cargo test
````
