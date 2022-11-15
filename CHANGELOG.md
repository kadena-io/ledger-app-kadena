## 0.2.1

Added support for the following

* Added support for building and signing transfer, transfer-create, and transfer-crosschain transactions on the Ledger device.
* Signing arbitrary hash. This must be enabled from the 'Settings' menu.
* Signing transaction containing arbitrary number of capabilities, with arbitrary number of arguments.
* A 'Cross-transfer' message is displayed for 'coin.TRANSFER_XCHAIN' capability.
* A generic message will be shown for unknown capabilities, with upto five arguments.
  And a warning will be shown if the arguments of the capability cannot be shown on the Ledger device.
* 'networkId' and 'clist' fields can be 'null'.
* The 'Transfer' and 'Unknown Capability' prompts shows the index.

## 0.1.0

* Initial version with support for signing simple 'coin.TRANSFER', 'coin.ROTATE' and 'coin.transfer-crosschain' transactions.
