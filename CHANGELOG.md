## 0.1.1

Added support for the following

* Signing arbitrary hash. This must be enabled from the 'Settings' menu.
* 'coin.TRANSFER_XCHAIN' capability.
* Signing transaction containing arbitrary number of capabilities, with arbitrary number of arguments. A generic message will be shown for unknown capabilities, and a warning will be shown if the arguments of the capability cannot be shown on the Ledger device.

## 0.1.0

* Initial version with support for signing simple 'coin.TRANSFER', 'coin.ROTATE' and 'coin.transfer-crosschain' transactions.
