use ledger_parser_combinators::core_parsers::*;
use ledger_parser_combinators::define_json_struct;
use ledger_parser_combinators::endianness::*;
use ledger_parser_combinators::json::*;

// Payload for a public key request
pub type Bip32Key = DArray<Byte, U32<{ Endianness::Little }>, 10>;

define_json_struct! { Meta 16 {
    chainId: JsonString,
    sender: JsonString,
    gasLimit: JsonNumber,
    gasPrice: JsonNumber,
    ttl: JsonNumber,
    creationTime: JsonNumber
}}

define_json_struct! { KadenaCapability 4 {
    args: JsonArray<JsonAny>,
    name: JsonString
}}

define_json_struct! { Signer 16 {
    scheme: JsonString,
    pubKey: JsonString,
    addr: JsonString,
    clist: Alt<JsonNull,JsonArray<KadenaCapabilitySchema>>
}}

define_json_struct! { Command 5 {
    data: JsonAny,
    code: JsonString
}}

define_json_struct! { Payload 5 {
    exec: CommandSchema
}}

define_json_struct! { KadenaCmd 16 {
  nonce: JsonString,
  meta: Alt<MetaSchema, JsonAny>,
  signers: JsonArray<SignerSchema>,
  payload: PayloadSchema,
  networkId: Alt<JsonString,JsonNull>
}}

// Payload for a signature request, content-agnostic.
pub type SignParameters = (
    LengthFallback<U32<{ Endianness::Little }>, Json<KadenaCmdSchema>>,
    Bip32Key,
);

pub type SignHashParameters = (Array<Byte, 32>, Bip32Key);

pub type ByteDArray<const N: usize> = DArray<Byte, Byte, N>;

pub const PARAM_AMOUNT_SIZE: usize = 32;
pub const PARAM_RECIPIENT_SIZE: usize = 64;
pub const PARAM_RECIPIENT_CHAIN_SIZE: usize = 2;
pub const PARAM_NETWORK_SIZE: usize = 20;
pub const PARAM_NAMESPACE_SIZE: usize = 16;
pub const PARAM_MOD_NAME_SIZE: usize = 32;

pub const PARAM_GAS_PRICE_SIZE: usize = 20;
pub const PARAM_GAS_LIMIT_SIZE: usize = 10;
pub const PARAM_CREATION_TIME_SIZE: usize = 12;
pub const PARAM_CHAIN_SIZE: usize = 2;
pub const PARAM_NOONCE_SIZE: usize = 32;
pub const PARAM_TTL_SIZE: usize = 20;

pub type MakeTransferTxParameters = (
    Bip32Key,
    MakeTransferTxParameters1,
    MakeTransferTxParameters2,
);

pub type MakeTransferTxParameters1 = (
    Byte, // txType
    (
        ByteDArray<PARAM_RECIPIENT_SIZE>,
        (
            ByteDArray<PARAM_RECIPIENT_CHAIN_SIZE>,
            (
                ByteDArray<PARAM_NETWORK_SIZE>,
                (
                    ByteDArray<PARAM_AMOUNT_SIZE>,
                    (
                        ByteDArray<PARAM_NAMESPACE_SIZE>,
                        ByteDArray<PARAM_MOD_NAME_SIZE>,
                    ),
                ),
            ),
        ),
    ),
);

pub type MakeTransferTxParameters2 = (
    ByteDArray<PARAM_GAS_PRICE_SIZE>,
    (
        ByteDArray<PARAM_GAS_LIMIT_SIZE>,
        (
            ByteDArray<PARAM_CREATION_TIME_SIZE>,
            (
                ByteDArray<PARAM_CHAIN_SIZE>,
                (ByteDArray<PARAM_NOONCE_SIZE>, ByteDArray<PARAM_TTL_SIZE>),
            ),
        ),
    ),
);
