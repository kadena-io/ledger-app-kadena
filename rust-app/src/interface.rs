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
  meta: MetaSchema,
  signers: JsonArray<SignerSchema>,
  payload: PayloadSchema,
  networkId: Alt<JsonString,JsonNull>
}}

// Payload for a signature request, content-agnostic.
pub type SignParameters = (
    LengthFallback<U32<{ Endianness::Little }>, Json<KadenaCmdSchema>>,
    Bip32Key,
);

pub type SignHashParameters = (
    Array<Byte, 32>,
    Bip32Key,
);
