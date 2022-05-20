use crate::crypto_helpers::{eddsa_sign, get_pkh, get_private_key, get_pubkey, get_pubkey_from_privkey, Hasher, Hash};
use crate::interface::*;
use crate::*;
use arrayvec::ArrayString;
use arrayvec::ArrayVec;
use core::fmt::Write;
use ledger_log::{info};
use ledger_parser_combinators::interp_parser::{
    Action, DefaultInterp, DropInterp, InterpParser, ObserveLengthedBytes, SubInterp, OOB, set_from_thunk
};
use ledger_parser_combinators::json::Json;
use ledger_parser_combinators::core_parsers::Alt;
use prompts_ui::{write_scroller, final_accept_prompt, mk_prompt_write};

use ledger_parser_combinators::define_json_struct_interp;
use ledger_parser_combinators::json_interp::AltResult::*;
use ledger_parser_combinators::json::*;
use ledger_parser_combinators::json_interp::*;
use ledger_parser_combinators::interp_parser::*;
use core::convert::TryFrom;
use core::str::from_utf8;

// A couple type ascription functions to help the compiler along.
const fn mkfn<A,B>(q: fn(&A,&mut B)->Option<()>) -> fn(&A,&mut B)->Option<()> {
  q
}
const fn mkfnc<A,B,C>(q: fn(&A,&mut B,C)->Option<()>) -> fn(&A,&mut B,C)->Option<()> {
    q
}
const fn mkvfn<A>(q: fn(&A,&mut Option<()>)->Option<()>) -> fn(&A,&mut Option<()>)->Option<()> {
  q
}

pub type GetAddressImplT = impl InterpParser<Bip32Key, Returning = ArrayVec<u8, 128_usize>>;
pub const GET_ADDRESS_IMPL: GetAddressImplT =
    Action(SubInterp(DefaultInterp), mkfn(|path: &ArrayVec<u32, 10>, destination: &mut Option<ArrayVec<u8, 128>>| {
        let key = get_pubkey(&path).ok()?;

        let pkh = get_pkh(key);

        write_scroller("Provide Public Key", |w| Ok(write!(w, "{}", pkh)?))?;

        final_accept_prompt(&[])?;

        *destination=Some(ArrayVec::new());
        // key without y parity
        let key_x = &key.W[1..key.W_len as usize];
        destination.as_mut()?.try_push(u8::try_from(key_x.len()).ok()?).ok()?;
        destination.as_mut()?.try_extend_from_slice(key_x).ok()?;
        Some(())
    }));

pub type SignImplT = impl InterpParser<SignParameters, Returning = ArrayVec<u8, 128_usize>>;

#[derive(PartialEq, Debug)]
enum CapabilityCoverage {
    Full,
    HasFallback,
    NoCaps
}

impl Summable<CapabilityCoverage> for CapabilityCoverage {
    fn zero() -> Self { CapabilityCoverage::Full }
    fn add_and_set(&mut self, other: &CapabilityCoverage) {
        match other {
            CapabilityCoverage::Full => { }
            CapabilityCoverage::HasFallback => { if *self == CapabilityCoverage::Full { *self = CapabilityCoverage::HasFallback } }
            CapabilityCoverage::NoCaps => { *self = CapabilityCoverage::NoCaps }
        }
    }
}

pub static SIGN_IMPL: SignImplT = Action(
    (
        Action(
            // Calculate the hash of the transaction
            ObserveLengthedBytes(
                Hasher::new,
                Hasher::update,
                Json(Action(Preaction( || -> Option<()> { write_scroller("Signing", |w| Ok(write!(w, "Transaction")?)) } , KadenaCmdInterp {
                    field_nonce: DropInterp,
                    field_meta: Action(MetaInterp {
                        field_chain_id: Action(JsonStringAccumulate::<32>, mkvfn(|chain: &ArrayVec<u8, 32>, _| -> Option<()> {
                                write_scroller("On Chain", |w| Ok(write!(w, "{}", from_utf8(chain.as_slice()).ok()?)?))
                        })),
                        field_sender: DropInterp,
                        field_gas_limit: JsonStringAccumulate::<100>,
                        field_gas_price: JsonStringAccumulate::<100>,
                        field_ttl: DropInterp,
                        field_creation_time: DropInterp
                    }, mkvfn(|Meta { ref field_gas_limit, ref field_gas_price, .. } : &Meta<_,_,Option<ArrayVec<u8,100>>,Option<ArrayVec<u8,100>>,_,_>, _| {
                        write_scroller("Using Gas", |w| Ok(write!(w, "at most {} at price {}", from_utf8(field_gas_limit.as_ref()?.as_slice()).ok()?, from_utf8(field_gas_price.as_ref()?.as_slice()).ok()?)?))
                    })),
                    field_payload: PayloadInterp {
                        field_exec: CommandInterp {
                            field_code: DropInterp,
                            field_data: DropInterp
                        }},
                    field_signers: SubInterpM::<_, CapabilityCoverage>::new(Action(Preaction(
                            || -> Option<()> {
                                write_scroller("Requiring", |w| Ok(write!(w, "Capabilities")?))
                            },
                            SignerInterp {
                        field_scheme: DropInterp,
                        field_pub_key: Action(JsonStringAccumulate::<64>, mkvfn(|key : &ArrayVec<u8, 64>, _: &mut Option<()>| -> Option<()> {
                            write_scroller("Of Key", |w| Ok(write!(w, "{}", from_utf8(key.as_slice())?)?))
                        })),
                        field_addr: DropInterp,
                        field_clist: CLIST_ACTION,
                    }),
                        mkfn(|signer: &Signer<_,_,_, Option<(CapCountData, All)>>, dest: &mut Option<CapabilityCoverage> | {
                            *dest = Some(match signer.field_clist {
                                Some((CapCountData::CapCount{total_caps,..}, All(a))) if total_caps > 0 => if a {CapabilityCoverage::Full} else {CapabilityCoverage::HasFallback},
                                _ => CapabilityCoverage::NoCaps,
                            });
                            Some(())
                        })),
                        ),
                    field_network_id: Action(JsonStringAccumulate::<32>, mkvfn(|net: &ArrayVec<u8, 32>, dest: &mut Option<()>| {
                        *dest = Some(());
                        write_scroller("On Network", |w| Ok(write!(w, "{}", from_utf8(net.as_slice())?)?))
                    }))
                }),
                mkvfn(|cmd : &KadenaCmd<_,_,Option<CapabilityCoverage>,_,_>, _| { 
                    match cmd.field_signers.as_ref() {
                        Some(CapabilityCoverage::Full) => { }
                        Some(CapabilityCoverage::HasFallback) => {
                            write_scroller("WARNING", |w| Ok(write!(w, "Transaction too large for Ledger to display.  PROCEED WITH GREAT CAUTION.  Do you want to continue?")?))?;
                        }
                        _ => {
                            write_scroller("WARNING", |w| Ok(write!(w, "UNSAFE TRANSACTION. This transaction's code was not recognized and does not limit capabilities for all signers. Signing this transaction may make arbitrary actions on the chain including loss of all funds.")?))?;
                        }
                    }
                    Some(())
                })
                )),
            true),
            // Ask the user if they accept the transaction body's hash
            mkfn(|(_, mut hash): &(_, Hasher), destination: &mut Option<[u8; 32]>| {
                let the_hash = hash.finalize();
                write_scroller("Transaction hash", |w| Ok(write!(w, "{}", the_hash)?))?;
                *destination=Some(the_hash.0.into());
                Some(())
            }),
        ),
        Action(
            SubInterp(DefaultInterp),
            // And ask the user if this is the key the meant to sign with:
            mkfn(|path: &ArrayVec<u32, 10>, destination: &mut _| {
                // Mutable because of some awkwardness with the C api.
                let mut privkey = get_private_key(&path).ok()?;
                let pubkey = get_pubkey_from_privkey(&mut privkey).ok()?;
                let pkh = get_pkh(pubkey);

                write_scroller("Sign for Address", |w| Ok(write!(w, "{}", pkh)?))?;
                *destination = Some(privkey);
                Some(())
            }),
        ),
    ),
    mkfn(|(hash, key): &(Option<[u8; 32]>, Option<_>), destination: &mut _| {
        final_accept_prompt(&[&"Sign Transaction?"])?;

        // By the time we get here, we've approved and just need to do the signature.
        let sig = eddsa_sign(&hash.as_ref()?[..], key.as_ref()?)?;
        let mut rv = ArrayVec::<u8, 128>::new();
        rv.try_extend_from_slice(&sig.0[..]).ok()?;
        *destination = Some(rv);
        Some(())
    }),
);

#[derive(Debug, Clone, Copy)]
enum CapCountData {
    IsTransfer,
    IsUnknownCap,
    CapCount {
        total_caps: u16,
        total_transfers: u16,
        total_unknown: u16,
    },
}

impl Summable<CapCountData> for CapCountData {
    fn add_and_set(&mut self, other: &CapCountData) {
        match self {
            CapCountData::CapCount {total_caps, total_transfers, total_unknown} => {
                *total_caps += 1;
                match other {
                    CapCountData::IsTransfer => *total_transfers += 1,
                    CapCountData::IsUnknownCap => *total_unknown += 1,
                    _ => {},
                }
            },
            _ => {}
        }
    }
    fn zero() -> Self { CapCountData::CapCount { total_caps: 0, total_transfers: 0, total_unknown: 0} }
}

const CLIST_ACTION: SubInterpMFold::<Action<KadenaCapabilityInterp<KadenaCapabilityArgsInterp, JsonStringAccumulate<128_usize>>, for<'r, 's> fn(&'r KadenaCapability<Option<<KadenaCapabilityArgsInterp as ParserCommon<JsonArray<JsonAny>>>::Returning>, Option<ArrayVec<u8, 128_usize>>>, &'s mut Option<(CapCountData, bool)>, (CapCountData, All)) -> Option<()>>, (CapCountData, All)> =
  SubInterpMFold::new(Action(
      KadenaCapabilityInterp {
          field_args: KadenaCapabilityArgsInterp,
          field_name: JsonStringAccumulate::<128>
      },
      mkfnc(|cap : &KadenaCapability<Option<<KadenaCapabilityArgsInterp as ParserCommon<JsonArray<JsonAny>>>::Returning>, Option<ArrayVec<u8, 128>>>, destination: &mut Option<(CapCountData, bool)>, v: (CapCountData, All)| {
          let name = cap.field_name.as_ref()?.as_slice();
          let name_utf8 = from_utf8(name).ok()?;
          let mk_unknown_cap_title = || -> Option <_>{
              let count = match v.0 {
                  CapCountData::CapCount{ total_unknown, ..} => total_unknown,
                  _ => 0,
              };
              let mut buffer: ArrayString<22> = ArrayString::new();
              Ok(write!(mk_prompt_write(&mut buffer), "Unknown Capability {}", count + 1).ok()?)?;
              Some(buffer)
          };
          let mk_transfer_title = || -> Option <_>{
              let count = match v.0 {
                  CapCountData::CapCount{ total_transfers, ..} => total_transfers,
                  _ => 0,
              };
              let mut buffer: ArrayString<22> = ArrayString::new();
              Ok(write!(mk_prompt_write(&mut buffer), "Transfer {}", count + 1).ok()?)?;
              Some(buffer)
          };
          let transfer_prompt = |(sender, receiver, amount):(&ArrayVec<u8, 128>, &ArrayVec<u8, 128>, &ArrayVec<u8, 20>)| -> Option<()> {
              write_scroller(&mk_transfer_title()?, |w| Ok(write!(w, "{} from {} to {}", from_utf8(amount.as_slice())?, from_utf8(sender.as_slice())?, from_utf8(receiver.as_slice())?)?))?;
              Some(())
          };
          let cross_transfer_prompt = |(sender, receiver, amount, target_chain):(&ArrayVec<u8, 128>, &ArrayVec<u8, 128>, &ArrayVec<u8, 20>, &ArrayVec<u8, 20>)| -> Option<()> {
              write_scroller(&mk_transfer_title()?, |w| Ok(write!(w, "Cross-chain {} from {} to {} to chain {}", from_utf8(amount.as_slice())?, from_utf8(sender.as_slice())?, from_utf8(receiver.as_slice())?, from_utf8(target_chain.as_slice())?)?))?;
              Some(())
          };

          trace!("Prompting for capability");
          *destination = Some((CapCountData::IsUnknownCap, true));
          match cap.field_args.as_ref() {
              Some((None, None, None, None)) if name == b"coin.GAS" => {
                  write_scroller("Paying Gas", |w| Ok(write!(w, " ")?))?;
                  *destination = Some((Summable::zero(), true));
                  trace!("Accepted gas");
              }
              _ if name == b"coin.GAS" => { return None; }
              Some((Some(Some(acct)), None, None, None)) if name == b"coin.ROTATE" => {
                  write_scroller("Rotate for account", |w| Ok(write!(w, "{}", from_utf8(acct.as_slice())?)?))?;
                  *destination = Some((Summable::zero(), true));
              }
              _ if name == b"coin.ROTATE" => { return None; }
              Some((Some(Some(sender)), Some(Some(receiver)), Some(First(amount)), None)) if name == b"coin.TRANSFER" => {
                  transfer_prompt((sender, receiver, amount));
                  *destination = Some((CapCountData::IsTransfer, true));
              }
              Some((Some(Some(sender)), Some(Some(receiver)), Some(Second(Some(Decimal{field_decimal:Some (amount)}))), None)) if name == b"coin.TRANSFER" => {
                  transfer_prompt((sender, receiver, amount));
                  *destination = Some((CapCountData::IsTransfer, true));
              }
              _ if name == b"coin.TRANSFER" => { return None; }
              Some((Some(Some(sender)), Some(Some(receiver)), Some(First(amount)), Some(Some(target_chain)))) if name == b"coin.TRANSFER_XCHAIN" => {
                  cross_transfer_prompt((sender, receiver, amount, target_chain));
                  *destination = Some((CapCountData::IsTransfer, true));
              }
              Some((Some(Some(sender)), Some(Some(receiver)), Some(Second(Some(Decimal{field_decimal:Some (amount)}))), Some(Some(target_chain)))) if name == b"coin.TRANSFER_XCHAIN" => {
                  cross_transfer_prompt((sender, receiver, amount, target_chain));
                  *destination = Some((CapCountData::IsTransfer, true));
              }
              _ if name == b"coin.TRANSFER_XCHAIN" => { return None; }
              Some((None, None, None, None)) => {
                  write_scroller(&mk_unknown_cap_title()?, |w| Ok(write!(w, "name: {}, no args", name_utf8)?))?;
              }
              Some((Some(Some(arg1)), None, None, None)) => {
                  write_scroller(&mk_unknown_cap_title()?, |w| Ok(write!(w, "name: {}, arg 1: '{}'", name_utf8, from_utf8(arg1.as_slice())?)?))?;
              }
              Some((Some(Some(arg1)), Some(Some(arg2)), None, None)) => {
                  write_scroller(&mk_unknown_cap_title()?, |w| Ok(write!(w, "name: {}, arg 1: '{}', arg 2: '{}'", name_utf8, from_utf8(arg1.as_slice())?, from_utf8(arg2.as_slice())?)?))?;
              }
              Some((Some(Some(arg1)), Some(Some(arg2)), Some(First(arg3)), None)) => {
                  write_scroller(&mk_unknown_cap_title()?, |w| Ok(write!(w, "name: {}, arg 1: '{}', arg 2: '{}', arg 3: {}", name_utf8, from_utf8(arg1.as_slice())?, from_utf8(arg2.as_slice())?, from_utf8(arg3.as_slice())?)?))?;
              }
              Some((Some(Some(arg1)), Some(Some(arg2)), Some(First(arg3)), Some(Some(arg4)))) => {
                  write_scroller(&mk_unknown_cap_title()?, |w| Ok(write!(w, "name: {}, arg 1: '{}', arg 2: '{}', arg 3: {}, arg 4: '{}'", name_utf8, from_utf8(arg1.as_slice())?, from_utf8(arg2.as_slice())?, from_utf8(arg3.as_slice())?, from_utf8(arg4.as_slice())?)?))?;
              }
              _ => {
                  write_scroller(&mk_unknown_cap_title()?, |w| Ok(write!(w, "name: {}, args cannot be displayed on Ledger", name_utf8)?))?;
                  set_from_thunk(destination, || Some((CapCountData::IsUnknownCap, false))); // Fallback case
              }
          }
          Some(())
      }),
  ));

pub type SignHashImplT = impl InterpParser<SignHashParameters, Returning = ArrayVec<u8, 128_usize>>;

pub static SIGN_HASH_IMPL: SignHashImplT = Action(
    Preaction( || -> Option<()> { write_scroller("Signing", |w| Ok(write!(w, "Transaction Hash")?)) } ,
    (
        Action(
            SubInterp(DefaultInterp),
            // Ask the user if they accept the transaction body's hash
            mkfn(|hash_val: &[u8; 32], destination: &mut Option<[u8; 32]>| {
                let the_hash = Hash ( *hash_val );
                write_scroller("Transaction hash", |w| Ok(write!(w, "{}", the_hash)?))?;
                *destination=Some(the_hash.0.into());
                Some(())
            }),
        ),
        Action(
            SubInterp(DefaultInterp),
            // And ask the user if this is the key the meant to sign with:
            mkfn(|path: &ArrayVec<u32, 10>, destination: &mut _| {
                // Mutable because of some awkwardness with the C api.
                let mut privkey = get_private_key(&path).ok()?;
                let pubkey = get_pubkey_from_privkey(&mut privkey).ok()?;
                let pkh = get_pkh(pubkey);

                write_scroller("Sign for Address", |w| Ok(write!(w, "{}", pkh)?))?;
                *destination = Some(privkey);
                Some(())
            }),
        ),
    )),
    mkfn(|(hash, key): &(Option<[u8; 32]>, Option<_>), destination: &mut _| {
        final_accept_prompt(&[&"Sign Transaction Hash?"])?;

        // By the time we get here, we've approved and just need to do the signature.
        let sig = eddsa_sign(&hash.as_ref()?[..], key.as_ref()?)?;
        let mut rv = ArrayVec::<u8, 128>::new();
        rv.try_extend_from_slice(&sig.0[..]).ok()?;
        *destination = Some(rv);
        Some(())
    }),
);

pub struct KadenaCapabilityArgsInterp;
type ThirdArgT = Alt<JsonNumber, Alt<DecimalSchema, JsonAny>>;
type ThirdArgInterpT = Alt<JsonStringAccumulate<20>, OrDropAny<DecimalInterp<JsonStringAccumulate<20>>>>;

#[derive(Debug)]
pub enum KadenaCapabilityArgsInterpState {
    Start,
    Begin,
    FirstArgument(<OrDropAny<JsonStringAccumulate<128>> as ParserCommon<Alt<JsonString, JsonAny>>>::State),
    FirstValueSep,
    SecondArgument(<OrDropAny<JsonStringAccumulate<128>> as ParserCommon<Alt<JsonString, JsonAny>>>::State),
    SecondValueSep,
    ThirdArgument(<ThirdArgInterpT as ParserCommon<ThirdArgT>>::State),
    ThirdValueSep,
    FourthArgument(<OrDropAny<JsonStringAccumulate<20>> as ParserCommon<Alt<JsonString, JsonAny>>>::State),
    FourthValueSep,
    FallbackValue(<DropInterp as ParserCommon<JsonAny>>::State),
    FallbackValueSep
}

impl ParserCommon<JsonArray<JsonAny>> for KadenaCapabilityArgsInterp {
    type State = (KadenaCapabilityArgsInterpState, Option<<DropInterp as ParserCommon<JsonAny>>::Returning>);
    type Returning = ( Option<Option<ArrayVec<u8, 128>>>, Option<Option<ArrayVec<u8, 128>>>, Option<AltResult<ArrayVec<u8, 20_usize>, Option<Decimal<Option<ArrayVec<u8, 20_usize>>>>>>, Option<Option<ArrayVec<u8, 20>>> );
    fn init(&self) -> Self::State {
        (KadenaCapabilityArgsInterpState::Start, None)
    }
}
impl JsonInterp<JsonArray<JsonAny>> for KadenaCapabilityArgsInterp {
    #[inline(never)]
    fn parse<'a, 'b>(&self, (ref mut state, ref mut scratch): &'b mut Self::State, token: JsonToken<'a>, destination: &mut Option<Self::Returning>) -> Result<(), Option<OOB>> {
        let str_interp = OrDropAny(JsonStringAccumulate::<128>);
        let dec_interp = Alt(JsonStringAccumulate::<20>, OrDropAny(DecimalInterp { field_decimal: JsonStringAccumulate::<20>}));
        let f_interp = OrDropAny(JsonStringAccumulate::<20>);
        loop {
            use KadenaCapabilityArgsInterpState::*;
            match state {
                Start if token == JsonToken::BeginArray => {
                    set_from_thunk(destination, || Some((None, None, None, None)));
                    set_from_thunk(state, || Begin);
                }
                Begin if token == JsonToken::EndArray => {
                    return Ok(());
                }
                Begin => {
                    set_from_thunk(state, || FirstArgument(<OrDropAny<JsonStringAccumulate<128>> as ParserCommon<Alt<JsonString, JsonAny>>>::init(&str_interp)));
                    continue;
                }
                FirstArgument(ref mut s) => {
                    <OrDropAny<JsonStringAccumulate<128>> as JsonInterp<Alt<JsonString, JsonAny>>>::parse(&str_interp, s, token, &mut destination.as_mut().ok_or(Some(OOB::Reject))?.0)?;
                    set_from_thunk(state, || FirstValueSep);
                }
                FirstValueSep if token == JsonToken::ValueSeparator => {
                    set_from_thunk(state, || SecondArgument(<OrDropAny<JsonStringAccumulate<128>> as ParserCommon<Alt<JsonString, JsonAny>>>::init(&str_interp)));
                }
                FirstValueSep if token == JsonToken::EndArray => return Ok(()),
                SecondArgument(ref mut s) => {
                    <OrDropAny<JsonStringAccumulate<128>> as JsonInterp<Alt<JsonString, JsonAny>>>::parse(&str_interp, s, token, &mut destination.as_mut().ok_or(Some(OOB::Reject))?.1)?;
                    set_from_thunk(state, || SecondValueSep);
                }
                SecondValueSep if token == JsonToken::ValueSeparator => {
                    set_from_thunk(state, || ThirdArgument(<ThirdArgInterpT as ParserCommon<ThirdArgT>>::init(&dec_interp)));
                }
                SecondValueSep if token == JsonToken::EndArray => return Ok(()),
                ThirdArgument(ref mut s) => {
                    <ThirdArgInterpT as JsonInterp<ThirdArgT>>::parse(&dec_interp, s, token, &mut destination.as_mut().ok_or(Some(OOB::Reject))?.2)?;
                    set_from_thunk(state, || ThirdValueSep);
                }
                ThirdValueSep if token == JsonToken::ValueSeparator => {
                    set_from_thunk(state, || FourthArgument(<OrDropAny<JsonStringAccumulate<20>> as ParserCommon<Alt<JsonString, JsonAny>>>::init(&f_interp)));
                }
                ThirdValueSep if token == JsonToken::EndArray => return Ok(()),
                FourthArgument(ref mut s) => {
                    <OrDropAny<JsonStringAccumulate<20>> as JsonInterp<Alt<JsonString, JsonAny>>>::parse(&f_interp, s, token, &mut destination.as_mut().ok_or(Some(OOB::Reject))?.3)?;
                    set_from_thunk(state, || FourthValueSep);
                }
                FourthValueSep if token == JsonToken::EndArray => return Ok(()),
                FourthValueSep if token == JsonToken::ValueSeparator => {
                    set_from_thunk(destination, || None);
                    set_from_thunk(state, || FallbackValue(<DropInterp as ParserCommon<JsonAny>>::init(&DropInterp)));
                }
                FallbackValue(ref mut s) => {
                    <DropInterp as JsonInterp<JsonAny>>::parse(&DropInterp, s, token, scratch)?;
                    set_from_thunk(state, || FallbackValueSep);
                }
                FallbackValueSep if token == JsonToken::ValueSeparator => {
                    set_from_thunk(state, || FallbackValue(<DropInterp as ParserCommon<JsonAny>>::init(&DropInterp)));
                }
                FallbackValueSep if token == JsonToken::EndArray => {
                    return Ok(());
                }
                _ => return Err(Some(OOB::Reject))
            }
            break Err(None)
        }
    }
}

// The global parser state enum; any parser above that'll be used as the implementation for an APDU
// must have a field here.

pub enum ParsersState {
    NoState,
    SettingsState(u8),
    GetAddressState(<GetAddressImplT as ParserCommon<Bip32Key>>::State),
    SignState(<SignImplT as ParserCommon<SignParameters>>::State),
    SignHashState(<SignHashImplT as ParserCommon<SignHashParameters>>::State),
}

pub fn reset_parsers_state(state: &mut ParsersState) {
    *state = ParsersState::NoState;
}

meta_definition!{}
decimal_definition!{}
kadena_capability_definition!{}
signer_definition!{}
payload_definition!{}
command_definition!{}
kadena_cmd_definition!{}

#[inline(never)]
pub fn get_get_address_state(
    s: &mut ParsersState,
) -> &mut <GetAddressImplT as ParserCommon<Bip32Key>>::State {
    match s {
        ParsersState::GetAddressState(_) => {}
        _ => {
            info!("Non-same state found; initializing state.");
            *s = ParsersState::GetAddressState(<GetAddressImplT as ParserCommon<Bip32Key>>::init(
                &GET_ADDRESS_IMPL,
            ));
        }
    }
    match s {
        ParsersState::GetAddressState(ref mut a) => a,
        _ => {
            panic!("")
        }
    }
}

#[inline(never)]
pub fn get_sign_state(
    s: &mut ParsersState,
) -> &mut <SignImplT as ParserCommon<SignParameters>>::State {
    match s {
        ParsersState::SignState(_) => {}
        _ => {
            info!("Non-same state found; initializing state.");
            *s = ParsersState::SignState(<SignImplT as ParserCommon<SignParameters>>::init(
                &SIGN_IMPL,
            ));
        }
    }
    match s {
        ParsersState::SignState(ref mut a) => a,
        _ => {
            panic!("")
        }
    }
}

#[inline(never)]
pub fn get_sign_hash_state(
    s: &mut ParsersState,
) -> &mut <SignHashImplT as ParserCommon<SignHashParameters>>::State {
    match s {
        ParsersState::SignHashState(_) => {}
        _ => {
            info!("Non-same state found; initializing state.");
            *s = ParsersState::SignHashState(<SignHashImplT as ParserCommon<SignHashParameters>>::init(
                &SIGN_HASH_IMPL,
            ));
        }
    }
    match s {
        ParsersState::SignHashState(ref mut a) => a,
        _ => {
            panic!("")
        }
    }
}
