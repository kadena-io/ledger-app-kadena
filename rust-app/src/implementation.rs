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
use ledger_prompts_ui::{final_accept_prompt, mk_prompt_write, ScrollerError, PromptWrite};

use ledger_parser_combinators::define_json_struct_interp;
use ledger_parser_combinators::json::*;
use ledger_parser_combinators::json_interp::*;
use ledger_parser_combinators::interp_parser::*;
use core::convert::TryFrom;
use core::str::from_utf8;

// A couple type ascription functions to help the compiler along.
const fn mkfn<A,B>(q: fn(&A,&mut B)->Option<()>) -> fn(&A,&mut B)->Option<()> {
  q
}
const fn mkmvfn<A,B,C>(q: fn(A,&mut B)->Option<C>) -> fn(A,&mut B)->Option<C> {
    q
}
const fn mkfnc<A,B,C>(q: fn(&A,&mut B,C)->Option<()>) -> fn(&A,&mut B,C)->Option<()> {
    q
}
const fn mkvfn<A>(q: fn(&A,&mut Option<()>)->Option<()>) -> fn(&A,&mut Option<()>)->Option<()> {
  q
}

#[cfg(not(target_device = "nanos"))]
#[inline(never)]
fn scroller < F: for <'b> Fn(&mut PromptWrite<'b, 16>) -> Result<(), ScrollerError> > (title: &str, prompt_function: F) -> Option<()> {
    ledger_prompts_ui::write_scroller_three_rows(title, prompt_function)
}

#[cfg(target_device = "nanos")]
#[inline(never)]
fn scroller < F: for <'b> Fn(&mut PromptWrite<'b, 16>) -> Result<(), ScrollerError> > (title: &str, prompt_function: F) -> Option<()> {
    ledger_prompts_ui::write_scroller(title, prompt_function)
}

fn mkstr(v: Option<&[u8]>) -> Result<&str, ScrollerError> {
    Ok(from_utf8(v.ok_or(ScrollerError)?)?)
}

pub type GetAddressImplT = impl InterpParser<Bip32Key, Returning = ArrayVec<u8, 128_usize>>;
pub const GET_ADDRESS_IMPL: GetAddressImplT =
    Action(SubInterp(DefaultInterp), mkfn(|path: &ArrayVec<u32, 10>, destination: &mut Option<ArrayVec<u8, 128>>| {
        let key = get_pubkey(&path).ok()?;

        let pkh = get_pkh(key);

        scroller("Provide Public Key", |w| Ok(write!(w, "{}", pkh)?))?;

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
                Json(Action(Preaction( || -> Option<()> { scroller("Signing", |w| Ok(write!(w, "Transaction")?)) } , KadenaCmdInterp {
                    field_nonce: DropInterp,
                    field_meta: META_ACTION,
                    field_payload: PayloadInterp {
                        field_exec: CommandInterp {
                            field_code: DropInterp,
                            field_data: DropInterp
                        }},
                    field_signers: SubInterpM::<_, CapabilityCoverage>::new(Action(Preaction(
                            || -> Option<()> {
                                scroller("Requiring", |w| Ok(write!(w, "Capabilities")?))
                            },
                            SignerInterp {
                        field_scheme: DropInterp,
                        field_pub_key: MoveAction(JsonStringAccumulate::<64>, mkmvfn(|key : ArrayVec<u8, 64>, dest: &mut Option<ArrayVec<u8, 64>>| -> Option<()> {
                            scroller("Of Key", |w| Ok(write!(w, "{}", from_utf8(key.as_slice())?)?))?;
                            set_from_thunk(dest, || Some(key));
                            Some(())
                        })),
                        field_addr: DropInterp,
                        field_clist: Alt(DropInterp, CLIST_ACTION),
                    }),
                        mkfn(|signer: &Signer<_,Option<ArrayVec<u8, 64>>,_, Option<AltResult<(),(CapCountData, All)>>>, dest: &mut Option<CapabilityCoverage> | {
                            *dest = Some(match signer.field_clist {
                                Some(AltResult::Second((CapCountData::CapCount{total_caps,..}, All(a)))) if total_caps > 0 => if a {CapabilityCoverage::Full} else {CapabilityCoverage::HasFallback},
                                _ => {
                                    match from_utf8(signer.field_pub_key.as_ref()?.as_slice()) {
                                        Ok(pub_key) => scroller("Unscoped Signer", |w| Ok(write!(w, "{}", pub_key)?)),
                                        _ => Some(()),
                                    };
                                    CapabilityCoverage::NoCaps
                                },
                            });
                            Some(())
                        })),
                        ),
                    field_network_id: Action(Alt(JsonStringAccumulate::<32>, DropInterp), mkvfn(|mnet: &AltResult<ArrayVec<u8, 32>, ()>, dest: &mut Option<()>| {
                        *dest = Some(());
                        match mnet {
                            AltResult::First(net) => {
                                scroller("On Network", |w| Ok(write!(w, "{}", from_utf8(net.as_slice())?)?))
                            }
                            _ => { Some(())} // Ignore null
                        }
                    }))
                }),
                mkvfn(|cmd : &KadenaCmd<_,_,Option<CapabilityCoverage>,_,_>, _| { 
                    match cmd.field_signers.as_ref() {
                        Some(CapabilityCoverage::Full) => { }
                        Some(CapabilityCoverage::HasFallback) => {
                            scroller("WARNING", |w| Ok(write!(w, "Transaction too large for Ledger to display.  PROCEED WITH GREAT CAUTION.  Do you want to continue?")?))?;
                        }
                        _ => {
                            scroller("WARNING", |w| Ok(write!(w, "UNSAFE TRANSACTION. This transaction's code was not recognized and does not limit capabilities for all signers. Signing this transaction may make arbitrary actions on the chain including loss of all funds.")?))?;
                        }
                    }
                    Some(())
                })
                )),
            true),
            // Ask the user if they accept the transaction body's hash
            mkfn(|(_, mut hash): &(_, Hasher), destination: &mut Option<[u8; 32]>| {
                let the_hash = hash.finalize();
                scroller("Transaction hash", |w| Ok(write!(w, "{}", the_hash)?))?;
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

                scroller("Sign for Address", |w| Ok(write!(w, "{}", pkh)?))?;
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

const META_ACTION:
  Action<MetaInterp<
          Action<JsonStringAccumulate<32_usize>, fn(&ArrayVec<u8, 32_usize>, &mut Option<()>) -> Option<()>>
          , DropInterp
          , JsonStringAccumulate<100_usize>
          , JsonStringAccumulate<100_usize>
          , DropInterp
          , DropInterp>
         , fn(&Meta<Option<()>, Option<()>, Option<ArrayVec<u8, 100_usize>>
                    , Option<ArrayVec<u8, 100_usize>>, Option<()>, Option<()>>
              , &mut Option<()>) -> Option<()>
         >
    = Action(
        MetaInterp {
            field_chain_id: Action(JsonStringAccumulate::<32>, mkvfn(|chain: &ArrayVec<u8, 32>, _| -> Option<()> {
                scroller("On Chain", |w| Ok(write!(w, "{}", from_utf8(chain.as_slice())?)?))
            })),
            field_sender: DropInterp,
            field_gas_limit: JsonStringAccumulate::<100>,
            field_gas_price: JsonStringAccumulate::<100>,
            field_ttl: DropInterp,
            field_creation_time: DropInterp
        }, mkvfn(|Meta { ref field_gas_limit, ref field_gas_price, .. }, _| {
            scroller("Using Gas", |w| Ok(write!(w, "at most {} at price {}"
                , from_utf8(field_gas_limit.as_ref().ok_or(ScrollerError)?.as_slice())?
                , from_utf8(field_gas_price.as_ref().ok_or(ScrollerError)?.as_slice())?)?))
        }));

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

const CLIST_ACTION:
  SubInterpMFold::<
    Action< KadenaCapabilityInterp<KadenaCapabilityArgsInterp, JsonStringAccumulate<128_usize>>
          , fn( &KadenaCapability< Option<<KadenaCapabilityArgsInterp as ParserCommon<JsonArray<JsonAny>>>::Returning>
                                , Option<ArrayVec<u8, 128_usize>>>
              , &mut Option<(CapCountData, bool)>
              , (CapCountData, All)
              ) -> Option<()>
          >
    , (CapCountData, All)
    > =
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
              write!(mk_prompt_write(&mut buffer), "Unknown Capability {}", count + 1).ok()?;
              Some(buffer)
          };
          let mk_transfer_title = || -> Option <_>{
              let count = match v.0 {
                  CapCountData::CapCount{ total_transfers, ..} => total_transfers,
                  _ => 0,
              };
              let mut buffer: ArrayString<22> = ArrayString::new();
              write!(mk_prompt_write(&mut buffer), "Transfer {}", count + 1).ok()?;
              Some(buffer)
          };

          trace!("Prompting for capability");
          *destination = Some((CapCountData::IsUnknownCap, true));
          match cap.field_args.as_ref() {
              Some((None, _)) => {
                  if name == b"coin.GAS" {
                      scroller("Paying Gas", |w| Ok(write!(w, " ")?))?;
                      *destination = Some((Summable::zero(), true));
                      trace!("Accepted gas");
                  } else {
                      scroller(&mk_unknown_cap_title()?, |w| Ok(write!(w, "name: {}, no args", name_utf8)?))?;
                  }
              }
              Some((Some(Some(args)), arg_lengths)) => {
                  if arg_lengths[3] != 0 {
                      scroller(&mk_unknown_cap_title()?, |w| Ok(
                          write!(w, "name: {}, arg 1: {}, arg 2: {}, arg 3: {}, arg 4: {}, arg 5: {}", name_utf8
                                 , mkstr(args.as_slice().get(0..arg_lengths[0]))?
                                 , mkstr(args.as_slice().get(arg_lengths[0]..arg_lengths[1]))?
                                 , mkstr(args.as_slice().get(arg_lengths[1]..arg_lengths[2]))?
                                 , mkstr(args.as_slice().get(arg_lengths[2]..arg_lengths[3]))?
                                 , mkstr(args.as_slice().get(arg_lengths[3]..args.len()))?
                          )?))?;
                  } else if arg_lengths[2] != 0 {
                      if name == b"coin.TRANSFER_XCHAIN" {
                          scroller(&mk_transfer_title()?, |w| Ok(
                              write!(w, "Cross-chain {} from {} to {} to chain {}"
                                     , mkstr(args.as_slice().get(arg_lengths[1]..arg_lengths[2]))?
                                     , mkstr(args.as_slice().get(0..arg_lengths[0]))?
                                     , mkstr(args.as_slice().get(arg_lengths[0]..arg_lengths[1]))?
                                     , mkstr(args.as_slice().get(arg_lengths[2]..args.len()))?
                              )?))?;
                          *destination = Some((CapCountData::IsTransfer, true));
                      } else {
                          scroller(&mk_unknown_cap_title()?, |w| Ok(
                              write!(w, "name: {}, arg 1: {}, arg 2: {}, arg 3: {}, arg 4: {}", name_utf8
                                     , mkstr(args.as_slice().get(0..arg_lengths[0]))?
                                     , mkstr(args.as_slice().get(arg_lengths[0]..arg_lengths[1]))?
                                     , mkstr(args.as_slice().get(arg_lengths[1]..arg_lengths[2]))?
                                     , mkstr(args.as_slice().get(arg_lengths[2]..args.len()))?
                              )?))?;
                      }
                  } else if arg_lengths[1] != 0 {
                      if name == b"coin.TRANSFER" {
                          scroller(&mk_transfer_title()?, |w| Ok(
                              write!(w, "{} from {} to {}"
                                     , mkstr(args.as_slice().get(arg_lengths[1]..args.len()))?
                                     , mkstr(args.as_slice().get(0..arg_lengths[0]))?
                                     , mkstr(args.as_slice().get(arg_lengths[0]..arg_lengths[1]))?
                              )?))?;
                          *destination = Some((CapCountData::IsTransfer, true));
                      } else {
                          scroller(&mk_unknown_cap_title()?, |w| Ok(
                              write!(w, "name: {}, arg 1: {}, arg 2: {}, arg 3: {}", name_utf8
                                     , mkstr(args.as_slice().get(0..arg_lengths[0]))?
                                     , mkstr(args.as_slice().get(arg_lengths[0]..arg_lengths[1]))?
                                     , mkstr(args.as_slice().get(arg_lengths[1]..args.len()))?
                              )?))?;
                      }
                  } else if arg_lengths[0] != 0 {
                      scroller(&mk_unknown_cap_title()?, |w| Ok(
                          write!(w, "name: {}, arg 1: {}, arg 2: {}", name_utf8
                                 , mkstr(args.as_slice().get(0..arg_lengths[0]))?
                                 , mkstr(args.as_slice().get(arg_lengths[0]..args.len()))?
                      )?))?;
                  } else {
                      if name == b"coin.ROTATE" {
                          scroller("Rotate for account", |w| Ok(write!(w, "{}", from_utf8(args)?)?))?;
                          *destination = Some((Summable::zero(), true));
                      } else {
                          scroller(&mk_unknown_cap_title()?, |w| Ok(write!(w, "name: {}, arg 1: {}", name_utf8, from_utf8(args)?)?))?;
                      }
                  }
              }
              _ => {
                  scroller(&mk_unknown_cap_title()?, |w| Ok(write!(w, "name: {}, args cannot be displayed on Ledger", name_utf8)?))?;
                  set_from_thunk(destination, || Some((CapCountData::IsUnknownCap, false))); // Fallback case
              }
          }
          Some(())
      }),
  ));

pub type SignHashImplT = impl InterpParser<SignHashParameters, Returning = ArrayVec<u8, 128_usize>>;

pub static SIGN_HASH_IMPL: SignHashImplT = Action(
    Preaction( || -> Option<()> { scroller("Signing", |w| Ok(write!(w, "Transaction Hash")?)) } ,
    (
        Action(
            SubInterp(DefaultInterp),
            // Ask the user if they accept the transaction body's hash
            mkfn(|hash_val: &[u8; 32], destination: &mut Option<[u8; 32]>| {
                let the_hash = Hash ( *hash_val );
                scroller("Transaction hash", |w| Ok(write!(w, "{}", the_hash)?))?;
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

                scroller("Sign for Address", |w| Ok(write!(w, "{}", pkh)?))?;
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

// The Caps list is parsed and the args are stored in a single common ArrayVec of this size.
// (This may be as large as the stack allows)
#[cfg(target_device = "nanos")]
const ARG_ARRAY_SIZE: usize = 272;
#[cfg(not(target_device = "nanos"))]
const ARG_ARRAY_SIZE: usize = 2048;
const MAX_ARG_COUNT: usize = 5;

// Since we use a single ArrayVec to store the rendered json of all the args.
// This list keeps track of the indices in the array for each arg, and even the args count

// If there are three args; then indices[0] will contain the end of first arg, indices[1] will be end of second, and indices[2] will be 0
// In other words, first arg will be: array[0..indices[0]], second: array[indices[0]..indices[1]], third: array[indices[1]..array.len()]
type ArgListIndicesT = [usize; MAX_ARG_COUNT - 1];

// The Alt parser will first try to parse JsonAny and render it upto the available space in array
// on hitting end of array it will fallback to the OrDropAny
type CapArgT = Alt<JsonAny, JsonAny>;
type CapArgInterpT = OrDropAny<JsonStringAccumulate<ARG_ARRAY_SIZE>>;

#[derive(Debug)]
pub enum KadenaCapabilityArgsInterpState {
    Start,
    Begin,
    Argument(<CapArgInterpT as ParserCommon<CapArgT>>::State),
    ValueSep,
    FallbackValue(<DropInterp as ParserCommon<JsonAny>>::State),
    FallbackValueSep
}

impl ParserCommon<JsonArray<JsonAny>> for KadenaCapabilityArgsInterp {
    type State = (KadenaCapabilityArgsInterpState, Option<<DropInterp as ParserCommon<JsonAny>>::Returning>, usize);
    type Returning = (Option<<CapArgInterpT as ParserCommon<CapArgT>>::Returning>, ArgListIndicesT );
    fn init(&self) -> Self::State {
        (KadenaCapabilityArgsInterpState::Start, None, 0)
    }
}
impl JsonInterp<JsonArray<JsonAny>> for KadenaCapabilityArgsInterp {
    #[inline(never)]
    fn parse<'a, 'b>(&self, (ref mut state, ref mut scratch, ref mut arg_count): &'b mut Self::State, token: JsonToken<'a>, destination: &mut Option<Self::Returning>) -> Result<(), Option<OOB>> {
        let str_interp = OrDropAny(JsonStringAccumulate::<ARG_ARRAY_SIZE>);
        loop {
            use KadenaCapabilityArgsInterpState::*;
            match state {
                Start if token == JsonToken::BeginArray => {
                    set_from_thunk(destination, || Some((None, [0,0,0,0])));
                    set_from_thunk(state, || Begin);
                }
                Begin if token == JsonToken::EndArray => {
                    return Ok(());
                }
                Begin => {
                    set_from_thunk(state, || Argument(<CapArgInterpT as ParserCommon<CapArgT>>::init(&str_interp)));
                    *arg_count = 1;
                    continue;
                }
                Argument(ref mut s) => {
                    <CapArgInterpT as JsonInterp<CapArgT>>::parse(&str_interp, s, token, &mut destination.as_mut().ok_or(Some(OOB::Reject))?.0)?;
                    set_from_thunk(state, || ValueSep);
                }
                ValueSep if token == JsonToken::ValueSeparator => {
                    match &destination.as_mut().ok_or(Some(OOB::Reject))?.0 {
                        Some(Some(sub_dest)) if *arg_count < MAX_ARG_COUNT => {
                            destination.as_mut().ok_or(Some(OOB::Reject))?.1[*arg_count-1] = sub_dest.len();
                            set_from_thunk(state, || Argument(<CapArgInterpT as ParserCommon<CapArgT>>::init(&str_interp)));
                            *arg_count+=1;
                        }
                        _ => {
                            set_from_thunk(destination, || None);
                            set_from_thunk(state, || FallbackValue(<DropInterp as ParserCommon<JsonAny>>::init(&DropInterp)));
                        }
                    }
                }
                ValueSep if token == JsonToken::EndArray => return Ok(()),
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
