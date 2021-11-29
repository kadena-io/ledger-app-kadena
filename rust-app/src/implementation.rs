use crate::crypto_helpers::{eddsa_sign, get_pkh, get_private_key, get_pubkey, get_pubkey_from_privkey, Hasher};
use crate::interface::*;
use crate::*;
use arrayvec::ArrayVec;
use core::fmt::Write;
use ledger_log::{info};
use ledger_parser_combinators::interp_parser::{
    Action, DefaultInterp, DropInterp, InterpParser, ObserveLengthedBytes, SubInterp, OOB, set_from_thunk
};
use ledger_parser_combinators::json::Json;
use ledger_parser_combinators::core_parsers::Alt;
use crate::ui::{write_scroller, final_accept_prompt};

use ledger_parser_combinators::define_json_struct_interp;
use ledger_parser_combinators::json::*;
use ledger_parser_combinators::json_interp::*;

pub type GetAddressImplT =
    Action<SubInterp<DefaultInterp>, fn(&ArrayVec<u32, 10>, &mut Option<ArrayVec<u8, 260>>) -> Option<()>>;


pub const GET_ADDRESS_IMPL: GetAddressImplT =
    Action(SubInterp(DefaultInterp), |path: &ArrayVec<u32, 10>, destination: &mut Option<ArrayVec<u8, 260>>| {
        let key = get_pubkey(&path).ok()?;

        let pkh = get_pkh(key);
        
        write_scroller("Provide Public Key", |w| Ok(write!(w, "{}", pkh)?))?;

        final_accept_prompt(&[])?;

        *destination=Some(ArrayVec::new());
        destination.as_mut()?.try_extend_from_slice(&key.W[1..key.W_len as usize]).ok()?;
        Some(())
    });

pub struct Preaction<S>(fn() -> Option<()>, S);

impl<A, S: JsonInterp<A>> JsonInterp<A> for Preaction<S> {
    type State = Option<<S as JsonInterp<A>>::State>;
    type Returning = <S as JsonInterp<A>>::Returning;

    fn init(&self) -> Self::State { None }
    #[inline(never)]
    fn parse<'a>(&self, state: &mut Self::State, token: JsonToken<'a>, destination: &mut Option<Self::Returning>) -> Result<(), Option<OOB>> {
        loop { break match state {
            None => {
                (self.0)().ok_or(Some(OOB::Reject))?;
                set_from_thunk(state, || Some(<S as JsonInterp<A>>::init(&self.1)));
                continue;
            }
            Some(ref mut s) => <S as JsonInterp<A>>::parse(&self.1, s, token, destination)
        }}
    }
}

pub type SignImplT = Action<
    (
        Action<
            ObserveLengthedBytes<
                Hasher,
                fn(&mut Hasher, &[u8]),
                Json<
                    KadenaCmdInterp<
                        DropInterp,
                        DropInterp,
                        SubInterp<
                            Preaction<SignerInterp<
                                DropInterp,
                                DropInterp,
                                DropInterp,
                                SubInterp<
                                    Action<
                                        KadenaCapabilityInterp<KadenaCapabilityArgsInterp, JsonStringAccumulate<14>>,
                                        fn(&KadenaCapability<Option<(Option<AltResult<ArrayVec<u8, 65>, ()>>, Option<AltResult<ArrayVec<u8, 65>, ()>>, Option<AltResult<ArrayVec<u8, 20>, ()>>)>, Option<ArrayVec<u8, 14>>>, &mut Option<()>) -> Option<()>,
                                    >,
                                >,
                            >>,
                        >,
                        DropInterp,
                        DropInterp,
                    >,
                >,
            >,
            fn(
                &(
                    Option< <DropInterp as JsonInterp<KadenaCmdSchema>>::Returning>,
                    Hasher,
                ),
                &mut Option<[u8; 64]>
            ) -> Option<()>,
        >,
        Action<
            SubInterp<DefaultInterp>,
            fn(&ArrayVec<u32, 10>, &mut Option<nanos_sdk::bindings::cx_ecfp_private_key_t>) -> Option<()>,
        >,
    ),
    fn(&(Option<[u8; 64]>, Option<nanos_sdk::bindings::cx_ecfp_private_key_t>), &mut Option<ArrayVec<u8, 260>>) -> Option<()>,
>;

pub const SIGN_IMPL: SignImplT = Action(
    (
        Action(
            // Calculate the hash of the transaction
            ObserveLengthedBytes(
                Hasher::new,
                Hasher::update,
                Json(KadenaCmdInterp {
                    field_nonce: DropInterp,
                    field_meta: DropInterp,
                    field_signers: SubInterp(Preaction(
                            || {
                                write_scroller("Required", |w| Ok(write!(w, "Signature")?))
                            },
                            SignerInterp {
                        field_scheme: DropInterp,
                        field_pub_key: DropInterp,
                        field_addr: DropInterp,
                        field_clist: SubInterp(Action(
                                KadenaCapabilityInterp {
                                    field_args: KadenaCapabilityArgsInterp,
                                    field_name: JsonStringAccumulate::<14>
                                },
                            |cap : &KadenaCapability<Option<<KadenaCapabilityArgsInterp as JsonInterp<JsonArray<JsonAny>>>::Returning>, Option<ArrayVec<u8, 14>>>, _| {
                                use core::str::from_utf8;
                                use AltResult::*;
                                let name = cap.field_name.as_ref()?.as_slice();
                                match cap.field_args.as_ref()? {
                                    (None, None, None) if name == b"coin.GAS" => {
                                        write_scroller("Paying Gas", |w| Ok(write!(w, " ")?))?;
                                    }
                                    _ if name == b"coin.GAS" => { return None; }
                                    (Some(First(acct)), None, None) if name == b"coin.ROTATE" => {
                                        write_scroller("Rotate for account", |w| Ok(write!(w, "{}", from_utf8(acct.as_slice())?)?))?;
                                    }
                                    _ if name == b"coin.ROTATE" => { return None; }
                                    (Some(First(sender)), Some(First(receiver)), Some(First(amount))) if name == b"coin.TRANSFER" => {
                                        write_scroller("Transfer", |w| Ok(write!(w, "{} from {} to {}", from_utf8(amount.as_slice())?, from_utf8(sender.as_slice())?, from_utf8(receiver.as_slice())?)?))?;
                                    }
                                    _ if name == b"coin.TRANSFER" => { return None; }
                                    _ => { return None; } // Change this to allow unknown capabilities.
                                }
                                Some(())
                            },
                        )),
                    })),
                    field_payload: DropInterp,
                    field_network_id: DropInterp,
                }),
            true),
            // Ask the user if they accept the transaction body's hash
            |(_, mut hash): &(_, Hasher), destination: &mut _| {
                let the_hash = hash.finalize();
                write_scroller("Transaction hash", |w| Ok(write!(w, "{}", the_hash)?))?;
                *destination=Some(the_hash.0.into());
                Some(())
            },
        ),
        Action(
            SubInterp(DefaultInterp),
            // And ask the user if this is the key the meant to sign with:
            |path: &ArrayVec<u32, 10>, destination: &mut _| {
                // Mutable because of some awkwardness with the C api.
                let mut privkey = get_private_key(&path).ok()?;
                let pubkey = get_pubkey_from_privkey(&mut privkey).ok()?;
                let pkh = get_pkh(pubkey);

                write_scroller("sign for address", |w| Ok(write!(w, "{}", pkh)?))?;
                *destination = Some(privkey);
                Some(())
            },
        ),
    ),
    |(hash, key): &(Option<[u8; 64]>, Option<_>), destination: &mut _| {
        final_accept_prompt(&[&"Sign Transaction?"])?;
        
        // By the time we get here, we've approved and just need to do the signature.
        let sig = eddsa_sign(&hash.as_ref()?[..], key.as_ref()?)?;
        let mut rv = ArrayVec::<u8, 260>::new();
        rv.try_extend_from_slice(&sig.0[..]).ok()?;
        *destination = Some(rv);
        Some(())
    },
);

pub struct KadenaCapabilityArgsInterp;

#[derive(Debug)]
pub enum KadenaCapabilityArgsInterpState {
    Start,
    Begin,
    FirstArgument(<Alt<JsonStringAccumulate<65>, DropInterp> as JsonInterp<Alt<JsonString, JsonAny>>>::State),
    FirstValueSep,
    SecondArgument(<Alt<JsonStringAccumulate<65>, DropInterp> as JsonInterp<Alt<JsonString, JsonAny>>>::State),
    SecondValueSep,
    ThirdArgument(<Alt<JsonStringAccumulate<20>, DropInterp> as JsonInterp<Alt<JsonNumber, JsonAny>>>::State),
    ThirdValueSep,
    FallbackValue(<DropInterp as JsonInterp<JsonAny>>::State),
    FallbackValueSep
}

impl JsonInterp<JsonArray<JsonAny>> for KadenaCapabilityArgsInterp {
    type State = (KadenaCapabilityArgsInterpState, Option<<DropInterp as JsonInterp<JsonAny>>::Returning>);
    type Returning = ( Option<AltResult<ArrayVec<u8, 65>, ()>>, Option<AltResult<ArrayVec<u8, 65>, ()>>, Option<AltResult<ArrayVec<u8, 20>, ()>> );
    fn init(&self) -> Self::State {
        (KadenaCapabilityArgsInterpState::Start, None)
    }
    #[inline(never)]
    fn parse<'a, 'b>(&self, (ref mut state, ref mut scratch): &'b mut Self::State, token: JsonToken<'a>, destination: &mut Option<Self::Returning>) -> Result<(), Option<OOB>> {
        let str_interp = Alt(JsonStringAccumulate::<65>, DropInterp);
        let dec_interp = Alt(JsonStringAccumulate::<20>, DropInterp);
        loop {
            use KadenaCapabilityArgsInterpState::*;
            match state {
                Start if token == JsonToken::BeginArray => {
                    set_from_thunk(destination, || Some((None, None, None)));
                    set_from_thunk(state, || Begin);
                }
                Begin if token == JsonToken::EndArray => {
                    return Ok(());
                }
                Begin => {
                    set_from_thunk(state, || FirstArgument(<Alt<JsonStringAccumulate<65>, DropInterp> as JsonInterp<Alt<JsonString, JsonAny>>>::init(&str_interp)));
                    continue;
                }
                FirstArgument(ref mut s) => {
                    <Alt<JsonStringAccumulate<65>, DropInterp> as JsonInterp<Alt<JsonString, JsonAny>>>::parse(&str_interp, s, token, &mut destination.as_mut().ok_or(Some(OOB::Reject))?.0)?;
                    set_from_thunk(state, || FirstValueSep);
                }
                FirstValueSep if token == JsonToken::ValueSeparator => {
                    set_from_thunk(state, || SecondArgument(<Alt<JsonStringAccumulate<65>, DropInterp> as JsonInterp<Alt<JsonString, JsonAny>>>::init(&str_interp)));
                }
                FirstValueSep if token == JsonToken::EndArray => return Ok(()),
                SecondArgument(ref mut s) => {
                    <Alt<JsonStringAccumulate<65>, DropInterp> as JsonInterp<Alt<JsonString, JsonAny>>>::parse(&str_interp, s, token, &mut destination.as_mut().ok_or(Some(OOB::Reject))?.1)?;
                    set_from_thunk(state, || SecondValueSep);
                }
                SecondValueSep if token == JsonToken::ValueSeparator => {
                    set_from_thunk(state, || ThirdArgument(<Alt<JsonStringAccumulate<20>, DropInterp> as JsonInterp<Alt<JsonNumber, JsonAny>>>::init(&dec_interp)));
                }
                SecondValueSep if token == JsonToken::EndArray => return Ok(()),
                ThirdArgument(ref mut s) => {
                    <Alt<JsonStringAccumulate<20>, DropInterp> as JsonInterp<Alt<JsonNumber, JsonAny>>>::parse(&dec_interp, s, token, &mut destination.as_mut().ok_or(Some(OOB::Reject))?.2)?;
                    set_from_thunk(state, || FirstValueSep);
                }
                ThirdValueSep if token == JsonToken::EndArray => {
                    return Ok(());
                }
                ThirdValueSep if token == JsonToken::ValueSeparator => {
                    set_from_thunk(destination, || None);
                    set_from_thunk(state, || FallbackValue(<DropInterp as JsonInterp<JsonAny>>::init(&DropInterp)));
                }
                FallbackValue(ref mut s) => {
                    <DropInterp as JsonInterp<JsonAny>>::parse(&DropInterp, s, token, scratch)?;
                    set_from_thunk(state, || FallbackValueSep);
                }
                FallbackValueSep if token == JsonToken::ValueSeparator => {
                    set_from_thunk(state, || FallbackValue(<DropInterp as JsonInterp<JsonAny>>::init(&DropInterp)));
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
    GetAddressState(<GetAddressImplT as InterpParser<Bip32Key>>::State),
    SignState(<SignImplT as InterpParser<SignParameters>>::State),
}

pub fn reset_parsers_state(state: &mut ParsersState) {
    *state = ParsersState::NoState;
}

meta_definition!{}
kadena_capability_definition!{}
signer_definition!{}
kadena_cmd_definition!{}

/*
define_json_struct_interp! { Meta 16 {
    chainId: JsonString,
    sender: JsonString,
    gasLimit: JsonNumber,
    gasPrice: JsonNumber,
    ttl: JsonNumber,
    creationTime: JsonNumber
}}
define_json_struct_interp! { KadenaCapability 4 {
    args: JsonArray<JsonAny>,
    name: JsonString
}}
define_json_struct_interp! { Signer 16 {
    scheme: JsonString,
    pubKey: JsonString,
    addr: JsonString,
    clist: JsonArray<JsonString>
}}
define_json_struct_interp! { KadenaCmd 16 {
  nonce: JsonString,
  meta: MetaSchema,
  signers: JsonArray<SignerSchema>,
  payload: JsonAny,
  networkId: JsonAny
}}
*/

#[inline(never)]
pub fn get_get_address_state(
    s: &mut ParsersState,
) -> &mut <GetAddressImplT as InterpParser<Bip32Key>>::State {
    match s {
        ParsersState::GetAddressState(_) => {}
        _ => {
            info!("Non-same state found; initializing state.");
            *s = ParsersState::GetAddressState(<GetAddressImplT as InterpParser<Bip32Key>>::init(
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
) -> &mut <SignImplT as InterpParser<SignParameters>>::State {
    match s {
        ParsersState::SignState(_) => {}
        _ => {
            info!("Non-same state found; initializing state.");
            *s = ParsersState::SignState(<SignImplT as InterpParser<SignParameters>>::init(
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
