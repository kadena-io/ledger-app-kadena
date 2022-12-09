#![allow(clippy::type_complexity)]
use crate::interface::*;
use crate::*;
use arrayvec::ArrayString;
use arrayvec::ArrayVec;
use core::fmt::Write;
use ledger_crypto_helpers::common::try_option;
use ledger_crypto_helpers::eddsa::{
    ed25519_public_key_bytes, eddsa_sign, eddsa_sign_int, with_public_keys, with_public_keys_int,
    Ed25519RawPubKeyAddress,
};
use ledger_crypto_helpers::hasher::{Blake2b, Hash, Hasher};
use ledger_log::info;
use ledger_parser_combinators::core_parsers::Alt;
use ledger_parser_combinators::interp_parser::{
    set_from_thunk, Action, DefaultInterp, DropInterp, InterpParser, ObserveLengthedBytes,
    SubInterp, OOB,
};
use ledger_parser_combinators::json::Json;
use ledger_prompts_ui::{final_accept_prompt, mk_prompt_write, PromptWrite, ScrollerError};

use core::convert::TryFrom;
use core::ops::Deref;
use core::str::from_utf8;
use ledger_parser_combinators::define_json_struct_interp;
use ledger_parser_combinators::interp_parser::*;
use ledger_parser_combinators::json::*;
use ledger_parser_combinators::json_interp::*;
use zeroize::Zeroizing;

use nanos_sdk::ecc::{ECPrivateKey, Ed25519};

#[allow(clippy::upper_case_acronyms)]
type PKH = Ed25519RawPubKeyAddress;

// A couple type ascription functions to help the compiler along.
const fn mkfn<A, B>(q: fn(&A, &mut B) -> Option<()>) -> fn(&A, &mut B) -> Option<()> {
    q
}
const fn mkmvfn<A, B, C>(q: fn(A, &mut B) -> Option<C>) -> fn(A, &mut B) -> Option<C> {
    q
}
const fn mkfnc<A, B, C>(q: fn(&A, &mut B, C) -> Option<()>) -> fn(&A, &mut B, C) -> Option<()> {
    q
}
const fn mkvfn<A>(
    q: fn(&A, &mut Option<()>) -> Option<()>,
) -> fn(&A, &mut Option<()>) -> Option<()> {
    q
}

#[cfg(not(target_os = "nanos"))]
#[inline(never)]
fn scroller<F: for<'b> Fn(&mut PromptWrite<'b, 16>) -> Result<(), ScrollerError>>(
    title: &str,
    prompt_function: F,
) -> Option<()> {
    ledger_prompts_ui::write_scroller_three_rows(title, prompt_function)
}

#[cfg(target_os = "nanos")]
#[inline(never)]
fn scroller<F: for<'b> Fn(&mut PromptWrite<'b, 16>) -> Result<(), ScrollerError>>(
    title: &str,
    prompt_function: F,
) -> Option<()> {
    ledger_prompts_ui::write_scroller(title, prompt_function)
}

fn mkstr(v: Option<&[u8]>) -> Result<&str, ScrollerError> {
    Ok(from_utf8(v.ok_or(ScrollerError)?)?)
}

pub type GetAddressImplT = impl InterpParser<Bip32Key, Returning = ArrayVec<u8, 128_usize>>;
pub const GET_ADDRESS_IMPL: GetAddressImplT = Action(
    SubInterp(DefaultInterp),
    mkfn(
        |path: &ArrayVec<u32, 10>, destination: &mut Option<ArrayVec<u8, 128>>| {
            with_public_keys(path, |key: &_, pkh: &PKH| {
                try_option(|| -> Option<()> {
                    scroller("Provide Public Key", |w| Ok(write!(w, "{}", pkh)?))?;

                    final_accept_prompt(&[])?;

                    *destination = Some(ArrayVec::new());
                    // key without y parity
                    let key_x = ed25519_public_key_bytes(key);
                    destination
                        .as_mut()?
                        .try_push(u8::try_from(key_x.len()).ok()?)
                        .ok()?;
                    destination.as_mut()?.try_extend_from_slice(key_x).ok()?;
                    Some(())
                }())
            })
            .ok()
        },
    ),
);

pub type SignImplT = impl InterpParser<SignParameters, Returning = ArrayVec<u8, 128_usize>>;

#[derive(PartialEq, Debug)]
enum CapabilityCoverage {
    Full,
    HasFallback,
    NoCaps,
}

impl Summable<CapabilityCoverage> for CapabilityCoverage {
    fn zero() -> Self {
        CapabilityCoverage::Full
    }
    fn add_and_set(&mut self, other: &CapabilityCoverage) {
        match other {
            CapabilityCoverage::Full => {}
            CapabilityCoverage::HasFallback => {
                if *self == CapabilityCoverage::Full {
                    *self = CapabilityCoverage::HasFallback
                }
            }
            CapabilityCoverage::NoCaps => *self = CapabilityCoverage::NoCaps,
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
            mkfn(|(_, mut hasher): &(_, Blake2b), destination: &mut Option<Zeroizing<Hash<32>>>| {
                let the_hash = hasher.finalize();
                scroller("Transaction hash", |w| Ok(write!(w, "{}", the_hash.deref())?))?;
                *destination=Some(the_hash);
                Some(())
            }),
        ),
        MoveAction(
            SubInterp(DefaultInterp),
            // And ask the user if this is the key the meant to sign with:
            mkmvfn(|path: ArrayVec<u32, 10>, destination: &mut Option<ArrayVec<u32, 10>>| {
                with_public_keys(&path, |_, pkh: &PKH| { try_option(|| -> Option<()> {
                    scroller("Sign for Address", |w| Ok(write!(w, "{pkh}")?))?;
                    Some(())
                }())}).ok()?;
                *destination = Some(path);
                Some(())
            }),
        ),
    ),
    mkfn(|(hash, path): &(Option<Zeroizing<Hash<32>>>, Option<ArrayVec<u32, 10>>), destination: &mut _| {
        #[allow(clippy::needless_borrow)] // Needed for nanos
        final_accept_prompt(&[&"Sign Transaction?"])?;

        // By the time we get here, we've approved and just need to do the signature.
        let sig = eddsa_sign(path.as_ref()?, &hash.as_ref()?.0[..]).ok()?;
        let mut rv = ArrayVec::<u8, 128>::new();
        rv.try_extend_from_slice(&sig.0[..]).ok()?;
        *destination = Some(rv);
        Some(())
    }),
);

const META_ACTION: Action<
    Alt<
        MetaInterp<
            Action<
                JsonStringAccumulate<32_usize>,
                fn(&ArrayVec<u8, 32_usize>, &mut Option<()>) -> Option<()>,
            >,
            DropInterp,
            JsonStringAccumulate<100_usize>,
            JsonStringAccumulate<100_usize>,
            DropInterp,
            DropInterp,
        >,
        DropInterp,
    >,
    fn(
        &AltResult<
            Meta<
                Option<()>,
                Option<()>,
                Option<ArrayVec<u8, 100_usize>>,
                Option<ArrayVec<u8, 100_usize>>,
                Option<()>,
                Option<()>,
            >,
            (),
        >,
        &mut Option<()>,
    ) -> Option<()>,
> = Action(
    Alt(
        MetaInterp {
            field_chain_id: Action(
                JsonStringAccumulate::<32>,
                mkvfn(|chain: &ArrayVec<u8, 32>, _| -> Option<()> {
                    scroller("On Chain", |w| {
                        Ok(write!(w, "{}", from_utf8(chain.as_slice())?)?)
                    })
                }),
            ),
            field_sender: DropInterp,
            field_gas_limit: JsonStringAccumulate::<100>,
            field_gas_price: JsonStringAccumulate::<100>,
            field_ttl: DropInterp,
            field_creation_time: DropInterp,
        },
        DropInterp,
    ),
    mkvfn(|v, _| match v {
        AltResult::First(Meta {
            ref field_gas_limit,
            ref field_gas_price,
            ..
        }) => scroller("Using Gas", |w| {
            Ok(write!(
                w,
                "at most {} at price {}",
                from_utf8(field_gas_limit.as_ref().ok_or(ScrollerError)?.as_slice())?,
                from_utf8(field_gas_price.as_ref().ok_or(ScrollerError)?.as_slice())?
            )?)
        }),
        _ => scroller("CAUTION", |w| {
            Ok(write!(w, "'meta' field of transaction not recognized")?)
        }),
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
        if let CapCountData::CapCount {
            total_caps,
            total_transfers,
            total_unknown,
        } = self
        {
            *total_caps += 1;
            match other {
                CapCountData::IsTransfer => *total_transfers += 1,
                CapCountData::IsUnknownCap => *total_unknown += 1,
                _ => {}
            }
        }
    }
    fn zero() -> Self {
        CapCountData::CapCount {
            total_caps: 0,
            total_transfers: 0,
            total_unknown: 0,
        }
    }
}

const CLIST_ACTION: SubInterpMFold<
    Action<
        KadenaCapabilityInterp<KadenaCapabilityArgsInterp, JsonStringAccumulate<32>>,
        fn(
            &KadenaCapability<
                Option<<KadenaCapabilityArgsInterp as ParserCommon<JsonArray<JsonAny>>>::Returning>,
                Option<ArrayVec<u8, 32>>,
            >,
            &mut Option<(CapCountData, bool)>,
            (CapCountData, All),
        ) -> Option<()>,
    >,
    (CapCountData, All),
> = SubInterpMFold::new(Action(
    KadenaCapabilityInterp {
        field_args: KadenaCapabilityArgsInterp,
        field_name: JsonStringAccumulate::<32>,
    },
    mkfnc(
        |cap: &KadenaCapability<
            Option<<KadenaCapabilityArgsInterp as ParserCommon<JsonArray<JsonAny>>>::Returning>,
            Option<ArrayVec<u8, 32>>,
        >,
         destination: &mut Option<(CapCountData, bool)>,
         v: (CapCountData, All)| {
            let name = cap.field_name.as_ref()?.as_slice();
            let name_utf8 = from_utf8(name).ok()?;
            let mk_unknown_cap_title = || -> Option<_> {
                let count = match v.0 {
                    CapCountData::CapCount { total_unknown, .. } => total_unknown,
                    _ => 0,
                };
                let mut buffer: ArrayString<22> = ArrayString::new();
                write!(
                    mk_prompt_write(&mut buffer),
                    "Unknown Capability {}",
                    count + 1
                )
                .ok()?;
                Some(buffer)
            };
            let mk_transfer_title = || -> Option<_> {
                let count = match v.0 {
                    CapCountData::CapCount {
                        total_transfers, ..
                    } => total_transfers,
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
                        scroller(&mk_unknown_cap_title()?, |w| {
                            Ok(write!(w, "name: {}, no args", name_utf8)?)
                        })?;
                    }
                }
                Some((Some(Some(args)), arg_lengths)) => {
                    if arg_lengths[3] != 0 {
                        scroller(&mk_unknown_cap_title()?, |w| {
                            Ok(write!(
                                w,
                                "name: {}, arg 1: {}, arg 2: {}, arg 3: {}, arg 4: {}, arg 5: {}",
                                name_utf8,
                                mkstr(args.as_slice().get(0..arg_lengths[0]))?,
                                mkstr(args.as_slice().get(arg_lengths[0]..arg_lengths[1]))?,
                                mkstr(args.as_slice().get(arg_lengths[1]..arg_lengths[2]))?,
                                mkstr(args.as_slice().get(arg_lengths[2]..arg_lengths[3]))?,
                                mkstr(args.as_slice().get(arg_lengths[3]..args.len()))?
                            )?)
                        })?;
                    } else if arg_lengths[2] != 0 {
                        if name == b"coin.TRANSFER_XCHAIN" {
                            scroller(&mk_transfer_title()?, |w| {
                                Ok(write!(
                                    w,
                                    "Cross-chain {} from {} to {} to chain {}",
                                    mkstr(args.as_slice().get(arg_lengths[1]..arg_lengths[2]))?,
                                    mkstr(args.as_slice().get(0..arg_lengths[0]))?,
                                    mkstr(args.as_slice().get(arg_lengths[0]..arg_lengths[1]))?,
                                    mkstr(args.as_slice().get(arg_lengths[2]..args.len()))?
                                )?)
                            })?;
                            *destination = Some((CapCountData::IsTransfer, true));
                        } else {
                            scroller(&mk_unknown_cap_title()?, |w| {
                                Ok(write!(
                                    w,
                                    "name: {}, arg 1: {}, arg 2: {}, arg 3: {}, arg 4: {}",
                                    name_utf8,
                                    mkstr(args.as_slice().get(0..arg_lengths[0]))?,
                                    mkstr(args.as_slice().get(arg_lengths[0]..arg_lengths[1]))?,
                                    mkstr(args.as_slice().get(arg_lengths[1]..arg_lengths[2]))?,
                                    mkstr(args.as_slice().get(arg_lengths[2]..args.len()))?
                                )?)
                            })?;
                        }
                    } else if arg_lengths[1] != 0 {
                        if name == b"coin.TRANSFER" {
                            scroller(&mk_transfer_title()?, |w| {
                                Ok(write!(
                                    w,
                                    "{} from {} to {}",
                                    mkstr(args.as_slice().get(arg_lengths[1]..args.len()))?,
                                    mkstr(args.as_slice().get(0..arg_lengths[0]))?,
                                    mkstr(args.as_slice().get(arg_lengths[0]..arg_lengths[1]))?
                                )?)
                            })?;
                            *destination = Some((CapCountData::IsTransfer, true));
                        } else {
                            scroller(&mk_unknown_cap_title()?, |w| {
                                Ok(write!(
                                    w,
                                    "name: {}, arg 1: {}, arg 2: {}, arg 3: {}",
                                    name_utf8,
                                    mkstr(args.as_slice().get(0..arg_lengths[0]))?,
                                    mkstr(args.as_slice().get(arg_lengths[0]..arg_lengths[1]))?,
                                    mkstr(args.as_slice().get(arg_lengths[1]..args.len()))?
                                )?)
                            })?;
                        }
                    } else if arg_lengths[0] != 0 {
                        scroller(&mk_unknown_cap_title()?, |w| {
                            Ok(write!(
                                w,
                                "name: {}, arg 1: {}, arg 2: {}",
                                name_utf8,
                                mkstr(args.as_slice().get(0..arg_lengths[0]))?,
                                mkstr(args.as_slice().get(arg_lengths[0]..args.len()))?
                            )?)
                        })?;
                    } else if name == b"coin.ROTATE" {
                        scroller("Rotate for account", |w| {
                            Ok(write!(w, "{}", from_utf8(args.as_slice())?)?)
                        })?;
                        *destination = Some((Summable::zero(), true));
                    } else {
                        scroller(&mk_unknown_cap_title()?, |w| {
                            Ok(write!(
                                w,
                                "name: {}, arg 1: {}",
                                name_utf8,
                                from_utf8(args.as_slice())?
                            )?)
                        })?;
                    }
                }
                _ => {
                    scroller(&mk_unknown_cap_title()?, |w| {
                        Ok(write!(
                            w,
                            "name: {}, args cannot be displayed on Ledger",
                            name_utf8
                        )?)
                    })?;
                    set_from_thunk(destination, || Some((CapCountData::IsUnknownCap, false)));
                    // Fallback case
                }
            }
            Some(())
        },
    ),
));

pub type SignHashImplT = impl InterpParser<SignHashParameters, Returning = ArrayVec<u8, 128_usize>>;

pub static SIGN_HASH_IMPL: SignHashImplT = Action(
    Preaction(
        || -> Option<()> {
            scroller("WARNING", |w| {
                Ok(write!(w, "Blind Signing a Transaction Hash is a very unusual operation. Do not continue unless you know what you are doing")?)
            })
        },
        (
            Action(
                SubInterp(DefaultInterp),
                // Ask the user if they accept the transaction body's hash
                mkfn(|hash_val: &[u8; 32], destination: &mut Option<[u8; 32]>| {
                    let the_hash = Hash(*hash_val);
                    scroller("Transaction hash", |w| Ok(write!(w, "{}", the_hash)?))?;
                    *destination = Some(the_hash.0);
                    Some(())
                }),
            ),
            MoveAction(
                SubInterp(DefaultInterp),
                // And ask the user if this is the key the meant to sign with:
                mkmvfn(
                    |path: ArrayVec<u32, 10>, destination: &mut Option<ArrayVec<u32, 10>>| {
                        with_public_keys(&path, |_, pkh: &PKH| {
                            try_option(|| -> Option<()> {
                                scroller("Sign for Address", |w| Ok(write!(w, "{}", pkh)?))?;
                                Some(())
                            }())
                        })
                        .ok()?;
                        *destination = Some(path);
                        Some(())
                    },
                ),
            ),
        ),
    ),
    mkfn(
        |(hash, path): &(Option<[u8; 32]>, Option<ArrayVec<u32, 10>>), destination: &mut _| {
            #[allow(clippy::needless_borrow)] // Needed for nanos
            final_accept_prompt(&[&"Sign Transaction Hash?"])?;

            // By the time we get here, we've approved and just need to do the signature.
            let sig = eddsa_sign(path.as_ref()?, &hash.as_ref()?[..]).ok()?;
            let mut rv = ArrayVec::<u8, 128>::new();
            rv.try_extend_from_slice(&sig.0[..]).ok()?;
            *destination = Some(rv);
            Some(())
        },
    ),
);

pub struct KadenaCapabilityArgsInterp;

// The Caps list is parsed and the args are stored in a single common ArrayVec of this size.
// (This may be as large as the stack allows)
#[cfg(target_os = "nanos")]
const ARG_ARRAY_SIZE: usize = 184;
#[cfg(not(target_os = "nanos"))]
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
    FallbackValueSep,
}

impl ParserCommon<JsonArray<JsonAny>> for KadenaCapabilityArgsInterp {
    type State = (
        KadenaCapabilityArgsInterpState,
        Option<<DropInterp as ParserCommon<JsonAny>>::Returning>,
        usize,
    );
    type Returning = (
        Option<<CapArgInterpT as ParserCommon<CapArgT>>::Returning>,
        ArgListIndicesT,
    );
    fn init(&self) -> Self::State {
        (KadenaCapabilityArgsInterpState::Start, None, 0)
    }
}
impl JsonInterp<JsonArray<JsonAny>> for KadenaCapabilityArgsInterp {
    #[inline(never)]
    fn parse<'a, 'b>(
        &self,
        (ref mut state, ref mut scratch, ref mut arg_count): &'b mut Self::State,
        token: JsonToken<'a>,
        destination: &mut Option<Self::Returning>,
    ) -> Result<(), Option<OOB>> {
        let str_interp = OrDropAny(JsonStringAccumulate::<ARG_ARRAY_SIZE>);
        loop {
            use KadenaCapabilityArgsInterpState::*;
            match state {
                Start if token == JsonToken::BeginArray => {
                    set_from_thunk(destination, || Some((None, [0, 0, 0, 0])));
                    set_from_thunk(state, || Begin);
                }
                Begin if token == JsonToken::EndArray => {
                    return Ok(());
                }
                Begin => {
                    set_from_thunk(state, || {
                        Argument(<CapArgInterpT as ParserCommon<CapArgT>>::init(&str_interp))
                    });
                    *arg_count = 1;
                    continue;
                }
                Argument(ref mut s) => {
                    <CapArgInterpT as JsonInterp<CapArgT>>::parse(
                        &str_interp,
                        s,
                        token,
                        &mut destination.as_mut().ok_or(Some(OOB::Reject))?.0,
                    )?;
                    set_from_thunk(state, || ValueSep);
                }
                ValueSep if token == JsonToken::ValueSeparator => {
                    match &destination.as_mut().ok_or(Some(OOB::Reject))?.0 {
                        Some(Some(sub_dest)) if *arg_count < MAX_ARG_COUNT => {
                            destination.as_mut().ok_or(Some(OOB::Reject))?.1[*arg_count - 1] =
                                sub_dest.len();
                            set_from_thunk(state, || {
                                Argument(<CapArgInterpT as ParserCommon<CapArgT>>::init(
                                    &str_interp,
                                ))
                            });
                            *arg_count += 1;
                        }
                        _ => {
                            set_from_thunk(destination, || None);
                            set_from_thunk(state, || {
                                FallbackValue(<DropInterp as ParserCommon<JsonAny>>::init(
                                    &DropInterp,
                                ))
                            });
                        }
                    }
                }
                ValueSep if token == JsonToken::EndArray => return Ok(()),
                FallbackValue(ref mut s) => {
                    <DropInterp as JsonInterp<JsonAny>>::parse(&DropInterp, s, token, scratch)?;
                    set_from_thunk(state, || FallbackValueSep);
                }
                FallbackValueSep if token == JsonToken::ValueSeparator => {
                    set_from_thunk(state, || {
                        FallbackValue(<DropInterp as ParserCommon<JsonAny>>::init(&DropInterp))
                    });
                }
                FallbackValueSep if token == JsonToken::EndArray => {
                    return Ok(());
                }
                _ => return Err(Some(OOB::Reject)),
            }
            break Err(None);
        }
    }
}

// ----------------------------------------------------------------------------------

// tx_type
// 0 -> Transfer
// 1 -> Transfer create
// 2 -> Transfer cross-chain

#[allow(clippy::too_many_arguments)]
#[inline(never)]
fn handle_tx_param_1(
    pkh_str: &ArrayString<64>,
    hasher: &mut Blake2b,
    tx_type: u8,
    recipient: &ArrayVec<u8, PARAM_RECIPIENT_SIZE>,
    recipient_chain: &ArrayVec<u8, PARAM_RECIPIENT_CHAIN_SIZE>,
    amount: &ArrayVec<u8, PARAM_AMOUNT_SIZE>,
    network: &ArrayVec<u8, PARAM_NETWORK_SIZE>,
    namespace: &ArrayVec<u8, PARAM_NAMESPACE_SIZE>,
    mod_name: &ArrayVec<u8, PARAM_MOD_NAME_SIZE>,
) -> Option<()> {
    let amount_str = from_utf8(amount).ok()?;
    let recipient_str = from_utf8(recipient).ok()?;
    let recipient_chain_str = from_utf8(recipient_chain).ok()?;
    let network_str = from_utf8(network).ok()?;
    let namespace_str = from_utf8(namespace).ok()?;
    let mod_name_str = from_utf8(mod_name).ok()?;
    if !namespace_str.is_empty() && mod_name_str.is_empty() {
        return None;
    }

    // recipient_str should be hex
    if recipient_str.len() != 64 {
        return None;
    }
    for (_, c) in recipient_str.char_indices() {
        if !matches!(c, '0'..='9' | 'A'..='F' | 'a'..='f') {
            return None;
        }
    }
    check_positive_integer(recipient_chain_str)?;
    check_decimal(amount_str)?;

    let coin_or_namespace = |hasher: &mut Blake2b| -> Option<()> {
        if namespace_str.is_empty() {
            write!(hasher, "coin").ok()?;
        } else {
            write!(hasher, "{}.{}", namespace_str, mod_name_str).ok()?;
        }
        Some(())
    };

    // curly braces are escaped like '{{', '}}'
    // The JSON struct begins here, and ends in handle_tx_params_2
    write!(hasher, "{{").ok()?;
    write!(hasher, "\"networkId\":\"{}\"", network_str).ok()?;
    match tx_type {
        0 => {
            write!(
                hasher,
                ",\"payload\":{{\"exec\":{{\"data\":{{}},\"code\":\"("
            )
            .ok()?;
            coin_or_namespace(hasher)?;
            write!(hasher, ".transfer").ok()?;
            write!(hasher, " \\\"k:{}\\\"", pkh_str).ok()?;
            write!(hasher, " \\\"k:{}\\\"", recipient_str).ok()?;
            write!(hasher, " {})\"}}}}", amount_str).ok()?;
            write!(hasher, ",\"signers\":[{{\"pubKey\":").ok()?;
            write!(hasher, "\"{}\"", pkh_str).ok()?;
            write!(hasher, ",\"clist\":[{{\"args\":[").ok()?;
            write!(hasher, "\"k:{}\",", pkh_str).ok()?;
            write!(hasher, "\"k:{}\",", recipient_str).ok()?;
            write!(hasher, "{}]", amount_str).ok()?;
            write!(hasher, ",\"name\":\"").ok()?;
            coin_or_namespace(hasher)?;
            write!(
                hasher,
                ".TRANSFER\"}},{{\"args\":[],\"name\":\"coin.GAS\"}}]}}]"
            )
            .ok()?;
        }
        1 => {
            write!(hasher, ",\"payload\":{{\"exec\":{{\"data\":{{").ok()?;
            write!(hasher, "\"ks\":{{\"pred\":\"keys-all\",\"keys\":[").ok()?;
            write!(hasher, "\"{}\"]}}}}", recipient_str).ok()?;
            write!(hasher, ",\"code\":\"(").ok()?;
            coin_or_namespace(hasher)?;
            write!(hasher, ".transfer-create").ok()?;
            write!(hasher, " \\\"k:{}\\\"", pkh_str).ok()?;
            write!(hasher, " \\\"k:{}\\\"", recipient_str).ok()?;
            write!(hasher, " (read-keyset \\\"ks\\\")").ok()?;
            write!(hasher, " {})\"}}}}", amount_str).ok()?;
            write!(hasher, ",\"signers\":[{{\"pubKey\":").ok()?;
            write!(hasher, "\"{}\"", pkh_str).ok()?;
            write!(hasher, ",\"clist\":[{{\"args\":[").ok()?;
            write!(hasher, "\"k:{}\",", pkh_str).ok()?;
            write!(hasher, "\"k:{}\",", recipient_str).ok()?;
            write!(hasher, "{}]", amount_str).ok()?;
            write!(hasher, ",\"name\":\"").ok()?;
            coin_or_namespace(hasher)?;
            write!(
                hasher,
                ".TRANSFER\"}},{{\"args\":[],\"name\":\"coin.GAS\"}}]}}]"
            )
            .ok()?;
        }
        2 => {
            write!(hasher, ",\"payload\":{{\"exec\":{{\"data\":{{").ok()?;
            write!(hasher, "\"ks\":{{\"pred\":\"keys-all\",\"keys\":[").ok()?;
            write!(hasher, "\"{}\"]}}}}", recipient_str).ok()?;
            write!(hasher, ",\"code\":\"(").ok()?;
            coin_or_namespace(hasher)?;
            write!(hasher, ".transfer-crosschain").ok()?;
            write!(hasher, " \\\"k:{}\\\"", pkh_str).ok()?;
            write!(hasher, " \\\"k:{}\\\"", recipient_str).ok()?;
            write!(hasher, " (read-keyset \\\"ks\\\")").ok()?;
            write!(hasher, " \\\"{}\\\"", recipient_chain_str).ok()?;
            write!(hasher, " {})\"}}}}", amount_str).ok()?;
            write!(hasher, ",\"signers\":[{{\"pubKey\":").ok()?;
            write!(hasher, "\"{}\"", pkh_str).ok()?;
            write!(hasher, ",\"clist\":[{{\"args\":[").ok()?;
            write!(hasher, "\"k:{}\",", pkh_str).ok()?;
            write!(hasher, "\"k:{}\",", recipient_str).ok()?;
            write!(hasher, "{},", amount_str).ok()?;
            write!(hasher, "\"{}\"]", recipient_chain_str).ok()?;
            write!(hasher, ",\"name\":\"").ok()?;
            coin_or_namespace(hasher)?;
            write!(
                hasher,
                ".TRANSFER_XCHAIN\"}},{{\"args\":[],\"name\":\"coin.GAS\"}}]}}]"
            )
            .ok()?;
        }
        _ => {}
    }

    if namespace_str.is_empty() {
        scroller("Token:", |w| Ok(write!(w, "KDA")?))?;
    } else {
        scroller("Token:", |w| {
            Ok(write!(w, "{}.{}", namespace_str, mod_name_str)?)
        })?;
    }

    match tx_type {
        0 | 1 => {
            scroller("Transfer", |w| {
                Ok(write!(
                    w,
                    "{} from k:{} to k:{} on network {}",
                    amount_str, pkh_str, recipient_str, network_str
                )?)
            })?;
        }
        2 => {
            scroller("Transfer", |w| {
                Ok(write!(
                    w,
                    "Cross-chain {} from k:{} to k:{} to chain {} on network {}",
                    amount_str, pkh_str, recipient_str, recipient_chain_str, network_str
                )?)
            })?;
        }
        _ => {}
    }
    Some(())
}

#[allow(clippy::too_many_arguments)]
fn handle_tx_params_2(
    pkh_str: &ArrayString<64>,
    hasher: &mut Blake2b,
    gas_price: &ArrayVec<u8, PARAM_GAS_PRICE_SIZE>,
    gas_limit: &ArrayVec<u8, PARAM_GAS_LIMIT_SIZE>,
    creation_time: &ArrayVec<u8, PARAM_CREATION_TIME_SIZE>,
    chain_id: &ArrayVec<u8, PARAM_CHAIN_SIZE>,
    nonce: &ArrayVec<u8, PARAM_NOONCE_SIZE>,
    ttl: &ArrayVec<u8, PARAM_TTL_SIZE>,
) -> Option<()> {
    let gas_price_str = from_utf8(gas_price).ok()?;
    let gas_limit_str = from_utf8(gas_limit).ok()?;
    let chain_id_str = from_utf8(chain_id).ok()?;
    let ttl_str = from_utf8(ttl).ok()?;
    let creation_time_str = from_utf8(creation_time).ok()?;
    {
        // gas_price_str should be positive integer, decimal or exponential value
        if gas_price_str.is_empty() {
            return None;
        }
        let mut decimal = false;
        let mut exp = false;
        let mut should_be_minus = false;
        for (_, c) in gas_price_str.char_indices() {
            if should_be_minus {
                if c == '-' {
                    should_be_minus = false;
                    continue;
                } else {
                    return None;
                }
            }
            if !matches!(c, '0'..='9') {
                if c == '.' && !decimal {
                    decimal = true;
                    continue;
                }
                if c == 'e' && !exp && decimal {
                    exp = true;
                    should_be_minus = true;
                    continue;
                }
                return None;
            }
        }
    }
    check_positive_integer(gas_limit_str)?;
    check_positive_integer(chain_id_str)?;
    check_positive_integer(creation_time_str)?;
    check_decimal(ttl_str)?;
    write!(hasher, ",\"meta\":{{").ok()?;
    write!(hasher, "\"creationTime\":{}", creation_time_str).ok()?;
    write!(hasher, ",\"ttl\":{}", ttl_str).ok()?;
    write!(hasher, ",\"gasLimit\":{}", gas_limit_str).ok()?;
    write!(hasher, ",\"chainId\":\"{}\"", chain_id_str).ok()?;
    write!(hasher, ",\"gasPrice\":{}", gas_price_str).ok()?;
    write!(hasher, ",\"sender\":\"k:{}\"", pkh_str).ok()?;
    write!(hasher, "}}").ok()?;
    write!(hasher, ",\"nonce\":\"{}\"", from_utf8(nonce).ok()?).ok()?;
    // The JSON struct ends here
    write!(hasher, "}}").ok()?;

    scroller("Paying Gas", |w| {
        Ok(write!(
            w,
            "at most {} at price {}",
            from_utf8(gas_limit)?,
            from_utf8(gas_price)?
        )?)
    })?;
    Some(())
}

fn check_decimal(s: &str) -> Option<()> {
    if s.is_empty() {
        return None;
    }
    let mut decimal = false;
    for (_, c) in s.char_indices() {
        if !matches!(c, '0'..='9') {
            if c == '.' && !decimal {
                decimal = true;
                continue;
            }
            return None;
        }
    }
    Some(())
}

fn check_positive_integer(s: &str) -> Option<()> {
    if s.is_empty() {
        return None;
    }
    for (_, c) in s.char_indices() {
        if !matches!(c, '0'..='9') {
            return None;
        }
    }
    Some(())
}

// Define some useful type aliases
pub type OptionByteVec<const N: usize> = Option<ArrayVec<u8, N>>;
type SubDefT = SubInterp<DefaultInterp>;
const SUB_DEF: SubDefT = SubInterp(DefaultInterp);

// This is kept in State to avoid passing it in-between the sub-parsers
// via parameters / DynBind
type HasherAndPrivKey = (Blake2b, ECPrivateKey<32, 'E'>);

pub type PathParserT = impl InterpParser<Bip32Key, Returning = HasherAndPrivKey>;

const PATH_PARSER: PathParserT = MoveAction(
    SUB_DEF,
    mkmvfn(
        |path: <SubDefT as ParserCommon<Bip32Key>>::Returning,
         destination: &mut Option<HasherAndPrivKey>| {
            set_from_thunk(destination, || {
                Some((Hasher::new(), Ed25519::from_bip32(&path)))
            });
            Some(())
        },
    ),
);

type TxParams1ParserT = (
    DefaultInterp,
    (SubDefT, (SubDefT, (SubDefT, (SubDefT, (SubDefT, SubDefT))))),
);
const TX_PARAMS1_PARSER: TxParams1ParserT = (
    DefaultInterp,
    (SUB_DEF, (SUB_DEF, (SUB_DEF, (SUB_DEF, (SUB_DEF, SUB_DEF))))),
);

pub type RecipientAmountT =
    impl InterpParser<MakeTransferTxParameters1, Returning = HasherAndPrivKey>;

const RECIPIENT_AMOUNT_PARSER: RecipientAmountT
  = MoveAction(
      TX_PARAMS1_PARSER
    , mkmvfn(|(tx_type, optv1): <TxParams1ParserT as ParserCommon<MakeTransferTxParameters1>>::Returning
             , destination:&mut Option<HasherAndPrivKey>| {
        let (recipient, optv2) = optv1?;
        let (recipient_chain, optv3) = optv2?;
        let (network, optv4) = optv3?;
        let (amount, optv5) = optv4?;
        let (namespace, mod_name) = optv5?;
        match destination {
            Some((ref mut hasher, privkey)) => {
                let mut pkh_str: ArrayString<64> = ArrayString::new();
                {
                    with_public_keys_int(privkey, |_: &_, pkh: &PKH| { try_option(|| -> Option<()> {
                        write!(mk_prompt_write(&mut pkh_str), "{}", pkh).ok()
                    }())}).ok()?;
                }
                handle_tx_param_1(&pkh_str, hasher, tx_type?, recipient.as_ref()?, recipient_chain.as_ref()?, amount.as_ref()?, network.as_ref()?, namespace.as_ref()?, mod_name.as_ref()?)?;

            }
            _ => { panic!("should have been set") }
        }
        Some(())
    }),
    );

type TxParams2ParserT = (SubDefT, (SubDefT, (SubDefT, (SubDefT, (SubDefT, SubDefT)))));
const TX_PARAMS2_PARSER: TxParams2ParserT =
    (SUB_DEF, (SUB_DEF, (SUB_DEF, (SUB_DEF, (SUB_DEF, SUB_DEF)))));

pub type MetaNonceT = impl InterpParser<MakeTransferTxParameters2, Returning = HasherAndPrivKey>;

const META_NONCE_PARSER: MetaNonceT =
    MoveAction(
        TX_PARAMS2_PARSER,
        mkmvfn(
            |(gas_price, optv1): <TxParams2ParserT as ParserCommon<
                MakeTransferTxParameters2,
            >>::Returning,
             destination: &mut Option<HasherAndPrivKey>| {
                let (gas_limit, optv2) = optv1?;
                let (creation_time, optv3) = optv2?;
                let (chain_id, optv4) = optv3?;
                let (nonce, ttl) = optv4?;
                match destination {
                    Some((ref mut hasher, privkey)) => {
                        let mut pkh_str: ArrayString<64> = ArrayString::new();
                        {
                            with_public_keys_int(privkey, |_: &_, pkh: &PKH| {
                                try_option(|| -> Option<()> {
                                    write!(mk_prompt_write(&mut pkh_str), "{}", pkh).ok()
                                }())
                            })
                            .ok()?;
                        }
                        handle_tx_params_2(
                            &pkh_str,
                            hasher,
                            &gas_price?,
                            &gas_limit?,
                            &creation_time?,
                            &chain_id?,
                            &nonce?,
                            &ttl?,
                        )?;
                    }
                    _ => {
                        panic!("destination should have been set")
                    }
                }
                Some(())
            },
        ),
    );

pub type MakeTransferTxImplT =
    impl InterpParser<MakeTransferTxParameters, Returning = ArrayVec<u8, 128_usize>>;

pub struct MakeTx;
pub static MAKE_TRANSFER_TX_IMPL: MakeTransferTxImplT = MakeTx;

pub enum MakeTxSubState {
    Init,
    Path(<PathParserT as ParserCommon<Bip32Key>>::State),
    RecipientAmount(<RecipientAmountT as ParserCommon<MakeTransferTxParameters1>>::State),
    MetaNonce(<MetaNonceT as ParserCommon<MakeTransferTxParameters2>>::State),
    Done,
}

impl ParserCommon<MakeTransferTxParameters> for MakeTx {
    type State = (Option<HasherAndPrivKey>, MakeTxSubState);
    type Returning = ArrayVec<u8, 128_usize>;
    fn init(&self) -> Self::State {
        (None, MakeTxSubState::Init)
    }
}

impl InterpParser<MakeTransferTxParameters> for MakeTx {
    #[inline(never)]
    fn parse<'a, 'b>(
        &self,
        (ref mut hasher_and_privkey, ref mut state): &'b mut Self::State,
        chunk: &'a [u8],
        destination: &mut Option<Self::Returning>,
    ) -> ParseResult<'a> {
        let mut cursor = chunk;
        loop {
            match state {
                MakeTxSubState::Init => {
                    info!(
                        "State sizes \nMakeTx: {}\n",
                        core::mem::size_of::<MakeTxSubState>()
                    );
                    init_with_default(destination);
                    set_from_thunk(state, || {
                        MakeTxSubState::Path(<PathParserT as ParserCommon<Bip32Key>>::init(
                            &PATH_PARSER,
                        ))
                    })
                }
                MakeTxSubState::Path(ref mut sub) => {
                    cursor = <PathParserT as InterpParser<Bip32Key>>::parse(
                        &PATH_PARSER,
                        sub,
                        cursor,
                        hasher_and_privkey,
                    )?;
                    set_from_thunk(state, || {
                        MakeTxSubState::RecipientAmount(<RecipientAmountT as ParserCommon<
                            MakeTransferTxParameters1,
                        >>::init(
                            &RECIPIENT_AMOUNT_PARSER
                        ))
                    })
                }
                MakeTxSubState::RecipientAmount(ref mut sub) => {
                    cursor = <RecipientAmountT as InterpParser<MakeTransferTxParameters1>>::parse(
                        &RECIPIENT_AMOUNT_PARSER,
                        sub,
                        cursor,
                        hasher_and_privkey,
                    )?;
                    set_from_thunk(state, || {
                        MakeTxSubState::MetaNonce(<MetaNonceT as ParserCommon<
                            MakeTransferTxParameters2,
                        >>::init(
                            &META_NONCE_PARSER
                        ))
                    })
                }
                MakeTxSubState::MetaNonce(ref mut sub) => {
                    cursor = <MetaNonceT as InterpParser<MakeTransferTxParameters2>>::parse(
                        &META_NONCE_PARSER,
                        sub,
                        cursor,
                        hasher_and_privkey,
                    )?;
                    set_from_thunk(state, || MakeTxSubState::Done);
                }
                MakeTxSubState::Done => {
                    match hasher_and_privkey {
                        Some((ref mut hasher, privkey)) => {
                            #[allow(clippy::needless_borrow)] // Needed for nanos
                            final_accept_prompt(&[&"Sign Transaction?"])
                                .ok_or((Some(OOB::Reject), cursor))?;
                            *destination = Some(ArrayVec::new());

                            let mut add_sig = || -> Option<()> {
                                let hash = hasher.finalize();
                                let sig = eddsa_sign_int(privkey, &hash.0).ok()?;
                                destination
                                    .as_mut()?
                                    .try_extend_from_slice(&sig.0[..])
                                    .ok()?;
                                Some(())
                            };
                            add_sig().ok_or((Some(OOB::Reject), cursor))?;

                            with_public_keys_int(privkey, |key: &_, _: &PKH| {
                                try_option(|| -> Option<()> {
                                    let key_x = ed25519_public_key_bytes(key);
                                    destination.as_mut()?.try_extend_from_slice(key_x).ok()
                                }())
                            })
                            .or(Err((Some(OOB::Reject), cursor)))?;
                            break Ok(cursor);
                        }
                        _ => {
                            panic!("should have been set")
                        }
                    }
                }
            }
        }
    }
}

// The global parser state enum; any parser above that'll be used as the implementation for an APDU
// must have a field here.
#[allow(clippy::large_enum_variant)]
pub enum ParsersState {
    NoState,
    SettingsState(u8),
    GetAddressState(<GetAddressImplT as ParserCommon<Bip32Key>>::State),
    SignState(<SignImplT as ParserCommon<SignParameters>>::State),
    SignHashState(<SignHashImplT as ParserCommon<SignHashParameters>>::State),
    MakeTransferTxState(<MakeTransferTxImplT as ParserCommon<MakeTransferTxParameters>>::State),
}

pub fn reset_parsers_state(state: &mut ParsersState) {
    *state = ParsersState::NoState;
}

meta_definition! {}
kadena_capability_definition! {}
signer_definition! {}
payload_definition! {}
command_definition! {}
kadena_cmd_definition! {}

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
            *s = ParsersState::SignHashState(
                <SignHashImplT as ParserCommon<SignHashParameters>>::init(&SIGN_HASH_IMPL),
            );
        }
    }
    match s {
        ParsersState::SignHashState(ref mut a) => a,
        _ => {
            panic!("")
        }
    }
}

#[inline(never)]
pub fn get_make_transfer_tx_state(
    s: &mut ParsersState,
) -> &mut <MakeTransferTxImplT as ParserCommon<MakeTransferTxParameters>>::State {
    match s {
        ParsersState::MakeTransferTxState(_) => {}
        _ => {
            info!("Non-same state found; initializing state.");
            *s = ParsersState::MakeTransferTxState(<MakeTransferTxImplT as ParserCommon<
                MakeTransferTxParameters,
            >>::init(&MAKE_TRANSFER_TX_IMPL));
        }
    }
    match s {
        ParsersState::MakeTransferTxState(ref mut a) => a,
        _ => {
            panic!("")
        }
    }
}
