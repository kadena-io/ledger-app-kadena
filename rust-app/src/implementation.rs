use crate::crypto_helpers::{eddsa_sign, get_pkh, get_private_key, get_pubkey, get_pubkey_from_privkey, Hasher};
use crate::interface::*;
use arrayvec::{ArrayString, ArrayVec};
use core::fmt::Write;
use ledger_log::*;
use ledger_parser_combinators::interp_parser::{
    Action, DefaultInterp, DropInterp, InterpParser, ObserveLengthedBytes, SubInterp,
};
use ledger_parser_combinators::json::Json;
use nanos_ui::ui;

use ledger_parser_combinators::define_json_struct_interp;
use ledger_parser_combinators::json::*;
use ledger_parser_combinators::json_interp::*;

pub type GetAddressImplT =
    Action<SubInterp<DefaultInterp>, fn(&ArrayVec<u32, 10>, &mut Option<ArrayVec<u8, 260>>) -> Option<()>>;

pub const GET_ADDRESS_IMPL: GetAddressImplT =
    Action(SubInterp(DefaultInterp), |path: &ArrayVec<u32, 10>, destination: &mut Option<ArrayVec<u8, 260>>| {
        let key = get_pubkey(&path).ok()?;
        //let mut rv = ArrayVec::<u8, 260>::new();
        // rv.try_extend_from_slice(&[(key.W.len() as u8)][..]).ok()?;

        // At this point we have the value to send to the host; but there's a bit more to do to
        // ask permission from the user.

        let pkh = get_pkh(key);

        let mut pmpt = ""; // ArrayString::<128>::new();
        //write!(pmpt, "{}", pkh).ok()?;

        if !ui::MessageValidator::new(&["Provide Public Key", &pmpt], &[&"Confirm"], &[]).ask() {
            trace!("User rejected\n");
            None
        } else {
            trace!("User accepted");
            *destination=Some(ArrayVec::new());
            destination.as_mut()?.try_extend_from_slice(&key.W[1..key.W_len as usize]).ok()?;
            Some(())
        }
    });

pub type SignImplT = Action<
    (
        Action<
            ObserveLengthedBytes<
                Hasher,
                fn(&mut Hasher, &[u8]),
                Json<
                    KadenaCmd<
                        DropInterp,
                        DropInterp,
                        SubInterp<
                            Signer<
                                DropInterp,
                                DropInterp,
                                DropInterp,
                                SubInterp<
                                    Action<
                                        JsonStringAccumulate<64>,
                                        fn(&ArrayVec<u8, 64>, &mut Option<()>) -> Option<()>,
                                    >,
                                >,
                            >,
                        >,
                        DropInterp,
                        DropInterp,
                    >,
                >,
            >,
            fn(
                &(
                    Option< KadenaCmd<Option<()>, Option<()>, Option<()>, Option<()>, Option<()>>>,
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
                Json(KadenaCmd {
                    field_nonce: DropInterp,
                    field_meta: DropInterp,
                    field_signers: SubInterp(Signer {
                        field_scheme: DropInterp,
                        field_pub_key: DropInterp,
                        field_addr: DropInterp,
                        field_caps: SubInterp(Action(
                            JsonStringAccumulate,
                            |cap_str: &ArrayVec<u8, 64>, _| {
                                /*let pmpt = ArrayString::<128>::from(
                                    core::str::from_utf8(&cap_str[..]).ok()?,
                                )
                                .ok()?;
                                if !ui::MessageValidator::new(&["Transaction May", &pmpt], &[], &[])
                                    .ask()
                                {
                                    None
                                } else {*/
                                    Some(())
                                //}
                            },
                        )),
                    }),
                    field_payload: DropInterp,
                    field_network_id: DropInterp,
                }),
            false),
            // Ask the user if they accept the transaction body's hash
            |(_, mut hash): &(_, Hasher), destination: &mut _| {
                error!("Prompting with hash");
                let the_hash = hash.finalize();
                
                error!("Hash is: {}", the_hash);
                /*

                let mut pmpt = "";// ArrayString::<128>::new();
                //write!(pmpt, "{}", the_hash).ok()?;

                error!("Prompt formatted");

                if !ui::MessageValidator::new(&["Sign Hash?", &pmpt], &[], &[]).ask() {
                    None
                } else {*/
                    *destination=Some(the_hash.0.into());
                    Some(())
                /*}*/
            },
        ),
        Action(
            SubInterp(DefaultInterp),
            // And ask the user if this is the key the meant to sign with:
            |path: &ArrayVec<u32, 10>, destination: &mut _| {
                error!("Getting private key");
                // Mutable because of some awkwardness with the C api.
                let mut privkey = get_private_key(&path).ok()?;
                error!("Getting public key");
                let pubkey = get_pubkey_from_privkey(&mut privkey).ok()?;
                error!("Getting pKH");
                let pkh = get_pkh(pubkey);

                error!("Prompting for public key");
                let mut pmpt = ""; // ArrayString::<128>::new();
                //write!(pmpt, "{}", pkh).ok()?;

                /* if !ui::MessageValidator::new(&["With Public Key", &pmpt], &[], &[]).ask() {
                    None
                } else { */
                    *destination = Some(privkey);
                    Some(())
                // }
            },
        ),
    ),
    |(hash, key): &(Option<[u8; 64]>, Option<_>), destination: &mut _| {
        // By the time we get here, we've approved and just need to do the signature.
        error!("SIGNING");
        let sig = eddsa_sign(&hash.as_ref()?[..], key.as_ref()?)?;
        let mut rv = ArrayVec::<u8, 260>::new();
        rv.try_extend_from_slice(&sig.0[..]).ok()?;
        *destination = Some(rv);
        Some(())
    },
);

// The global parser state enum; any parser above that'll be used as the implementation for an APDU
// must have a field here.

pub enum ParsersState {
    NoState,
    GetAddressState(<GetAddressImplT as InterpParser<Bip32Key>>::State),
    SignState(<SignImplT as InterpParser<SignParameters>>::State),
}

define_json_struct_interp! { Meta 16 {
    chainId: JsonString,
    sender: JsonString,
    gasLimit: JsonNumber,
    gasPrice: JsonNumber,
    ttl: JsonNumber,
    creationTime: JsonNumber
}}
define_json_struct_interp! { Signer 16 {
    scheme: JsonString,
    pubKey: JsonString,
    addr: JsonString,
    caps: JsonArray<JsonString>
}}
define_json_struct_interp! { KadenaCmd 16 {
  nonce: JsonString,
  meta: MetaSchema,
  signers: JsonArray<SignerSchema>,
  payload: JsonAny,
  networkId: JsonAny
}}

#[inline(never)]
pub fn get_get_address_state(
    s: &mut ParsersState,
) -> &mut <GetAddressImplT as InterpParser<Bip32Key>>::State {
    match s {
        ParsersState::GetAddressState(_) => {}
        _ => {
            trace!("Non-same state found; initializing state.");
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
            trace!("Non-same state found; initializing state.");
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
