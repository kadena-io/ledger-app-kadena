use crate::info;
use core::default::Default;
use core::fmt;
use nanos_sdk::bindings::*;
use nanos_sdk::ecc::{CurvesId};
use nanos_sdk::io::SyscallError;
use ledger_log::*;

pub const BIP32_PATH: [u32; 5] = nanos_sdk::ecc::make_bip32_path(b"m/44'/535348'/0'/0/0");

/// Helper function that derives the seed over secp256k1
pub fn bip32_derive_eddsa(path: &[u32]) -> Result<[u8; 32], SyscallError> {
    let mut raw_key = [0u8; 32];
    unsafe {
        os_perso_derive_node_bip32(
            CX_CURVE_Ed25519,
            path.as_ptr(),
            path.len() as u32,
            raw_key.as_mut_ptr(),
            core::ptr::null_mut()
        )
    };
    error!("bip32 result: {:?}", raw_key);
    Ok(raw_key)
}

pub struct EdDSASig(pub [u8; 64]);

macro_rules! call_c_api_function {
    ($($call:tt)*) => {
        {
            let err = unsafe {
                $($call)*
            };
            if err != 0 {
                Err(SyscallError::from(err))
            } else {
                Ok(())
            }
        }
    }
}


/// Helper function that signs with ECDSA in deterministic nonce,
/// using SHA256
#[allow(dead_code)]
pub fn eddsa_sign(
    m: &[u8],
    ec_k: &cx_ecfp_private_key_t,
) -> Option<EdDSASig> {
    let mut sig:[u8;64]=[0; 64];
    call_c_api_function!(
         cx_eddsa_sign_no_throw(
            ec_k,
            CX_SHA512,
            m.as_ptr(),
            m.len() as u32,
            sig.as_mut_ptr(),
            sig.len() as u32)
    ).ok()?;
    Some(EdDSASig(sig))
}

pub fn get_pubkey(path: &[u32]) -> Result<nanos_sdk::bindings::cx_ecfp_public_key_t, SyscallError> {

    let mut ec_k = get_private_key(path)?;
    /*let raw_key = bip32_derive_eddsa(path)?;
    let mut ec_k = cx_ecfp_private_key_t::default();
    call_c_api_function!(cx_ecfp_init_private_key_no_throw(
            CX_CURVE_Ed25519,
            raw_key.as_ptr(),
            raw_key.len() as u32,
            &mut ec_k
        ))?;

*/
    get_pubkey_from_privkey(&mut ec_k)
}

pub fn get_pubkey_from_privkey(ec_k: &mut nanos_sdk::bindings::cx_ecfp_private_key_t) -> Result<nanos_sdk::bindings::cx_ecfp_public_key_t, SyscallError> {
    let mut pubkey = cx_ecfp_public_key_t::default();

    error!("Private key: {:?}", ec_k.d);
    call_c_api_function!(cx_ecfp_generate_pair_no_throw(CX_CURVE_Ed25519, &mut pubkey, ec_k, true))?;
    error!("Private key 2: {:?}", ec_k.d);
    error!("Public key: {:?}", pubkey.W);
    call_c_api_function!(cx_edwards_compress_point_no_throw(CX_CURVE_Ed25519, pubkey.W.as_mut_ptr(), pubkey.W_len))?;
    pubkey.W_len = 33;
    error!("Public key: {:?}", pubkey.W);

    Ok(pubkey)
}

#[allow(dead_code)]
pub fn get_private_key(
    path: &[u32],
) -> Result<nanos_sdk::bindings::cx_ecfp_private_key_t, SyscallError> {
    let raw_key = bip32_derive_eddsa(path)?;
    let mut ec_k = cx_ecfp_private_key_t::default();
    call_c_api_function!(cx_ecfp_init_private_key_no_throw(
            CX_CURVE_Ed25519,
            raw_key.as_ptr(),
            raw_key.len() as u32,
            &mut ec_k
        ))?;
    Ok(ec_k)
}

// Public Key Hash type; update this to match the target chain's notion of an address and how to
// format one.
// Kadena doesn't appear to use hashed public keys, instead using raw public keys as addresses, so
// we'll make this match.

pub struct PKH(cx_ecfp_public_key_t);

#[allow(dead_code)]
pub fn get_pkh(key: nanos_sdk::bindings::cx_ecfp_public_key_t) -> PKH {
    PKH(key)
}

impl fmt::Display for PKH {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0.W[1..self.0.W_len as usize] {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

struct HexSlice<'a>(&'a [u8]);

// You can choose to implement multiple traits, like Lower and UpperHex
impl fmt::Display for HexSlice<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            // Decide if you want to pad the value or have spaces inbetween, etc.
            write!(f, "{:02X}", byte)?;
        }
        Ok(())
    }
}

// use blake2::Blake2s;
#[derive(Clone, Copy)]
pub struct Hasher(cx_blake2b_s);

impl Hasher {
    pub fn new() -> Hasher {
        let mut rv = cx_blake2b_s::default();
        unsafe { cx_blake2b_init_no_throw(&mut rv, 512) };
        Self(rv)
        // Self([0;255])
    }

    pub fn update(&mut self, bytes: &[u8]) {
        unsafe {
            trace!("Hashing bytes: {:?}", bytes);
            cx_hash_update(&mut self.0 as *mut cx_blake2b_s as *mut cx_hash_t, bytes.as_ptr(), bytes.len() as u32);
        }
    }

    pub fn finalize(&mut self) -> Hash {
        let mut rv = [0; 64];
        unsafe { cx_hash_final(&mut self.0 as *mut cx_blake2b_s as *mut cx_hash_t, rv.as_mut_ptr()) };
        error!("Hash value now: {:?}", rv);
        Hash(rv)
    }
}

pub struct Hash(pub [u8; 64]);

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{:02X}", byte)?;
        }
        Ok(())
    }
}
