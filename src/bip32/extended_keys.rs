use std::fmt;

use secp256k1::{PublicKey, Scalar, SecretKey};
use stacks_common::util::hash::Hash160;
use crate::crypto::{hash, hmac::{self, HmacSha512}};

use super::{child_number::ChildNumber, derivation_path::DerivationPath};

const BITCOIN_SEED_STRING: [u8; 12] = [
    0x42, 0x69, 0x74, 0x63, 0x6f, 0x69, 0x6e, 0x20, 0x73, 0x65, 0x65, 0x64,
];


const VERSION_LEN: usize = 4;
const KEY_LENGHT: usize = 32;
const EXTENDED_KEY_LENGHT: usize = 33;

pub type ChainCode = [u8; KEY_LENGHT];

pub enum Version {
    XPrv,
    XPub,
    TPrv,
    TPub,
    ZPrv,
    ZPub,
    YPrv,
    YPub,
}

impl Version {
    fn to_bytes(&self) -> [u8; VERSION_LEN] {
        fn convert<'a>(version_string: &str, buf: &'a mut [u8; VERSION_LEN])-> &'a [u8; VERSION_LEN] {
            buf.copy_from_slice(version_string.as_bytes());
            buf
        }
        let mut version_bytes = [0u8; VERSION_LEN];
        match *self {
            Version::XPrv => convert("0488ade4", &mut version_bytes).to_owned(),
            Version::XPub => convert("0488b21e", &mut version_bytes).to_owned(),
            Version::TPrv => convert("04358394", &mut version_bytes).to_owned(),
            Version::TPub => convert("043587cf", &mut version_bytes).to_owned(),
            Version::ZPrv => convert("04b2430c", &mut version_bytes).to_owned(),
            Version::ZPub => convert("04b24746", &mut version_bytes).to_owned(),
            Version::YPrv => convert("049d7878", &mut version_bytes).to_owned(),
            Version::YPub => convert("049d7cb2", &mut version_bytes).to_owned(),
        }
    }

    fn to_string<'a>(&'a self) -> &'a str {
        match *self {
            Version::XPrv => "xprv",
            Version::XPub => "xpub",
            Version::TPrv => "tprv",
            Version::TPub => "tpub",
            Version::ZPrv => "zprv",
            Version::ZPub => "zpub",
            Version::YPrv => "yprv",
            Version::YPub => "ypub",
        }
    }
}

pub struct ExtendedPrivateKey {
    chain_code: ChainCode,
    s_key: SecretKey,
}

pub trait ExtendedPrivateKeyMethods {
    fn new(seed: &[u8]) -> Result<Self, hmac::HmacError> where Self: Sized;
    fn derive_child(&self, index: u32) -> Self;
    fn public_key(&self) -> PublicKey;
    fn fingerprint(public_key: &PublicKey) -> [u8; 4];
}

impl ExtendedPrivateKeyMethods for ExtendedPrivateKey {

    /// Generates the Extended Master Private Key from the provided `seed`.
    fn new(seed: &[u8]) -> Result<Self, hmac::HmacError> {
        let result = hmac::compute_hmac::<hmac::HmacSha512>(seed, &BITCOIN_SEED_STRING)?;
        let mut chain_code: ChainCode = [0u8; KEY_LENGHT];
        let mut master_extended_s_key = [0u8; KEY_LENGHT];

        master_extended_s_key.copy_from_slice(&result[0..KEY_LENGHT]);
        chain_code.copy_from_slice(&result[KEY_LENGHT..KEY_LENGHT*2]);
        Ok( Self {
            chain_code: chain_code,
            s_key: SecretKey::from_byte_array(&master_extended_s_key).unwrap()
        })
    }

    fn derive_child(&self, index: u32) -> Self {
        let mut payload = self.public_key().serialize();
        payload.copy_from_slice(&index.to_be_bytes());
        let i = hmac::compute_hmac::<HmacSha512>(&payload, &self.chain_code).unwrap();
        
        let mut tweak_bytes: [u8; 32] = [0u8; KEY_LENGHT];
        let mut child_chain_code = [0u8; KEY_LENGHT];

        tweak_bytes.copy_from_slice(&i[0..KEY_LENGHT]);
        child_chain_code.copy_from_slice(&i[KEY_LENGHT..KEY_LENGHT*2]);

        let child_s_key = self.s_key.add_tweak(&Scalar::from_be_bytes(tweak_bytes).unwrap()).unwrap();
        Self {
            chain_code: child_chain_code,
            s_key: child_s_key
        }
    }

    fn public_key(&self) -> PublicKey {
        let secp = &secp256k1::Secp256k1::new();
        self.s_key.public_key(secp)
    }

    fn fingerprint(public_key: &PublicKey) -> [u8; 4] {
        let res = Hash160::from_data(&public_key.serialize());
        let mut fingerprint = [0u8; 4];
        fingerprint.copy_from_slice(&res.as_bytes()[0..4]);
        fingerprint
    }
}

pub struct ExtendedKey {
    /// version of the extended key (e.g. xprv, xpub, ...)
    version: Version,
    depth: u8,
    parent_fingerprint: [u8; 4],
    child_number: ChildNumber,
    /// bytes of the exteded key. Can be either the bytes of a private key or of a public key
    key_bytes: [u8; EXTENDED_KEY_LENGHT],
}

impl ExtendedKey {

    pub fn derive_from_path<T: ExtendedPrivateKeyMethods>(key: T, derivation_path: DerivationPath) {
        key.derive_child(0);
    }

    pub fn b58_encode() {

    }

    pub fn b58_decode() {

    }

}