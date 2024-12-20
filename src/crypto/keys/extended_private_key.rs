use secp256k1::{PublicKey, Scalar, SecretKey};
use stacks_common::util::hash::Hash160;
use crate::{bip32::{child_number::ChildNumber, derivation_path::DerivationPath, extended_keys::ExtendedKey, key_version::Version}, crypto::hmac::{self, HmacSha512}};
use super::{common_attrs::{ExtendedKeyAttrs, KeyFingerprint}, ChainCode, EXTENDED_KEY_LENGHT, KEY_LENGHT};


const BITCOIN_SEED_STRING: [u8; 12] = [
    0x42, 0x69, 0x74, 0x63, 0x6f, 0x69, 0x6e, 0x20, 0x73, 0x65, 0x65, 0x64,
];


pub struct ExtendedPrivateKey {
    pub attrs: ExtendedKeyAttrs,
    pub chain_code: ChainCode,
    pub s_key: SecretKey,
}

pub trait ExtendedPrivateKeyMethods {
    fn new(seed: &[u8]) -> Result<Self, hmac::HmacError> where Self: Sized;
    fn derive_child(&self, child_number: ChildNumber) -> Self;
    fn derive_from_path(seed: &[u8], derivation_path: DerivationPath) -> Self;
    fn public_key(&self) -> PublicKey;
    fn fingerprint(&self) -> KeyFingerprint;
    fn to_extended_key_bytes(&self) -> [u8; EXTENDED_KEY_LENGHT];
    fn to_extended_key(&self, version: Version) -> ExtendedKey;
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
            attrs: ExtendedKeyAttrs::default(),
            chain_code: chain_code,
            s_key: SecretKey::from_byte_array(&master_extended_s_key).unwrap()
        })
    }

    fn derive_child(&self, child_number: ChildNumber) -> Self {
        // TODO: check/propagate errors
        if self.attrs.depth >= 5 {
            // RETURN ERR
        }
        // key bytes + 4 byte index
        let mut payload = [0u8; 37];
        match child_number.is_hardened {
            true => payload[..33].copy_from_slice(&self.to_extended_key_bytes()),
            false => payload[..33].copy_from_slice(&self.public_key().serialize()),
        }
        payload[33..37].copy_from_slice(&child_number.index.to_be_bytes());
        let i = hmac::compute_hmac::<HmacSha512>(&payload, &self.chain_code).unwrap();
        
        let mut tweak_bytes: [u8; 32] = [0u8; KEY_LENGHT];
        let mut child_chain_code = [0u8; KEY_LENGHT];

        tweak_bytes.copy_from_slice(&i[0..KEY_LENGHT]);
        child_chain_code.copy_from_slice(&i[KEY_LENGHT..KEY_LENGHT*2]);

        let child_s_key = self.s_key.add_tweak(&Scalar::from_be_bytes(tweak_bytes).unwrap()).unwrap();
        Self {
            attrs: ExtendedKeyAttrs::new(self.attrs.depth+1, self.fingerprint(), child_number),
            chain_code: child_chain_code,
            s_key: child_s_key
        }
    }

    fn derive_from_path(seed: &[u8], derivation_path: DerivationPath) -> Self {
        // TODO: check/propagate errors
        let mut key = Self::new(seed).unwrap();
        let mut depth = 0u8;
        let mut path = ChildNumber::new(0).unwrap();
        for child_number in derivation_path.path {
            key = key.derive_child(child_number);
            depth+=1;
            path = child_number;
        }
        Self {  
            attrs: ExtendedKeyAttrs::new(depth, key.fingerprint(), path),
            s_key: key.s_key,
            chain_code: key.chain_code 
        }
    }

    fn public_key(&self) -> PublicKey {
        let secp = &secp256k1::Secp256k1::new();
        self.s_key.public_key(secp)
    }

    fn fingerprint(&self) -> KeyFingerprint {
        let public_key = self.public_key();
        let res = Hash160::from_data(&public_key.serialize());
        let mut fingerprint = [0u8; 4];
        fingerprint.copy_from_slice(&res.as_bytes()[0..4]);
        fingerprint
    }

    fn to_extended_key_bytes(&self) -> [u8; EXTENDED_KEY_LENGHT] {
        // Add leading `0` byte
        let mut key_bytes = [0u8; EXTENDED_KEY_LENGHT];
        key_bytes[1..].copy_from_slice(&self.s_key.secret_bytes());
        key_bytes
    }   

    fn to_extended_key(&self, version: Version) -> ExtendedKey {
        ExtendedKey {
            version: version,
            attrs: self.attrs,
            chain_code: self.chain_code,
            key_bytes: self.to_extended_key_bytes()
        }
    }
}
