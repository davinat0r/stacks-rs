use secp256k1::{PublicKey, Scalar};
use stacks_common::util::hash::Hash160;
use crate::bip32::extended_keys::ExtendedKey;
use crate::crypto::hmac::{self, HmacSha512};
use crate::bip32::{child_number::ChildNumber, key_version::Version};

use super::extended_private_key::ExtendedPrivateKeyMethods;
use super::{common_attrs::{ExtendedKeyAttrs, KeyFingerprint}, extended_private_key::ExtendedPrivateKey, ChainCode, EXTENDED_KEY_LENGHT, KEY_LENGHT};

pub struct ExtendedPublicKey {
    pub(crate) attrs: ExtendedKeyAttrs,
    pub(crate) chain_code: ChainCode,
    pub(crate) p_key: PublicKey,
}

pub trait ExtendedPublicKeyMethods {
    fn new(public_key: PublicKey, chain_code: ChainCode, attrs: ExtendedKeyAttrs) -> Self;
    fn public_key(&self) -> &PublicKey;
    fn derive_child(&self, child_number: ChildNumber) -> Result<Self, ()> where Self: Sized;
    fn fingerprint(&self) -> KeyFingerprint;
    fn public_key_bytes(&self) -> [u8; EXTENDED_KEY_LENGHT];
    fn to_extended_key(&self, version: Version) -> ExtendedKey;
}

impl ExtendedPublicKeyMethods for ExtendedPublicKey {
    fn new(public_key: PublicKey, chain_code: ChainCode, attrs: ExtendedKeyAttrs) -> Self {
        Self { attrs: attrs, chain_code: chain_code, p_key: public_key }
    }

    fn public_key(&self) -> &PublicKey {
        &self.p_key
    }

    fn fingerprint(&self) -> KeyFingerprint {
        let res = Hash160::from_data(&self.p_key.serialize());
        let mut fingerprint = [0u8; 4];
        fingerprint.copy_from_slice(&res.as_bytes()[0..4]);
        fingerprint
    }

    fn public_key_bytes(&self) -> [u8; EXTENDED_KEY_LENGHT] {
        self.public_key().serialize()
    }

    fn derive_child(&self, child_number: ChildNumber) -> Result<Self, ()> {
        // TODO: check/propagate errors
        if self.attrs.depth >= 5 {
            // RETURN ERR
        }
        // key bytes + 4 byte index
        let mut payload = [0u8; 37];
        match child_number.is_hardened {
            true => Err(()),
            false => Ok(payload[..33].copy_from_slice(&self.p_key.serialize())),
        }?;
        payload[33..37].copy_from_slice(&child_number.index.to_be_bytes());
        let i = hmac::compute_hmac::<HmacSha512>(&payload, &self.chain_code).unwrap();
        
        let mut tweak_bytes: [u8; 32] = [0u8; KEY_LENGHT];
        let mut child_chain_code = [0u8; KEY_LENGHT];

        tweak_bytes.copy_from_slice(&i[0..KEY_LENGHT]);
        child_chain_code.copy_from_slice(&i[KEY_LENGHT..KEY_LENGHT*2]);

        let child_p_key = self.p_key.add_exp_tweak(&secp256k1::Secp256k1::new() ,&Scalar::from_be_bytes(tweak_bytes).unwrap()).unwrap();
        Ok(Self {
            attrs: ExtendedKeyAttrs::new(self.attrs.depth+1, self.fingerprint(), child_number),
            chain_code: child_chain_code,
            p_key: child_p_key
        })
    }

    fn to_extended_key(&self, version: Version) -> ExtendedKey {
        ExtendedKey {
            version: version,
            attrs: self.attrs,
            chain_code: self.chain_code,
            key_bytes: self.public_key_bytes()
        }
    }
}

impl From<&ExtendedPrivateKey> for ExtendedPublicKey {
    fn from(extended_private_key: &ExtendedPrivateKey) -> Self {
        Self { 
            attrs: extended_private_key.attrs.clone(), 
            chain_code: extended_private_key.chain_code.clone(), 
            p_key: extended_private_key.public_key() 
        }
    }
}
