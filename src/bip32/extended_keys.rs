use secp256k1::{PublicKey, Scalar, SecretKey};
use stacks_common::{address::b58, util::hash::Hash160};
use crate::crypto::hmac::{self, HmacSha512};

use super::{child_number::ChildNumber, derivation_path::DerivationPath};

const BITCOIN_SEED_STRING: [u8; 12] = [
    0x42, 0x69, 0x74, 0x63, 0x6f, 0x69, 0x6e, 0x20, 0x73, 0x65, 0x65, 0x64,
];


const VERSION_LEN: usize = 4;
const FINGERPRINT_LEN: usize = 4;
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
        fn convert<'a>(version_string: &str, buf: &'a mut [u8; VERSION_LEN]) {
            buf.copy_from_slice(&hex::decode(version_string).unwrap());
        }
        let mut version_bytes = [0u8; VERSION_LEN];
        match *self {
            Version::XPrv => {
                convert("0488ade4", &mut version_bytes);
                version_bytes
            },
            Version::XPub => {
                convert("0488b21e", &mut version_bytes);
                version_bytes
            },
            Version::TPrv => {
                convert("04358394", &mut version_bytes);
                version_bytes
            },
            Version::TPub => {
                convert("043587cf", &mut version_bytes);
                version_bytes
            }
            Version::ZPrv => {
                convert("04b2430c", &mut version_bytes);
                version_bytes
            },
            Version::ZPub => {
                convert("04b24746", &mut version_bytes);
                version_bytes
            },
            Version::YPrv => {
                convert("049d7878", &mut version_bytes);
                version_bytes
            },
            Version::YPub => {
                convert("049d7cb2", &mut version_bytes);
                version_bytes
            },
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
    depth: u8,
    parent_fingerprint: [u8; FINGERPRINT_LEN],
    child_number: ChildNumber,
    chain_code: ChainCode,
    s_key: SecretKey,
}

pub trait ExtendedPrivateKeyMethods {
    fn new(seed: &[u8]) -> Result<Self, hmac::HmacError> where Self: Sized;
    fn derive_child(&self, index: u32) -> Self;
    fn derive_from_path(seed: &[u8], derivation_path: DerivationPath) -> Self;
    fn public_key(&self) -> PublicKey;
    fn fingerprint(&self) -> [u8; FINGERPRINT_LEN];
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
            depth: 0, 
            parent_fingerprint: [0u8; FINGERPRINT_LEN], 
            child_number: ChildNumber::new(0).unwrap(),
            chain_code: chain_code,
            s_key: SecretKey::from_byte_array(&master_extended_s_key).unwrap()
        })
    }

    fn derive_child(&self, index: u32) -> Self {
        // TODO: check/propagate errors
        if self.depth >= 5 {
            // RETURN ERR
        }
        let child_number = ChildNumber::new(index).unwrap();
        let mut payload = self.public_key().serialize();
        payload.copy_from_slice(&child_number.index.to_be_bytes());
        let i = hmac::compute_hmac::<HmacSha512>(&payload, &self.chain_code).unwrap();
        
        let mut tweak_bytes: [u8; 32] = [0u8; KEY_LENGHT];
        let mut child_chain_code = [0u8; KEY_LENGHT];

        tweak_bytes.copy_from_slice(&i[0..KEY_LENGHT]);
        child_chain_code.copy_from_slice(&i[KEY_LENGHT..KEY_LENGHT*2]);

        let child_s_key = self.s_key.add_tweak(&Scalar::from_be_bytes(tweak_bytes).unwrap()).unwrap();
        Self {
            depth: self.depth+1, 
            parent_fingerprint: self.fingerprint(), 
            child_number: child_number,
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
            key = key.derive_child(child_number.index);
            depth+=1;
            path = child_number;
        }
        Self { 
            depth: depth, 
            parent_fingerprint: key.fingerprint(), 
            child_number: path, 
            s_key: key.s_key,
            chain_code: key.chain_code 
        }
    }

    fn public_key(&self) -> PublicKey {
        let secp = &secp256k1::Secp256k1::new();
        self.s_key.public_key(secp)
    }

    fn fingerprint(&self) -> [u8; FINGERPRINT_LEN] {
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
            depth: self.depth,
            parent_fingerprint: self.parent_fingerprint,
            child_number: self.child_number,
            chain_code: self.chain_code,
            key_bytes: self.to_extended_key_bytes()
        }
    }
}

pub struct ExtendedKey {
    /// version of the extended key (e.g. xprv, xpub, ...)
    version: Version,
    depth: u8,
    parent_fingerprint: [u8; FINGERPRINT_LEN],
    child_number: ChildNumber,
    chain_code: ChainCode,
    /// bytes of the exteded key. Can be either the bytes of a private key or of a public key
    key_bytes: [u8; EXTENDED_KEY_LENGHT],
}

impl ExtendedKey {

    /// Size of an extended key when deserialized into bytes from Base58.
    pub const BYTE_SIZE: usize = 78;

    /// Maximum size of a Base58Check-encoded extended key in bytes.
    ///
    /// Note that extended keys can also be 111-bytes.
    pub const MAX_BASE58_SIZE: usize = 112;

    pub fn b58_encode(&self) -> String {
        let mut bytes = [0u8; Self::BYTE_SIZE]; // with 4-byte checksum
        bytes[..4].copy_from_slice(&self.version.to_bytes());
        bytes[4] = self.depth;
        bytes[5..9].copy_from_slice(&self.parent_fingerprint);
        bytes[9..13].copy_from_slice(&self.child_number.index.to_be_bytes());
        bytes[13..45].copy_from_slice(&self.chain_code);
        bytes[45..78].copy_from_slice(&self.key_bytes);
        
        b58::check_encode_slice(&bytes)
    }

    //pub fn b58_decode(b58_key: &str) -> Self {
    //    let bytes = b58::from_check(b58_key).unwrap();
    //}

}

mod tests {
    use super::*;


    #[test]
    /// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#user-content-Test_Vectors
    fn test_new_extended_private_key() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master_key = ExtendedPrivateKey::new(&seed).unwrap();
        let b58_master_key = master_key.to_extended_key(Version::XPrv).b58_encode();
        assert_eq!(b58_master_key, "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi");
    }   
}