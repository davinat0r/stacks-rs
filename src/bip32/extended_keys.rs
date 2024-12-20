use core::error;
use std::str::FromStr;

use secp256k1::{PublicKey, SecretKey};
use stacks_common::address::b58;
use crate::bip32::key_version::Version;
use crate::crypto::keys::common_attrs::{ExtendedKeyAttrs, KeyFingerprint};
use crate::crypto::keys::extended_private_key::ExtendedPrivateKey;
use crate::crypto::keys::extended_public_key::ExtendedPublicKey;
use crate::crypto::keys::{ChainCode, EXTENDED_KEY_LENGHT, KEY_LENGHT};
use super::child_number::ChildNumber;

pub struct ExtendedKey {
    /// version of the extended key (e.g. xprv, xpub, ...)
    pub version: Version,
    pub attrs: ExtendedKeyAttrs,
    pub chain_code: ChainCode,
    /// bytes of the exteded key. Can be either the bytes of a private key or of a public key
    pub key_bytes: [u8; EXTENDED_KEY_LENGHT],
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
        bytes[4] = self.attrs.depth;
        bytes[5..9].copy_from_slice(&self.attrs.parent_fingerprint);
        bytes[9..13].copy_from_slice(&self.attrs.child_number.index.to_be_bytes());
        bytes[13..45].copy_from_slice(&self.chain_code);
        bytes[45..78].copy_from_slice(&self.key_bytes);
        
        b58::check_encode_slice(&bytes)
    }
}

impl FromStr for ExtendedKey {
    type Err = Box<dyn error::Error>;

    fn from_str(b58_key: &str) -> Result<Self, Self::Err> {
        let b58key_bytes = b58::from_check(b58_key)?;
        let version = Version::try_from(&b58key_bytes[..4])?;
        let depth = &b58key_bytes[4];
        let mut parent_fingerprint = KeyFingerprint::default();
        parent_fingerprint.copy_from_slice(&b58key_bytes[5..9]);
        let mut child_index = [0u8; 4];
        child_index.copy_from_slice(&b58key_bytes[9..13]);
        let child_number = ChildNumber::new(u32::from_be_bytes(child_index))?;
        let mut chain_code = ChainCode::default();
        chain_code.copy_from_slice(&b58key_bytes[13..45]);
        let mut key = [0u8; EXTENDED_KEY_LENGHT];
        key.copy_from_slice(&b58key_bytes[45..78]);
        
        Ok(Self { 
            version: version, 
            attrs: ExtendedKeyAttrs::new(*depth, parent_fingerprint, child_number), 
            chain_code: chain_code, 
            key_bytes: key 
        })
    }
}

impl TryFrom<ExtendedKey> for ExtendedPrivateKey {
    type Error = Box<dyn error::Error>;

    fn try_from(extended_key: ExtendedKey) -> Result<Self, Self::Error> {
        let mut key_bytes = [0u8; KEY_LENGHT];
        key_bytes.copy_from_slice(&extended_key.key_bytes[1..EXTENDED_KEY_LENGHT]);
        Ok(Self { 
            attrs: extended_key.attrs, 
            chain_code: extended_key.chain_code, 
            s_key: SecretKey::from_byte_array(&key_bytes)? 
        })
    }
}

impl TryFrom<ExtendedKey> for ExtendedPublicKey {
    type Error = Box<dyn error::Error>;

    fn try_from(extended_key: ExtendedKey) -> Result<Self, Self::Error> {
        Ok(Self { 
            attrs: extended_key.attrs, 
            chain_code: extended_key.chain_code, 
            p_key: PublicKey::from_byte_array_compressed(&extended_key.key_bytes)? 
        })
    }
}

mod tests {
    use std::str::FromStr;

    use crate::crypto::keys::{extended_private_key::ExtendedPrivateKeyMethods, extended_public_key::ExtendedPublicKeyMethods};

    use super::*;


    #[test]
    /// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#user-content-Test_Vectors
    fn test_new_extended_private_key() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master_key = ExtendedPrivateKey::new(&seed).unwrap();
        let b58_master_key = master_key.to_extended_key(Version::XPrv).b58_encode();
        assert_eq!(b58_master_key, "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi");
        let master_pub_key = ExtendedPublicKey::try_from(&master_key).unwrap();
        let b58_master_pub_key = master_pub_key.to_extended_key(Version::XPub).b58_encode();
        assert_eq!(b58_master_pub_key, "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8");

        // m/0'
        let purpose_0_h = master_key.derive_child(ChildNumber::from_str("0'").unwrap());
        let b58_purpose_0_h = purpose_0_h.to_extended_key(Version::XPrv).b58_encode();
        assert_eq!(b58_purpose_0_h, "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7");
        let purpose_0_h_pub = ExtendedPublicKey::try_from(&purpose_0_h).unwrap();
        let b58_purpose_0_h_pub = purpose_0_h_pub.to_extended_key(Version::XPub).b58_encode();
        assert_eq!(b58_purpose_0_h_pub, "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw");


        // m/0'/1
        let coin_1 = purpose_0_h.derive_child(ChildNumber::from_str("1").unwrap());
        let b58_coin_1 = coin_1.to_extended_key(Version::XPrv).b58_encode();
        assert_eq!(b58_coin_1, "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs");
        let coin_1_pub = ExtendedPublicKey::try_from(&coin_1).unwrap();
        let b58_coin_1_pub = coin_1_pub.to_extended_key(Version::XPub).b58_encode();
        assert_eq!(b58_coin_1_pub, "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ");

        // m/0'/1/2'
        let account_2_h = coin_1.derive_child(ChildNumber::from_str("2'").unwrap());
        let b58_account_2_h = account_2_h.to_extended_key(Version::XPrv).b58_encode();
        assert_eq!(b58_account_2_h, "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM");
        let account_2_h_pub = ExtendedPublicKey::try_from(&account_2_h).unwrap();
        let b58_account_2_h_pub = account_2_h_pub.to_extended_key(Version::XPub).b58_encode();
        assert_eq!(b58_account_2_h_pub, "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5");

        // m/0'/1/2'/2
        let change_2 = account_2_h.derive_child(ChildNumber::from_str("2").unwrap());
        let b58_change_2 = change_2.to_extended_key(Version::XPrv).b58_encode();
        assert_eq!(b58_change_2, "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334");
        let change_2_pub = ExtendedPublicKey::try_from(&change_2).unwrap();
        let b58_change_2_pub = change_2_pub.to_extended_key(Version::XPub).b58_encode();
        assert_eq!(b58_change_2_pub, "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV");


        // m/0'/1/2'/2
        let address_1000000000 = change_2.derive_child(ChildNumber::from_str("1000000000").unwrap());
        let b58_address_1000000000 = address_1000000000.to_extended_key(Version::XPrv).b58_encode();
        assert_eq!(b58_address_1000000000, "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76");
        let address_1000000000_pub = ExtendedPublicKey::try_from(&address_1000000000).unwrap();
        let b58_address_1000000000_pub = address_1000000000_pub.to_extended_key(Version::XPub).b58_encode();
        assert_eq!(b58_address_1000000000_pub, "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy");

    }   
}