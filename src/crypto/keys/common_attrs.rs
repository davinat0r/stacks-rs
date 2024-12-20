use crate::bip32::child_number::ChildNumber;

const FINGERPRINT_LEN: usize = 4;

pub type KeyFingerprint = [u8; FINGERPRINT_LEN];

#[derive(Clone, Copy)]
pub struct ExtendedKeyAttrs {
    pub depth: u8,
    pub parent_fingerprint: KeyFingerprint,
    pub child_number: ChildNumber,
}

impl ExtendedKeyAttrs {
    pub fn new(depth: u8, parent_fingerprint: KeyFingerprint, child_number: ChildNumber) -> Self {
        Self { depth: depth, parent_fingerprint: parent_fingerprint, child_number: child_number }
    }

    pub fn default() -> Self {
        Self { depth: 0, parent_fingerprint: [0u8; FINGERPRINT_LEN], child_number: ChildNumber::new(0).unwrap()}
    }
}