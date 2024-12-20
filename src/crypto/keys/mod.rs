pub mod extended_private_key;
pub mod extended_public_key;
pub mod common_attrs;

pub const KEY_LENGHT: usize = 32;
pub const EXTENDED_KEY_LENGHT: usize = 33;
pub type ChainCode = [u8; KEY_LENGHT];
