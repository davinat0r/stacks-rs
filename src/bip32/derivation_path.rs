use std::str::FromStr;

use super::child_number::{ChildNumber, ChildNumberError};

const PATH_PREFIX: &str = "m/";
pub const MAX_DEPTH: usize = 5;

#[derive(Clone, Copy, Debug)]
pub enum Error {
    MaxDepthExceeded,
    WrongPathPrefix,
    InvalidPathIndex(ChildNumberError),
    CannotParseindex
}

pub struct DerivationPath {
    pub path: Vec<ChildNumber>
}

impl FromStr for DerivationPath {
    type Err = Error;

    // Convert 'm/44'/0'/../../0 into [`DerivationPath`]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let stripped_s = s.strip_prefix(PATH_PREFIX);
        let str_path = match stripped_s {
            Some(res) => Ok(res),
            None => Err(Error::WrongPathPrefix)
        };
        let splitted = str_path.unwrap().split("/").collect::<Vec<&str>>();
        if splitted.len() > MAX_DEPTH {
            return Err(Error::MaxDepthExceeded);
        }
        let mut path_vec = Vec::new();

        for part in splitted {
            let child_num = ChildNumber::from_str(part).map_err(|err| {
                Error::InvalidPathIndex(err)
            })?;
            path_vec.push(child_num);
        };

        Ok(Self { path: path_vec }) 
    }
}


mod tests {
    use super::*;

    #[test]
    fn test_derivation_path() {
        let str_path = "m/44'/0'/0'/0/0";
        let derivation_path = DerivationPath::from_str(&str_path).unwrap();
        let hardened_44 = ChildNumber::new(2147483692).unwrap();
        let hardened_0 = ChildNumber::new(2147483648).unwrap();
        let normal_0 = ChildNumber::new(0).unwrap();
        assert_eq!(derivation_path.path.len(), 5);
        assert_eq!(derivation_path.path[0], hardened_44);
        assert_eq!(derivation_path.path[1], hardened_0);
        assert_eq!(derivation_path.path[2], hardened_0);
        assert_eq!(derivation_path.path[3], normal_0);
        assert_eq!(derivation_path.path[4], normal_0);
    }

    #[test]
    fn test_short_derivation_path() {
        let str_path = "m/44'/0'/0";
        let derivation_path = DerivationPath::from_str(&str_path).unwrap();
        let hardened_44 = ChildNumber::new(2147483692).unwrap();
        let hardened_0 = ChildNumber::new(2147483648).unwrap();
        let normal_0 = ChildNumber::new(0).unwrap();
        assert_eq!(derivation_path.path.len(), 3);
        assert_eq!(derivation_path.path[0], hardened_44);
        assert_eq!(derivation_path.path[1], hardened_0);
        assert_eq!(derivation_path.path[2], normal_0);
    }

    #[test]
    #[should_panic]
    fn test_derivation_path_out_of_bounds() {
        let str_path = "m/44'/0'/0'/0/21474836480000";
        DerivationPath::from_str(&str_path).unwrap();
    }

    #[test]
    #[should_panic]
    /// this should fail cause non hardeden indexes are up to [`ChildNumber::INDEX_THRESHOLD`]
    fn test_derivation_path_invalid_non_hardened_index() {
        let str_path = "m/44'/0'/0'/0/2147483649";
        DerivationPath::from_str(&str_path).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_derivation_path_invalid_hardened_index() {
        let str_path = "m/44'/0'/0'/0/2147483648'";
        DerivationPath::from_str(&str_path).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_derivation_path_too_long() {
        let str_path = "m/44'/0'/0'/0/0/10000";
        DerivationPath::from_str(&str_path).unwrap();
    }
    
    #[test]
    #[should_panic]
    fn test_derivation_path_wrong_path_prefix() {
        let str_path = "x/44'/0'/0'/0/0";
        DerivationPath::from_str(&str_path).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_derivation_path_no_path_prefix() {
        let str_path = "44'/0'/0'/0/0";
        DerivationPath::from_str(&str_path).unwrap();
    }
}