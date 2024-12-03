use std::str::FromStr;

use super::child_number::{ChildNumber, ChildNumberError};

const PATH_PREFIX: &str = "m/";
const MAX_DEPTH: usize = 5;

#[derive(Clone, Copy, Debug)]
pub enum Error {
    MaxDepthExceeded,
    WrongPathPrefix,
    InvalidPathIndex(ChildNumberError),
    CannotParseindex
}

pub struct DerivationPath {
    path: [ChildNumber; MAX_DEPTH]
}

impl DerivationPath {
    
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
        let splitted = str_path.unwrap().split("/");
        let mut path_vec: [ChildNumber; MAX_DEPTH] = [ChildNumber::new(0).unwrap(); MAX_DEPTH];

        for (index, part) in splitted.enumerate() {
            let child_num = ChildNumber::from_str(&part).map_err(|err| {
                Error::InvalidPathIndex(err)
            })?;
            path_vec[index] = child_num;
        };

        Ok(Self { path: path_vec.into() }) 
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
}